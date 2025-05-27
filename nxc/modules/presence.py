from impacket.dcerpc.v5 import samr, transport
from impacket.dcerpc.v5 import tsts as TSTS
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from contextlib import suppress
import traceback


class NXCModule:
    name = "presence"
    description = "Traces Domain and Enterprise Admin presence in the target over SMB"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        """There are no module options."""

    def on_admin_login(self, context, connection):
        admin_users = []

        try:
            string_binding = fr"ncacn_np:{connection.host}[\pipe\samr]"
            context.log.debug(f"Using string binding: {string_binding}")

            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(connection.host)
            rpctransport.set_credentials(
                connection.username,
                connection.password,
                connection.domain,
                connection.lmhash,
                connection.nthash,
                aesKey=connection.aesKey,
            )

            dce = rpctransport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            try:
                server_handle = samr.hSamrConnect2(dce)["ServerHandle"]
                domain = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)["Buffer"]["Buffer"][0]["Name"]
                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)
                domain_sid = resp["DomainId"].formatCanonical()
                domain_handle = samr.hSamrOpenDomain(dce, server_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS, resp["DomainId"])["DomainHandle"]
                context.log.debug(f"Resolved domain SID for {domain}: {domain_sid}")
            except Exception as e:
                context.log.fail(f"Failed to open domain {domain}: {e!s}")
                context.log.debug(traceback.format_exc())
                return

            admin_rids = {
                "Domain Admins": 512,
                "Enterprise Admins": 519,
                "Administrators": 544,
            }

            # Enumerate admin groups and their members
            for group_name, group_rid in admin_rids.items():
                context.log.debug(f"Looking up group: {group_name} with RID {group_rid}")

                try:
                    group_handle = samr.hSamrOpenGroup(dce, domain_handle, samr.GROUP_LIST_MEMBERS, group_rid)["GroupHandle"]
                    resp = samr.hSamrGetMembersInGroup(dce, group_handle)
                    for member in resp["Members"]["Members"]:
                        rid = int.from_bytes(member.getData(), byteorder="little")
                        try:
                            user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, rid)["UserHandle"]
                            username = samr.hSamrQueryInformationUser2(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)["Buffer"]["All"]["UserName"]

                            admin_users.append({"username": username, "sid": f"{domain_sid}-{rid}", "domain": domain, "group": group_name, "in_tasks": False, "in_directory": False})
                            context.log.debug(f"Found user: {username} with RID {rid} in group {group_name}")
                        except Exception as e:
                            context.log.debug(f"Failed to get user info for RID {rid}: {e!s}")
                        finally:
                            with suppress(Exception):
                                samr.hSamrCloseHandle(dce, user_handle)
                except Exception as e:
                    context.log.debug(f"Failed to get members of group {group_name}: {e!s}")
                finally:
                    with suppress(Exception):
                        samr.hSamrCloseHandle(dce, group_handle)

            # Update user objects to check if they are in tasklist or users directory
            self.check_users_directory(context, connection, admin_users)
            self.check_tasklist(context, connection, admin_users)

            # print grouped/logged results nicely
            self.print_grouped_results(context, admin_users)
        except Exception as e:
            context.log.fail(str(e))
            context.log.debug(traceback.format_exc())

    def check_users_directory(self, context, connection, admin_users):
        dirs_found = set()

        # try C$\Users first
        try:
            files = connection.conn.listPath("C$", "\\Users\\*")
        except Exception as e:
            context.log.debug(f"C$\\Users unavailable: {e}, trying Documents and Settings")
            try:
                files = connection.conn.listPath("C$", "\\Documents and Settings\\*")
            except Exception as e:
                context.log.fail(f"Error listing fallback directory: {e}")
                return
        else:
            context.log.debug("Successfully listed C$\\Users")

        # collect folder names (lowercase) ignoring "." and ".."
        dirs_found.update([f.get_shortname().lower() for f in files if f.get_shortname().lower() not in [".", "..", "administrator"]])

        # for admin users, check for folder presence
        for user in admin_users:
            if user["username"].lower() in dirs_found:
                user["in_directory"] = True
                context.log.debug(f"Found user {user['username']} in directories")

    def check_tasklist(self, context, connection, admin_users):
        """Checks tasklist over rpc."""
        try:
            with TSTS.LegacyAPI(connection.conn, connection.host, kerberos=False) as legacy:
                handle = legacy.hRpcWinStationOpenServer()
                processes = legacy.hRpcWinStationGetAllProcesses(handle)
        except Exception as e:
            context.log.fail(f"Error in check_tasklist RPC method: {e}")
            return []

        context.log.debug(f"Enumerated {len(processes)} processes on {connection.host}")

        for process in processes:
            context.log.debug(f"ImageName: {process['ImageName']}, UniqueProcessId: {process['SessionId']}, pSid: {process['pSid']}")
            # Check if process SID matches any admin user SID
            for user in admin_users:
                if process["pSid"] == user["sid"]:
                    user["in_tasks"] = True
                    context.log.debug(f"Matched process {process['ImageName']} with user {user['username']}")

    def print_grouped_results(self, context, admin_users):
        """Logs all results grouped per host in order"""
        context.log.success(f"Identified Admin Users: {', '.join([user['username'] for user in admin_users])})")

        dir_users = [user for user in admin_users if user["in_directory"]]
        if dir_users:
            context.log.success("Found users in directories:")
            for user in dir_users:
                context.log.highlight(f"{user['username']} ({user['group']})")

        tasklist_users = [user for user in admin_users if user["in_tasks"]]
        if tasklist_users:
            context.log.success("Found users in tasklist:")
            for user in tasklist_users:
                context.log.highlight(f"{user['username']} ({user['group']})")

        # Making this less verbose to better scan large ranges
        if not dir_users and not tasklist_users:
            context.log.info("No matches found in users directory or tasklist.")

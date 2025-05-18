from impacket.dcerpc.v5 import samr, transport
from impacket.dcerpc.v5 import tsts as TSTS
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from contextlib import suppress


class NXCModule:
    name = "presence"
    description = "Traces Domain and Enterprise Admin presence in the target over SMB"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def __init__(self):
        # initialize the sid to user mapping dictionary
        self.sid_to_user = {}

    def options(self, context, module_options):
        """There are no module options."""

    def on_admin_login(self, context, connection):
        def safe_str(obj):
            try:
                if isinstance(obj, bytes):
                    return obj.decode("utf-8", errors="replace")
                if hasattr(obj, "to_string"):
                    return obj.to_string()
                return str(obj)
            except Exception:
                return "[unrepresentable object]"

        try:
            context.log.debug(f"Target NetBIOS Name: {connection.hostname}")

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

            server_handle = samr.hSamrConnect2(dce)["ServerHandle"]

            try:
                resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
                domain = resp["Buffer"]["Buffer"][0]["Name"]
            except Exception as e:
                context.log.fail(f"Could not enumerate domains: {e!s}")
                return False

            admin_users = set()
            self.sid_to_user = {}  # dictionary mapping sid string to username

            try:
                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)
                domain_sid = resp["DomainId"].formatCanonical()
                context.log.debug(f"Resolved domain SID for {domain}: {domain_sid}")
            except Exception as e:
                context.log.debug(f"Failed to lookup SID for domain {domain}: {e!s}")
                return False

            try:
                domain_handle = samr.hSamrOpenDomain(dce, server_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS, resp["DomainId"])["DomainHandle"]
            except Exception as e:
                context.log.debug(f"Failed to open domain {domain}: {e!s}")
                return False

            admin_rids = {
                "Domain Admins": 512,
                "Enterprise Admins": 519
            }

            for group_name, group_rid in admin_rids.items():
                context.log.debug(f"Looking up group: {group_name} with RID {group_rid}")

                try:
                    group_handle = samr.hSamrOpenGroup(dce, domain_handle, samr.GROUP_LIST_MEMBERS, group_rid)["GroupHandle"]
                except Exception as group_e:
                    context.log.debug(f"Failed to process {group_name} group: {group_e!s}")
                    return False
                try:
                    resp = samr.hSamrGetMembersInGroup(dce, group_handle)
                    if resp["Members"]["Members"]:
                        for member in resp["Members"]["Members"]:
                            try:
                                rid = int.from_bytes(member.getData(), byteorder="little")
                                try:
                                    user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, rid)["UserHandle"]
                                    username = samr.hSamrQueryInformationUser2(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)["Buffer"]["All"]["UserName"]

                                    full_username = f"{domain}\\{username}"
                                    admin_users.add(f"{full_username} (Member of {group_name})")

                                    # map sid string of user to username
                                    user_sid = f"{domain_sid}-{rid}"
                                    self.sid_to_user[user_sid] = full_username

                                    samr.hSamrCloseHandle(dce, user_handle)
                                except Exception as name_e:
                                    try:
                                        sid_str = domain_sid
                                        full_sid = f"{sid_str}-{rid}"
                                    except Exception:
                                        full_sid = "[unrepresentable SID]"
                                    context.log.debug(f"Failed to get user info for RID {rid}: {name_e!s}")
                                    admin_users.add(f"{domain}\\{full_sid} (Member of {group_name})")
                            except Exception as member_e_inner:
                                context.log.debug(f"Error processing group member: {member_e_inner!s}")
                except Exception as e:
                    context.log.exception(e)
                    context.log.debug(f"Failed to get members of group {group_name}: {e!s}")
                finally:
                    with suppress(Exception):
                        samr.hSamrCloseHandle(dce, group_handle)

            if admin_users:
                # extract usernames only, remove domain and suffix
                usernames = set()
                for user in admin_users:
                    # user format: domain\username (member of group)
                    try:
                        # split on '\' and take second part, then split on ' ' and take first token as username
                        username_part = user.split("\\")[1]
                        username = username_part.split(" ")[0]
                        usernames.add(username)
                    except Exception:
                        # fallback to whole user string if parsing fails
                        usernames.add(user)

                sorted_names = sorted(usernames)
            else:
                context.log.info("No privileged users found")
                sorted_names = []

            matched_dirs = self.check_users_directory(context, connection, sorted_names)
            matched_tasks = self.check_tasklist(context, connection, sorted_names, connection.hostname)

            # collect results for printing
            results = {
                "netbios_name": connection.hostname,
                "admin_users": sorted_names,
                "matched_dirs": matched_dirs,
                "matched_tasks": matched_tasks,
            }

            # print grouped/logged results nicely
            self.print_grouped_results(context, connection, results)

            return True

        except Exception as e:
            context.log.fail(str(e))
            return False

    def check_users_directory(self, context, connection, admin_users):
        matched_dirs = []
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
                return matched_dirs  # return empty
        else:
            context.log.debug("Successfully listed C$\\Users")

        # collect folder names (lowercase) ignoring "." and ".."
        folder_names = [f.get_shortname().lower() for f in files if f.get_shortname() not in [".", ".."]]
        dirs_found.update(folder_names)

        # for admin users, check for folder presence
        for user in admin_users:
            user_lower = user.lower()
            if user_lower == "administrator":
                # only match folders like "administrator.something", not "administrator"
                matched = [d for d in dirs_found if d.startswith("administrator.") and d != "administrator"]
                matched_dirs.extend(matched)
            else:
                if user_lower in dirs_found:
                    matched_dirs.append(user)

        if matched_dirs:
            pass
        else:
            context.log.highlight("[+] No admin users found in directories")

        return matched_dirs

    def check_tasklist(self, context, connection, admin_users, netbios_name):
        """Checks tasklist over rpc."""
        try:
            with TSTS.LegacyAPI(connection.conn, netbios_name, kerberos=False) as legacy:
                handle = legacy.hRpcWinStationOpenServer()
                processes = legacy.hRpcWinStationGetAllProcesses(handle)
        except Exception as e:
            context.log.fail(f"Error in check_tasklist RPC method: {e}")
            return []

        context.log.debug(f"Enumerated {len(processes)} processes on {netbios_name}")

        matched_admin_users = {}

        # prepare admin users in lowercase for case-insensitive matching
        admin_users_lower = {u.lower() for u in admin_users}

        for process in processes:
            context.log.debug(f"ImageName: {process['ImageName']}, UniqueProcessId: {process['SessionId']}, pSid: {process['pSid']}")

            psid = process["pSid"]
            if not psid:
                continue

            username = self.sid_to_user.get(psid)
            if username:
                # extract username part after '\'
                user_only = username.split("\\")[-1]
                if user_only.lower() in admin_users_lower:
                    # save original casing
                    matched_admin_users[user_only] = True

        if matched_admin_users:
            context.log.info("Found users in tasklist:\n" + "\n".join(matched_admin_users.keys()))
        else:
            context.log.info("No admin user processes found in tasklist")

        return list(matched_admin_users.keys())

    def print_grouped_results(self, context, connection, results):
        """Logs all results grouped per host in order"""
        if results["admin_users"]:
            context.log.success(f"Identified Admin Users: {', '.join(results['admin_users'])}")

        if results["matched_dirs"]:
            context.log.success("Found users in directories:")
            for d in results["matched_dirs"]:
                context.log.highlight(d)

        if results["matched_tasks"]:
            context.log.success("Found users in tasklist:")
            for t in results["matched_tasks"]:
                context.log.highlight(t)

        if not results["matched_dirs"] and not results["matched_tasks"]:
            context.log.success("No matches found in users directory or tasklist.")

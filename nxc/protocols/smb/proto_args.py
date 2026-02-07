from argparse import _StoreTrueAction, _StoreAction
from nxc.helpers.args import DisplayDefaultsNotNone, DefaultTrackingAction, get_conditional_action


def proto_args(parser, parents):
    smb_parser = parser.add_parser("smb", help="own stuff using SMB", parents=parents, formatter_class=DisplayDefaultsNotNone)
    smb_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")

    delegate_arg = smb_parser.add_argument("--delegate", action="store", help="Impersonate user with S4U2Self + S4U2Proxy")
    delegate_spn_arg = smb_parser.add_argument("--delegate-spn", action=get_conditional_action(_StoreAction), make_required=[], help="SPN to use for S4U2Proxy, if not specified the SPN used will be cifs/<target>", type=str)
    generate_st = smb_parser.add_argument("--generate-st", type=str, dest="generate_st", action=get_conditional_action(_StoreAction), make_required=[], help="Store the S4U Service Ticket in the specified file")
    self_delegate_arg = smb_parser.add_argument("--self", dest="no_s4u2proxy", action=get_conditional_action(_StoreTrueAction), make_required=[], help="Only do S4U2Self, no S4U2Proxy (use with delegate)")

    dgroup = smb_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", "--domain", metavar="DOMAIN", dest="domain", type=str, help="domain to authenticate to")
    dgroup.add_argument("--local-auth", action="store_true", help="authenticate locally to each target")

    smb_parser.add_argument("--port", type=int, default=445, help="SMB port")
    smb_parser.add_argument("--share", metavar="SHARE", default="C$", help="specify a share")
    smb_parser.add_argument("--smb-server-port", default="445", help="specify a server port for SMB", type=int)
    smb_parser.add_argument("--no-smbv1", action="store_true", help="Force to disable SMBv1 in connection")
    smb_parser.add_argument("--no-admin-check", action="store_true", help="Avoid checking admin which queries the Service Control Manager")
    smb_parser.add_argument("--gen-relay-list", metavar="OUTPUT_FILE", help="outputs all hosts that don't require SMB signing to the specified file")
    smb_parser.add_argument("--smb-timeout", help="SMB connection timeout", type=int, default=2)
    smb_parser.add_argument("--laps", dest="laps", metavar="LAPS", type=str, help="LAPS authentification", nargs="?", const="administrator")
    smb_parser.add_argument("--generate-hosts-file", type=str, help="Generate a hosts file like from a range of IP")
    smb_parser.add_argument("--generate-krb5-file", type=str, help="Generate a krb5 file like from a range of IP")
    smb_parser.add_argument("--generate-tgt", type=str, help="Generate a tgt ticket")
    self_delegate_arg.make_required = [delegate_arg]
    generate_st.make_required = [delegate_arg]
    delegate_spn_arg.make_required = [delegate_arg]

    cred_gathering_group = smb_parser.add_argument_group("Credential Gathering")
    cred_gathering_group.add_argument("--sam", choices={"regdump", "secdump"}, nargs="?", const="regdump", help="dump SAM hashes from target systems")
    cred_gathering_group.add_argument("--lsa", choices={"regdump", "secdump"}, nargs="?", const="regdump", help="dump LSA secrets from target systems")
    ntds_arg = cred_gathering_group.add_argument("--ntds", choices={"vss", "drsuapi"}, nargs="?", const="drsuapi", help="dump the NTDS.dit from target DCs using the specifed method")
    # NTDS options
    kerb_keys_arg = cred_gathering_group.add_argument("--kerberos-keys", action=get_conditional_action(_StoreTrueAction), make_required=[], help="Also dump Kerberos AES and DES keys from target DC (NTDS.dit)")
    exclusive = cred_gathering_group.add_mutually_exclusive_group()
    history_arg = exclusive.add_argument("--history", action=get_conditional_action(_StoreTrueAction), make_required=[], help="Also retrieve password history from target DC (NTDS.dit)")
    enabled_arg = exclusive.add_argument("--enabled", action=get_conditional_action(_StoreTrueAction), make_required=[], help="Only dump enabled targets from DC (NTDS.dit)")
    kerb_keys_arg.make_required = [ntds_arg]
    history_arg.make_required = [ntds_arg]
    enabled_arg.make_required = [ntds_arg]
    cred_gathering_group.add_argument("--user", dest="userntds", type=str, help="Dump selected user from DC (NTDS.dit)")
    cred_gathering_group.add_argument("--dpapi", choices={"cookies", "nosystem"}, nargs="*", help="dump DPAPI secrets from target systems, can dump cookies if you add 'cookies', will not dump SYSTEM dpapi if you add nosystem")
    cred_gathering_group.add_argument("--sccm", choices={"wmi", "disk"}, nargs="?", const="disk", help="dump SCCM secrets from target systems")
    cred_gathering_group.add_argument("--mkfile", action="store", help="DPAPI option. File with masterkeys in form of {GUID}:SHA1")
    cred_gathering_group.add_argument("--pvk", action="store", help="DPAPI option. File with domain backupkey")
    cred_gathering_group.add_argument("--list-snapshots", nargs="?", dest="list_snapshots", const="ADMIN$", help="Lists the VSS snapshots (default: %(const)s)")

    mapping_enum_group = smb_parser.add_argument_group("Mapping/Enumeration")
    mapping_enum_group.add_argument("--shares", type=str, nargs="?", const="", help="Enumerate shares and access, filter on specified argument (read ; write ; read,write)")
    mapping_enum_group.add_argument("--exclude-shares", nargs="+", help="List of shares to exclude from enumeration (e.g., C$ Admin$ IPC$)")
    mapping_enum_group.add_argument("--dir", nargs="?", type=str, const="", help="List the content of a path (default path: '%(const)s')")
    mapping_enum_group.add_argument("--interfaces", action="store_true", help="Enumerate network interfaces")
    mapping_enum_group.add_argument("--no-write-check", action="store_true", help="Skip write check on shares (avoid leaving traces when missing delete permissions)")
    mapping_enum_group.add_argument("--filter-shares", nargs="+", help="Filter share by access, option 'READ' 'WRITE' or 'READ,WRITE'")
    mapping_enum_group.add_argument("--disks", action="store_true", help="Enumerate disks")
    mapping_enum_group.add_argument("--users", nargs="*", metavar="USER", help="Enumerate domain users, if a user is specified than only its information is queried.")
    mapping_enum_group.add_argument("--users-export", help="Enumerate domain users and export them to the specified file")
    mapping_enum_group.add_argument("--groups", nargs="?", const="", metavar="GROUP", help="Enumerate domain groups, if a group is specified than its members are Enumerated")
    mapping_enum_group.add_argument("--local-groups", nargs="?", const="", metavar="GROUP", help="Enumerate local groups, if a group is specified then its members are Enumerated")
    mapping_enum_group.add_argument("--computers", nargs="?", const="", metavar="COMPUTER", help="Enumerate computer users")
    mapping_enum_group.add_argument("--pass-pol", action="store_true", help="dump password policy")
    mapping_enum_group.add_argument("--rid-brute", nargs="?", type=int, const=4000, metavar="MAX_RID", help="Enumerate users by bruteforcing RIDs")
    mapping_enum_group.add_argument("--smb-sessions", action="store_true", help="Enumerate active smb sessions")
    mapping_enum_group.add_argument("--reg-sessions", type=str, nargs="?", const="", help="Enumerate users sessions using the Remote Registry. If a username is given, filter for it. If a file is given, filter for listed usernames. If no value is given, list all.")
    mapping_enum_group.add_argument("--loggedon-users", nargs="?", const="", help="Enumerate logged on users, if a user is specified than a regex filter is applied.")
    mapping_enum_group.add_argument("--loggedon-users-filter", action="store", help="only search for specific user, works with regex")
    mapping_enum_group.add_argument("--qwinsta", type=str, nargs="?", const="", help="Enumerate user sessions. If a username is given, filter for it; if a file is given, filter for listed usernames. If no value is given, list all.")
    mapping_enum_group.add_argument("--tasklist", type=str, nargs="?", const=True, help="Enumerate running processes and filter for the specified one if specified")
    mapping_enum_group.add_argument("--taskkill", type=str, help="Kills a specific PID or a proces name's PID's")

    wmi_group = smb_parser.add_argument_group("WMI Queries")
    wmi_group.add_argument("--wmi-query", metavar="QUERY", dest="wmi_query", type=str, help="Issues the specified WMI query")
    wmi_group.add_argument("--wmi-namespace", metavar="NAMESPACE", default="root\\cimv2", help="WMI Namespace (default: %(default)s)")

    spidering_group = smb_parser.add_argument_group("Spidering Shares")
    spidering_group.add_argument("--spider", metavar="SHARE", type=str, help="share to spider")
    spidering_group.add_argument("--spider-folder", metavar="FOLDER", default=".", type=str, help="folder to spider")
    spidering_group.add_argument("--content", action="store_true", help="enable file content searching")
    spidering_group.add_argument("--exclude-dirs", type=str, metavar="DIR_LIST", default="", help="directories to exclude from spidering")
    spidering_group.add_argument("--depth", type=int, help="max spider recursion depth")
    spidering_group.add_argument("--only-files", action="store_true", help="only spider files")
    spidering_group.add_argument("--silent", action="store_true", help="Do not print found files/directories", default=False)
    segroup = spidering_group.add_mutually_exclusive_group()
    segroup.add_argument("--pattern", nargs="+", help="pattern(s) to search for in folders, filenames and file content")
    segroup.add_argument("--regex", nargs="+", help="regex(s) to search for in folders, filenames and file content")

    files_group = smb_parser.add_argument_group("File Operations")
    files_group.add_argument("--put-file", action="append", nargs=2, metavar="FILE", help="Put a local file into remote target, ex: whoami.txt \\\\Windows\\\\Temp\\\\whoami.txt")
    files_group.add_argument("--get-file", action="append", nargs=2, metavar="FILE", help="Get a remote file, ex: \\\\Windows\\\\Temp\\\\whoami.txt whoami.txt")
    files_group.add_argument("--append-host", action="store_true", help="append the host to the get-file filename")

    cmd_exec_group = smb_parser.add_argument_group("Command Execution")
    cmd_exec_group.add_argument("--exec-method", choices={"wmiexec", "mmcexec", "smbexec", "atexec"}, default="wmiexec", help="method to execute the command. Ignored if in MSSQL mode", action=DefaultTrackingAction)
    cmd_exec_group.add_argument("--dcom-timeout", help="DCOM connection timeout", type=int, default=5)
    cmd_exec_group.add_argument("--get-output-tries", help="Number of times atexec/smbexec/mmcexec tries to get results", type=int, default=10)
    cmd_exec_group.add_argument("--codec", default="utf-8", help="Set encoding used (codec) from the target's output. If errors are detected, run chcp.com at the target & map the result with https://docs.python.org/3/library/codecs.html#standard-encodings and then execute again with --codec and the corresponding codec")
    cmd_exec_group.add_argument("--no-output", action="store_true", help="do not retrieve command output")

    cmd_exec_method_group = cmd_exec_group.add_mutually_exclusive_group()
    cmd_exec_method_group.add_argument("-x", metavar="COMMAND", dest="execute", help="execute the specified CMD command")
    cmd_exec_method_group.add_argument("-X", metavar="PS_COMMAND", dest="ps_execute", help="execute the specified PowerShell command")

    posh_group = smb_parser.add_argument_group("Powershell Script Obfuscation")
    posh_group.add_argument("--obfs", action="store_true", help="Obfuscate PowerShell scripts")
    posh_group.add_argument("--amsi-bypass", nargs=1, metavar="FILE", help="File with a custom AMSI bypass")
    posh_group.add_argument("--clear-obfscripts", action="store_true", help="Clear all cached obfuscated PowerShell scripts")
    posh_group.add_argument("--force-ps32", action="store_true", help="force PowerShell commands to run in a 32-bit process (may not apply to modules)")
    posh_group.add_argument("--no-encode", action="store_true", default=False, help="Do not encode the PowerShell command ran on target")

    return parser

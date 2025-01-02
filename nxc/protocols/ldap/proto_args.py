from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    ldap_parser = parser.add_parser("ldap", help="own stuff using LDAP", parents=parents, formatter_class=DisplayDefaultsNotNone)
    ldap_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    ldap_parser.add_argument("--port", type=int, default=389, help="LDAP port")

    dgroup = ldap_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, default=None, help="domain to authenticate to")
    dgroup.add_argument("--local-auth", action="store_true", help="authenticate locally to each target")

    egroup = ldap_parser.add_argument_group("Retrieve hash on the remote DC", "Options to get hashes from Kerberos")
    egroup.add_argument("--asreproast", help="Output AS_REP response to crack with hashcat to file")
    egroup.add_argument("--kerberoasting", help="Output TGS ticket to crack with hashcat to file")

    vgroup = ldap_parser.add_argument_group("Retrieve useful information on the domain")
    vgroup.add_argument("--base-dn", metavar="BASE_DN", dest="base_dn", type=str, default=None, help="base DN for search queries")
    vgroup.add_argument("--query", nargs=2, help="Query LDAP with a custom filter and attributes")
    vgroup.add_argument("--find-delegation", action="store_true", help="Finds delegation relationships within an Active Directory domain. (Enabled Accounts only)")
    vgroup.add_argument("--trusted-for-delegation", action="store_true", help="Get the list of users and computers with flag TRUSTED_FOR_DELEGATION")
    vgroup.add_argument("--password-not-required", action="store_true", help="Get the list of users with flag PASSWD_NOTREQD")
    vgroup.add_argument("--admin-count", action="store_true", help="Get objets that had the value adminCount=1")
    vgroup.add_argument("--users", nargs="*", help="Enumerate enabled domain users")
    vgroup.add_argument("--groups", action="store_true", help="Enumerate domain groups")
    vgroup.add_argument("--dc-list", action="store_true", help="Enumerate Domain Controllers")
    vgroup.add_argument("--get-sid", action="store_true", help="Get domain sid")
    vgroup.add_argument("--active-users", nargs="*", help="Get Active Domain Users Accounts")

    ggroup = ldap_parser.add_argument_group("Retrieve gmsa on the remote DC", "Options to play with gmsa")
    ggroup.add_argument("--gmsa", action="store_true", help="Enumerate GMSA passwords")
    ggroup.add_argument("--gmsa-convert-id", help="Get the secret name of specific gmsa or all gmsa if no gmsa provided")
    ggroup.add_argument("--gmsa-decrypt-lsa", help="Decrypt the gmsa encrypted value from LSA")

    bgroup = ldap_parser.add_argument_group("Bloodhound Scan", "Options to play with Bloodhoud")
    bgroup.add_argument("--bloodhound", action="store_true", help="Perform a Bloodhound scan")
    bgroup.add_argument("-c", "--collection", default="Default", help="Which information to collect. Supported: Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps, ACL, All. You can specify more than one by separating them with a comma")

    return parser

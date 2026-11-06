from nxc.helpers.args import DefaultTrackingAction, DisplayDefaultsNotNone


def proto_args(parser, parents):
    adws_parser = parser.add_parser("adws", help="enumerate AD via ADWS (TCP 9389)", parents=parents, formatter_class=DisplayDefaultsNotNone)

    dgroup = adws_parser.add_mutually_exclusive_group()
    dgroup.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")

    adws_parser.add_argument("--port", type=int, default=9389, action=DefaultTrackingAction, help="ADWS port")
    adws_parser.add_argument("--adws-timeout", type=int, default=10, help="ADWS connection timeout")
    adws_parser.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, default=None, help="Domain to authenticate to")

    egroup = adws_parser.add_argument_group("Enumeration", "ADWS enumeration options")
    egroup.add_argument("--base-dn", metavar="BASE_DN", dest="base_dn", type=str, default=None, help="Base DN for search queries")
    egroup.add_argument("--query", nargs=2, metavar=("FILTER", "ATTRS"), help="Custom LDAP filter and comma-separated attributes")
    egroup.add_argument("--users", action="store_true", help="Enumerate domain users")
    egroup.add_argument("--computers", action="store_true", help="Enumerate domain computers")
    egroup.add_argument("--groups", nargs="?", const="", help="Enumerate domain groups, optionally filter by name")
    egroup.add_argument("--dc-list", action="store_true", help="Enumerate domain controllers")
    egroup.add_argument("--admin-count", action="store_true", help="Enumerate accounts with adminCount=1")
    egroup.add_argument("--trusted-for-delegation", action="store_true", help="Enumerate unconstrained delegation")
    egroup.add_argument("--find-delegation", action="store_true", help="Find all delegation relationships")
    egroup.add_argument("--password-not-required", action="store_true", help="Enumerate PASSWD_NOTREQD accounts")
    egroup.add_argument("--get-sid", action="store_true", help="Get domain SID")
    egroup.add_argument("--active-users", nargs="*", help="Enumerate active user accounts")

    return parser

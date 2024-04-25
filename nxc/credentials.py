from nxc.logger import nxc_logger, NXCAdapter
from os.path import isfile

class credentials:
    # domains[n] always corresponds to usernames[n]
    domains = []
    usernames = []

    # secrets[n] always corresponds to cred_types[n]
    secrets = []
    cred_types = []
    data = []  # Arbitrary data needed for the login, e.g. ssh_key

    def __init__(self, args, db):
        self.args = args
        self.db = db
        self.logger = nxc_logger

        if self.args.cred_id:
            self.parse_credid()

        if self.args.username:
            self.parse_credentials()

        if len(self.secrets) != len(self.data):
            self.data = [None] * len(self.secrets)

    def parse_credid(self):
        """Queries the database for credentials to be used for authentication.

        Valid cred_id values are:
            - a single cred_id
            - a range specified with a dash (ex. 1-5)
            - 'all' to select all credentials

        Extends domains[], usernames[], secrets[], cred_types[]
        """
        creds = []  # list of tuples (cred_id, domain, username, secret, cred_type, pillaged_from) coming from the database

        for cred_id in self.args.cred_id:
            if cred_id.lower() == "all":
                creds = self.db.get_credentials()
            else:
                if not self.db.get_credentials(filter_term=int(cred_id)):
                    self.logger.error(f"Invalid database credential ID {cred_id}!")
                    continue
                creds.extend(self.db.get_credentials(filter_term=int(cred_id)))

        for cred in creds:
            c_id, domain, username, secret, cred_type, pillaged_from = cred
            self.domains.append(domain)
            self.usernames.append(username)
            self.secrets.append(secret)
            self.cred_types.append(cred_type)


    def parse_credentials(self):
        r"""Parse credentials from the command line or from a file specified.

        Usernames can be specified with a domain (domain\\username) or without (username).
        If the file contains domain\\username the domain specified will be overwritten by the one in the file.

        Extends: domains[], usernames[], secrets[], cred_types[]
        """

        # Parse usernames
        for user in self.args.username:
            if isfile(user):
                with open(user) as user_file:
                    for line in user_file:
                        if "\\" in line:
                            domain_single, username_single = line.split("\\")
                        else:
                            domain_single = self.args.domain if hasattr(self.args, "domain") and self.args.domain else ""
                            username_single = line
                        self.domains.append(domain_single)
                        self.usernames.append(username_single.strip())
            else:
                if "\\" in user:
                    domain_single, username_single = user.split("\\")
                else:
                    domain_single = self.args.domain if hasattr(self.args, "domain") and self.args.domain else ""
                    username_single = user
                self.domains.append(domain_single)
                self.usernames.append(username_single)

        # Parse passwords
        for password in self.args.password:
            if isfile(password):
                try:
                    with open(password, errors=("ignore" if self.args.ignore_pw_decoding else "strict")) as password_file:
                        for line in password_file:
                            self.secrets.append(line.strip())
                            self.cred_types.append("plaintext")
                except UnicodeDecodeError as e:
                    self.logger.error(f"{type(e).__name__}: Could not decode password file. Make sure the file only contains UTF-8 characters.")
                    self.logger.error("You can ignore non UTF-8 characters with the option '--ignore-pw-decoding'")
                    sys.exit(1)
            else:
                self.secrets.append(password)
                self.cred_types.append("plaintext")

        # Parse NTLM-hashes
        if hasattr(self.args, "hash") and self.args.hash:
            for ntlm_hash in self.args.hash:
                if isfile(ntlm_hash):
                    with open(ntlm_hash) as ntlm_hash_file:
                        for line in ntlm_hash_file:
                            self.secrets.append(line.strip())
                            self.cred_types.append("hash")
                else:
                    self.secrets.append(ntlm_hash)
                    self.cred_types.append("hash")

        # Parse AES keys
        if self.args.aesKey:
            for aesKey in self.args.aesKey:
                if isfile(aesKey):
                    with open(aesKey) as aesKey_file:
                        for line in aesKey_file:
                            self.secrets.append(line.strip())
                            self.cred_types.append("aesKey")
                else:
                    self.secrets.append(aesKey)
                    self.cred_types.append("aesKey")

        # Allow trying multiple users with a single password
        if len(self.usernames) > 1 and len(self.secrets) == 1:
            self.secrets = self.secrets * len(self.usernames)
            self.cred_types = self.cred_types * len(self.usernames)
            self.args.no_bruteforce = True

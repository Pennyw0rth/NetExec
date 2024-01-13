import requests
import importlib.metadata
from impacket.ntlm import compute_nthash
from nxc.helpers.logger import highlight


class NXCModule:
    """
    Check database NT hashes against online lookup tables at https://ntlm.pw.
    Module by @m4lwhere
    """

    name = "nt_lookup"
    description = "Lookup NT hashes in database on https://ntlm.pw"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = False

    def __init__(self, context=None, module_options=None):
        self.server = None
        self.context = context
        self.module_options = module_options
        self.nxc_version = importlib.metadata.version("netexec")

    def options(self, context, module_options):
        self.output = "Test lookup"

    def user_warning(self, context):
        """Warn the user there is a loss of confidentiality with a 3rd party."""
        context.log.highlight("[!] This module sends NT hashes to a 3rd party website at https://ntlm.pw. There is a loss of confidentiality - you are responsible for your own actions!")

        ans = input(highlight("Do you understand and accept these risks? [y/N] ", "red"))

        if ans.lower() not in ["y", "yes"]:
            context.log.fail(f"User did not accept the risk for {self.name}, QUITTING!")
            exit(1)

        return

    def password_to_ntlm(self, password_list):
        """From a list of passwords, return a list of NT hashes. Used to check for known NT hashes in database."""
        nt_list = []

        for password in password_list:
            hash_digest = compute_nthash(password)
            hex_string = format(int.from_bytes(hash_digest, byteorder="big"), "032x")
            nt_list.append(hex_string)

        return nt_list

    def perform_lookup(self, context, hash_list):
        """Take a list of NT hashes of 500 or less and perform the bulk lookup. Return a list of results in nt:plaintext format."""
        url = "https://ntlm.pw/api/bulklookup"
        headers = {"Content-Type": "text/plain", "User-Agent": f"NetExec/{self.nxc_version} nt_lookup module"}
        data_string = "\n".join(map(str, hash_list))

        context.log.debug(f"POST body data: {data_string}")
        context.log.debug("Sending request...")

        response = requests.post(url, data=data_string, headers=headers)
        context.log.debug(response.request.headers)

        context.log.debug(f"Received response code {response.status_code}")
        context.log.debug(response.headers)
        context.log.debug(response.text)

        if response.status_code == 429:
            context.log.fail("Not enough credits for ntlm.pw! Wait 1-15 mins and try again!")
            exit(1)

        return response.text.split("\n")

    def break_into_groups(self, input_list, max_size):
        """Break more than 500 hashes into separate groups."""
        for i in range(0, len(input_list), max_size):
            yield input_list[i : i + max_size]

    def on_login(self, context, connection):
        # Prompt for user acknowledgement
        self.user_warning(context)

        all_creds = context.db.get_credentials()
        if len(all_creds) == 0:
            context.log.fail("No credentials in database! Go get some and try again!")
            exit(1)

        context.log.debug(f"Gathered {len(all_creds)} total credentials from database")
        context.log.debug(all_creds)

        nt_hashes = []

        # Create list of NT hashes from db
        for cred in all_creds:
            if cred[4] == "hash":
                try:
                    ntlm = cred[3].split(":")
                    nt = ntlm[1]
                    nt_hashes.append(nt)
                except IndexError:
                    context.log.debug(f"Cred must not be a NTLM hash, tried on: {cred}")

        if len(nt_hashes) == 0:
            context.log.fail("No NT hashes found in database! Go get some and try again!")
            exit(1)

        context.log.debug(nt_hashes)

        # Remove NT hash duplicates
        uniq_nt_hashes = list(set(nt_hashes))

        # Remove blank NT Hash
        uniq_nt_hashes.remove("31d6cfe0d16ae931b73c59d7e0c089c0")
        context.log.highlight(f"Gathered {len(nt_hashes)} NT hashes from database, {len(uniq_nt_hashes)} unique & non-blank hashes")

        # Create NT hashes for known plaintext passwords in database. Remove known plaintext hashes from lookup.
        known_plaintext = []

        for cred in all_creds:
            if cred[4] == "plaintext":
                known_plaintext.append(cred[3])

        context.log.debug(known_plaintext)
        calculated_nt_hashes = self.password_to_ntlm(known_plaintext)
        context.log.debug(calculated_nt_hashes)

        # Remove NT hashes which were calculated from known plaintext
        known_removed_count = 0
        for nt_hash in calculated_nt_hashes:
            if nt_hash in uniq_nt_hashes:
                uniq_nt_hashes.remove(nt_hash)
                known_removed_count += 1
        context.log.highlight(f"{known_removed_count} matching NT hashes from known plaintext in database. There are {len(uniq_nt_hashes)} unknown NT hashes.")

        if len(uniq_nt_hashes) > 500:
            context.log.debug("More than 500 hashes detected, splitting into groups of 500 each")
            hash_groups = list(self.break_into_groups(uniq_nt_hashes, 500))
            context.log.debug(f"Created {len(hash_groups)} hash groups for lookups")

            answers = []
            for hash_group in hash_groups:
                answer = self.perform_lookup(context, hash_group)
                for i in answer:
                    answers.append(i)

        else:
            answers = self.perform_lookup(context, uniq_nt_hashes)

        plaintext_passwords = {}

        context.log.debug(answers)

        for answer in answers:
            try:
                hash_answer = answer.split(":", maxsplit=1)
                context.log.debug(hash_answer)
                if hash_answer[1] != "[not found]":
                    plaintext_passwords[hash_answer[0]] = hash_answer[1]
            except IndexError:
                context.log.debug(f"Unable to split {answer}, skipping")

        if len(plaintext_passwords) == 0:
            context.log.fail("Did not find any matching NT hashes, time for hashcat!")
            exit(1)
        else:
            context.log.highlight(f"Found {len(plaintext_passwords)} hashes in the https://ntlm.pw database!")

            new_plaintext_count = 0
            for key, value in plaintext_passwords.items():
                context.log.debug(f"Checking for matching accounts for {key}:{value}")

                # Find any matching users with gathered hashes
                for cred in all_creds:
                    if key in cred[3]:
                        domain, username = cred[1], cred[2]
                        context.log.success(f"Found matching user {domain}\\{username}:{value} ({key})")
                        context.db.add_credential("plaintext", domain, username, value)

                        new_plaintext_count += 1
            if new_plaintext_count > 0:
                context.log.success(f"Added {new_plaintext_count} passwords to database!")

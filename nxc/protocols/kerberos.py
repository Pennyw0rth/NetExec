#!/usr/bin/env python3

import socket
import time
import binascii
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal, KerberosException

from nxc.connection import connection
from nxc.config import process_secret
from nxc.logger import NXCAdapter
from nxc.helpers.misc import threaded_enumeration
from nxc.protocols.kerberos.kerberosattacks import KerberosUserEnum


class kerberos(connection):
    """
    Kerberos protocol implementation for NetExec.

    This protocol provides Kerberos-specific enumeration and attack capabilities
    without requiring LDAP or SMB connections.
    """

    def __init__(self, args, db, host):
        self.domain = None
        self.kdcHost = None
        self.hash = None
        self.lmhash = ""
        self.nthash = ""
        self.aesKey = ""
        self.port = 88

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        """Initialize the protocol-specific logger"""
        self.logger = NXCAdapter(
            extra={
                "protocol": "KRB5",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname if hasattr(self, "hostname") else self.host,
            }
        )

    def create_conn_obj(self):
        """
        Create connection object (minimal for Kerberos - just validate KDC is reachable)
        """
        try:
            # Test if the KDC port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.args.timeout if self.args.timeout else 5)
            result = sock.connect_ex((self.host, self.port))
            sock.close()

            if result == 0:
                self.logger.debug(f"Kerberos port {self.port} is open on {self.host}")
                return True
            else:
                self.logger.fail(f"Kerberos port {self.port} is closed on {self.host}")
                return False

        except TimeoutError:
            self.logger.fail(f"Connection timeout to {self.host}:{self.port}")
            return False
        except Exception as e:
            self.logger.fail(f"Error connecting to {self.host}:{self.port} - {e}")
            return False

    def enum_host_info(self):
        """
        Enumerate basic host information
        """
        # Set domain from args
        if self.args.domain:
            self.domain = self.args.domain.upper()

        # Set KDC host (can be different from target)
        if self.args.kdcHost:
            self.kdcHost = self.args.kdcHost
        else:
            self.kdcHost = self.host

        # Try to resolve hostname
        try:
            self.hostname = socket.gethostbyaddr(self.host)[0]
        except Exception:
            self.hostname = self.host

        self.logger.debug(f"Domain: {self.domain}, KDC: {self.kdcHost}, Hostname: {self.hostname}")

        # Add to database
        try:
            self.db.add_host(
                self.host,
                self.hostname,
                self.domain,
                "Kerberos"
            )
        except Exception as e:
            self.logger.debug(f"Error adding host to database: {e}")

    def print_host_info(self):
        """Print host information"""
        self.logger.display(
            f"Kerberos KDC (domain:{self.domain}) (hostname:{self.hostname})"
        )

    def login(self):
        """
        Override the default login method to handle Kerberos-specific logic.

        For Kerberos protocol:
        - If usernames provided WITHOUT passwords: batch enumerate valid usernames
        - If usernames AND passwords provided: authenticate normally (call parent login())
        """
        # Check if we have usernames but no passwords - enumeration mode
        if self.args.username and not self.args.password:
            self.logger.debug("Kerberos enumeration mode: usernames without passwords")

            # Parse all usernames from args (can be files or direct usernames)
            usernames = []
            for user_item in self.args.username:
                user_item = user_item.strip()
                try:
                    # Try to open as file
                    with open(user_item) as f:
                        file_users = [line.strip() for line in f if line.strip()]
                        usernames.extend(file_users)
                        self.logger.info(f"Loaded {len(file_users)} usernames from {user_item}")
                except FileNotFoundError:
                    # Not a file, treat as username
                    usernames.append(user_item)
                except Exception as e:
                    self.logger.debug(f"Error reading file {user_item}: {e}")
                    usernames.append(user_item)

            # Remove duplicates
            usernames = list(set(usernames))

            if not usernames:
                self.logger.fail("No valid usernames to enumerate")
                return False

            # Perform enumeration based on count
            if len(usernames) == 1:
                return self._check_single_user(usernames[0])
            else:
                return self._enum_multiple_users(usernames)
        else:
            # Normal authentication with credentials - use parent's login method
            return super().login()

    def plaintext_login(self, domain, username, password):
        """
        Authenticate to Kerberos KDC using username and password.

        This method attempts to get a TGT to verify credentials.
        """
        self.username = username
        self.password = password
        self.domain = domain        # Try to authenticate with password
        try:
            self.logger.debug(f"Attempting Kerberos authentication for {domain}\\{username}")

            userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                clientName=userName,
                password=password,
                domain=domain.upper(),
                lmhash=binascii.unhexlify(self.lmhash) if self.lmhash else b"",
                nthash=binascii.unhexlify(self.nthash) if self.nthash else b"",
                aesKey=self.aesKey if self.aesKey else "",
                kdcHost=self.kdcHost
            )

            self.logger.success(f"{domain}\\{username}:{process_secret(password)}")

            # Add credential to database
            self.db.add_credential("plaintext", domain, username, password)

            return True

        except KerberosException as e:
            error_msg = str(e)

            # Parse common Kerberos errors
            if "KDC_ERR_PREAUTH_FAILED" in error_msg:
                self.logger.fail(f"{domain}\\{username}:{process_secret(password)} (invalid credentials)")
            elif "KDC_ERR_CLIENT_REVOKED" in error_msg:
                self.logger.fail(f"{domain}\\{username}:{process_secret(password)} (account disabled)")
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in error_msg:
                self.logger.fail(f"{domain}\\{username}:{process_secret(password)} (user does not exist)")
            else:
                self.logger.fail(f"{domain}\\{username}:{process_secret(password)} ({error_msg})")

            return False

        except Exception as e:
            self.logger.fail(f"{domain}\\{username}:{process_secret(password)} (error: {e})")
            return False

    def hash_login(self, domain, username, ntlm_hash):
        """
        Authenticate to Kerberos KDC using username and NTLM hash.
        """
        self.username = username
        self.domain = domain

        # Parse NTLM hash
        lmhash = ""
        nthash = ""

        if ":" in ntlm_hash:
            lmhash, nthash = ntlm_hash.split(":")
        else:
            nthash = ntlm_hash

        self.lmhash = lmhash
        self.nthash = nthash
        self.hash = ntlm_hash

        try:
            self.logger.debug(f"Attempting Kerberos authentication for {domain}\\{username} with NTLM hash")

            userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                clientName=userName,
                password="",
                domain=domain.upper(),
                lmhash=binascii.unhexlify(lmhash) if lmhash else b"",
                nthash=binascii.unhexlify(nthash) if nthash else b"",
                aesKey="",
                kdcHost=self.kdcHost
            )

            self.logger.success(f"{domain}\\{username}:{process_secret(ntlm_hash)}")

            # Add credential to database
            self.db.add_credential("hash", domain, username, ntlm_hash)

            return True

        except KerberosException as e:
            error_msg = str(e)

            if "KDC_ERR_PREAUTH_FAILED" in error_msg:
                self.logger.fail(f"{domain}\\{username}:{process_secret(ntlm_hash)} (invalid hash)")
            elif "KDC_ERR_CLIENT_REVOKED" in error_msg:
                self.logger.fail(f"{domain}\\{username}:{process_secret(ntlm_hash)} (account disabled)")
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in error_msg:
                self.logger.fail(f"{domain}\\{username}:{process_secret(ntlm_hash)} (user does not exist)")
            else:
                self.logger.fail(f"{domain}\\{username}:{process_secret(ntlm_hash)} ({error_msg})")

            return False

        except Exception as e:
            self.logger.fail(f"{domain}\\{username}:{process_secret(ntlm_hash)} (error: {e})")
            return False

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        """
        Authenticate using Kerberos with various credential types.
        """
        self.username = username
        self.password = password
        self.domain = domain
        self.kdcHost = kdcHost if kdcHost else self.kdcHost
        self.aesKey = aesKey

        # Parse NTLM hash if provided
        lmhash = ""
        nthash = ""

        if ntlm_hash:
            if ":" in ntlm_hash:
                lmhash, nthash = ntlm_hash.split(":")
            else:
                nthash = ntlm_hash

            self.lmhash = lmhash
            self.nthash = nthash
            self.hash = ntlm_hash

        try:
            self.logger.debug(f"Attempting Kerberos authentication for {domain}\\{username}")

            userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                clientName=userName,
                password=password,
                domain=domain.upper(),
                lmhash=binascii.unhexlify(lmhash) if lmhash else b"",
                nthash=binascii.unhexlify(nthash) if nthash else b"",
                aesKey=aesKey if aesKey else "",
                kdcHost=self.kdcHost
            )

            # Determine what credential was used
            if aesKey:
                cred_type = "aesKey"
                cred_value = aesKey
            elif nthash:
                cred_type = "hash"
                cred_value = ntlm_hash
            else:
                cred_type = "plaintext"
                cred_value = password

            self.logger.success(f"{domain}\\{username}:{process_secret(cred_value)}")

            # Add credential to database
            self.db.add_credential(cred_type, domain, username, cred_value)

            return True

        except KerberosException as e:
            error_msg = str(e)
            cred_value = aesKey or ntlm_hash or password

            if "KDC_ERR_PREAUTH_FAILED" in error_msg:
                self.logger.fail(f"{domain}\\{username}:{process_secret(cred_value)} (invalid credentials)")
            elif "KDC_ERR_CLIENT_REVOKED" in error_msg:
                self.logger.fail(f"{domain}\\{username}:{process_secret(cred_value)} (account disabled)")
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in error_msg:
                self.logger.fail(f"{domain}\\{username}:{process_secret(cred_value)} (user does not exist)")
            else:
                self.logger.fail(f"{domain}\\{username}:{process_secret(cred_value)} ({error_msg})")

            return False

        except Exception as e:
            cred_value = aesKey or ntlm_hash or password
            self.logger.fail(f"{domain}\\{username}:{process_secret(cred_value)} (error: {e})")
            return False

    def _check_single_user(self, username):
        """
        Check if a single username is valid via Kerberos AS-REQ request.
        This checks user existence without triggering badPwdCount.
        """
        kerberos_enum = KerberosUserEnum(
            domain=self.domain,
            kdcHost=self.kdcHost,
            timeout=self.args.timeout if self.args.timeout else 10
        )

        result = kerberos_enum.check_user_exists(username)

        if result is True:
            self.logger.success(f"{self.domain}\\{username}")
            # Add to database
            try:
                self.db.add_host(
                    self.host,
                    self.hostname,
                    self.domain,
                    "Kerberos"
                )
            except Exception:
                pass
            return True
        elif result == "ACCOUNT_DISABLED":
            self.logger.highlight(f"{self.domain}\\{username} (disabled)")
            return True
        elif result is False:
            # Only show invalid usernames in debug mode during enumeration
            self.logger.debug(f"{self.domain}\\{username} (invalid)")
            return False
        else:
            self.logger.debug(f"{self.domain}\\{username} (error: {result})")
            return False

    def _enum_multiple_users(self, usernames):
        """
        Enumerate valid domain usernames via Kerberos AS-REQ requests.
        This checks user existence without triggering badPwdCount.
        """
        self.logger.display(
            f"Starting Kerberos user enumeration with {len(usernames)} username(s)"
        )

        # Use the threaded enumeration helper
        results = self._check_username_batch(usernames)

        # Aggregate results
        valid_users = [r["username"] for r in results if r["status"] == "valid"]
        invalid_users = [r["username"] for r in results if r["status"] == "invalid"]
        errors = [r["username"] for r in results if r["status"] == "error"]

        # Summary
        self.logger.success(
            f"Enumeration complete: {len(valid_users)} valid, {len(invalid_users)} invalid, {len(errors)} errors"
        )

        if valid_users:
            self.logger.display(f"Valid usernames: {', '.join(valid_users)}")

            # Save to file if requested
            if self.args.log:
                output_file = f"{self.args.log}_valid_users.txt"
                try:
                    with open(output_file, "w") as f:
                        f.write("\n".join(valid_users))
                    self.logger.success(f"Valid usernames saved to {output_file}")
                except Exception as e:
                    self.logger.fail(f"Error saving valid usernames: {e}")

        return len(valid_users) > 0

    @threaded_enumeration(items_param="usernames", progress_threshold=100)
    def _check_username_batch(self, usernames):
        """
        Check a single username via Kerberos AS-REQ.
        This method is decorated to run concurrently for multiple usernames.
        The number of threads is automatically determined from self.args.threads (--threads CLI argument).

        Args:
            usernames: Single username to check (despite plural name, decorator handles iteration)

        Returns:
            dict: {"username": str, "status": "valid"|"invalid"|"error"}
        """
        kerberos_enum = KerberosUserEnum(
            domain=self.domain,
            kdcHost=self.kdcHost,
            timeout=self.args.timeout if self.args.timeout else 10
        )

        # Add delay if requested (for stealth/rate limiting)
        if hasattr(self.args, "delay") and self.args.delay > 0:
            time.sleep(self.args.delay)

        result = kerberos_enum.check_user_exists(usernames)

        if result is True:
            self.logger.highlight(f"[+] {usernames}")
            return {"username": usernames, "status": "valid"}
        elif result == "ACCOUNT_DISABLED":
            self.logger.highlight(f"[+] {usernames} (disabled)")
            return {"username": usernames, "status": "valid", "disabled": True}
        elif result is False:
            self.logger.debug(f"[-] {usernames}")
            return {"username": usernames, "status": "invalid"}
        else:
            self.logger.error(f"[!] {usernames}: {result}")
            return {"username": usernames, "status": "error", "error": result}

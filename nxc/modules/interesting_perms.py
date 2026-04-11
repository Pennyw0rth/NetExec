import ldap3
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
from impacket.uuid import bin_to_string


class NXCModule:
    name = "interesting_perms"
    description = "Finds abusable AD permissions and extended rights via LDAP. Supports tokenGroups unrolling for effective nested permissions."
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        self.show_builtin = False
        self.outbound_only = False
        self.tokengroup_mode = False

        opts = {str(k).lower(): str(v).lower() for k, v in module_options.items()}

        if "builtin" in opts and opts["builtin"] not in ["false", "0"]:
            self.show_builtin = True

        if "self" in opts and opts["self"] not in ["false", "0"]:
            self.outbound_only = True

        if "tokengroup" in opts and opts["tokengroup"] not in ["false", "0"]:
            self.tokengroup_mode = True
            self.outbound_only = False

    def on_login(self, context, connection):
        context.log.debug(f"Flags parsed - BUILTIN: {self.show_builtin} | SELF: {self.outbound_only} | TOKENGROUP: {self.tokengroup_mode}")

        guid_map = {
            "5b47d60f-6090-40b2-9f37-2a4de88f302e": "ShadowCreds",
            "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "RBCD",
            "bf9679c0-0de6-11d0-a285-00aa003049e2": "WriteMembers",
            "4c164200-20c0-11d0-a768-00aa006e0529": "WriteAccountRestrictions",
            "28630eb8-41d5-11d1-a9c1-0000f80367c1": "WriteSPN",
            "ce934cb6-0e1a-4d43-85f2-95f7efb0c201": "ReadLAPSPassword",
            "e362ed86-b728-0842-b27d-2dea7a9df218": "ReadGMSAPassword",
            "8710ae63-2287-43ce-a154-1563f683e60f": "ReadBitLockerRecoveryKey",
            "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
        }

        try:
            server = ldap3.Server(connection.host, get_info=ldap3.ALL)
            user = f"{connection.domain}\\{connection.username}"
            current_username = connection.username.lower()

            if getattr(connection, "nthash", ""):
                pwd = f"aad3b435b51404eeaad3b435b51404ee:{connection.nthash}"
            else:
                pwd = getattr(connection, "password", "")

            conn = ldap3.Connection(server, user=user, password=pwd, authentication=ldap3.NTLM, auto_bind=True)
            search_base = server.info.other["defaultNamingContext"][0]

            user_dn = None
            effective_sids = set()

            conn.search(
                search_base=search_base,
                search_filter=f"(sAMAccountName={current_username})",
                attributes=["distinguishedName", "objectSid"],
            )

            if conn.entries:
                user_entry = conn.entries[0]
                user_dn = user_entry.entry_dn
                if "objectSid" in user_entry and user_entry.objectSid:
                    effective_sids.add(str(user_entry.objectSid))

            if self.tokengroup_mode and user_dn:
                conn.search(
                    search_base=user_dn,
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=["tokenGroups"],
                )

                if conn.entries and "tokenGroups" in conn.entries[0]:
                    for raw_sid in conn.entries[0].tokenGroups.raw_values:
                        try:
                            sid_obj = LDAP_SID(raw_sid)
                            effective_sids.add(sid_obj.formatCanonical())
                        except Exception:
                            pass

                context.log.highlight(f"[*] Unrolled {len(effective_sids)} inherited SIDs for {current_username}")

            conn.search(
                search_base=search_base,
                search_filter="(objectCategory=*)",
                attributes=["sAMAccountName", "distinguishedName", "nTSecurityDescriptor", "objectSid"],
                controls=[("1.2.840.113556.1.4.801", False, b"\x30\x03\x02\x01\x07")],
            )

            sid_map = {}
            for entry in conn.entries:
                if "objectSid" in entry and entry.objectSid:
                    sid = str(entry.objectSid)
                    name = str(entry.sAMAccountName) if "sAMAccountName" in entry and entry.sAMAccountName else entry.entry_dn
                    sid_map[sid] = name

            found_anything = False

            for entry in conn.entries:
                target = str(entry.sAMAccountName) if "sAMAccountName" in entry and entry.sAMAccountName else entry.entry_dn

                if "nTSecurityDescriptor" not in entry or not entry.nTSecurityDescriptor:
                    continue

                sd = SR_SECURITY_DESCRIPTOR()
                sd.fromString(entry.nTSecurityDescriptor.raw_values[0])

                if not sd["Dacl"]:
                    continue

                acls = {}

                for ace in sd["Dacl"].aces:
                    sid = ace["Ace"]["Sid"].formatCanonical()

                    try:
                        rid = int(sid.split("-")[-1])
                    except ValueError:
                        continue

                    if not self.show_builtin and not self.tokengroup_mode and rid < 1000:
                        continue

                    if sid not in acls:
                        acls[sid] = set()

                    mask = ace["Ace"]["Mask"]["Mask"]
                    atype = ace["TypeName"]

                    if mask & 0x10000000:
                        acls[sid].add("GenericAll")
                    if mask & 0x40000000:
                        acls[sid].add("GenericWrite")
                    if mask & 0x00040000:
                        acls[sid].add("WriteDacl")
                    if mask & 0x00080000:
                        acls[sid].add("WriteOwner")

                    if atype in ["ACCESS_ALLOWED_OBJECT_ACE", "ACCESS_DENIED_OBJECT_ACE"]:
                        if ace["Ace"]["ObjectTypeLen"] > 0:
                            guid = bin_to_string(ace["Ace"]["ObjectType"]).lower()

                            if mask & 0x00000100:
                                if guid == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
                                    acls[sid].add("_gc")
                                elif guid == "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
                                    acls[sid].add("_gca")
                                elif guid in guid_map:
                                    acls[sid].add(guid_map[guid])
                                else:
                                    acls[sid].add("ExtendedRight")

                            if mask & 0x00000020 and guid in guid_map:
                                acls[sid].add(guid_map[guid])

                            if mask & 0x00000010 and guid in guid_map:
                                acls[sid].add(guid_map[guid])
                    else:
                        if mask & 0x00000100:
                            acls[sid].add("ExtendedRight")

                for sid, rights in acls.items():
                    if "_gc" in rights and "_gca" in rights:
                        rights.add("DCSync")

                    if "_gc" in rights:
                        rights.remove("_gc")
                    if "_gca" in rights:
                        rights.remove("_gca")

                    if rights:
                        t_name = sid_map.get(sid, sid)

                        # FILTER LOGIC
                        if self.tokengroup_mode:
                            if sid not in effective_sids:
                                continue
                        elif self.outbound_only and current_username not in t_name.lower():
                            continue

                        r_str = ", ".join(sorted(rights))
                        context.log.highlight(f"[+] {t_name} has [{r_str}] over {target}")

                        found_anything = True

            if not found_anything:
                context.log.highlight("[-] Nothing is found!")

        except Exception as e:
            context.log.error(f"[!] Error querying LDAP: {e}")

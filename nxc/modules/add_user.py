"""
LDAP add_user module for Active Directory (domain controllers).
Binds using the authenticated user and only performs unicodePwd operations over LDAPS (port 636).
Logs both username and password defaults.
"""
import ssl
import ldap3
import sys
from ldap3 import Tls, MODIFY_ADD, MODIFY_REPLACE

class NXCModule:
    name = "add_user"
    description = "Adds, deletes, or changes a domain user via LDAP (AD/DC targets)."
    supported_protocols = ["ldap", "smb"]
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        self.__userName = module_options.get("USERNAME", module_options.get("NAME", "foobar"))
        self.__userPassword = module_options.get("PASSWORD") or "P@ssw0rd!"
        self.__groupName = module_options.get("GROUP", "Domain Admins")
        self.__delete = module_options.get("DELETE", False)
        self.__changepw = module_options.get("CHANGEPW", False)
        self.__ou = module_options.get("OU", "").strip() or None

        context.log.info(f"[{self.name}] User to add: '{self.__userName}' with password: '{self.__userPassword}'")

        if self.__changepw and (not self.__userName or not self.__userPassword):
            context.log.error("CHANGEPW requires USERNAME and PASSWORD")
            sys.exit(1)

    def on_login(self, context, connection):
        ldap_host = connection.host
        ldap_port = int(getattr(connection, "port", None) or 389)
        use_ldaps = ldap_port == 636

        bind_user = connection.username or ""
        bind_pass = connection.password or ""
        domain = getattr(connection, "domain", "") or ""

        context.log.info(f"[{self.name}] Connecting to LDAP {ldap_host}:{ldap_port} (LDAPS={use_ldaps}) as {bind_user}")

        tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL:@SECLEVEL=0") if use_ldaps else None
        ldap_server = ldap3.Server(ldap_host, use_ssl=use_ldaps, port=ldap_port, get_info=ldap3.ALL, tls=tls)

        bind_name = bind_user
        if domain and "@" not in bind_user and "\\" not in bind_user:
            bind_name = f"{bind_user}@{domain}"

        try:
            c = ldap3.Connection(ldap_server, user=bind_name, password=bind_pass, auto_bind=True)
            context.log.info(f"[{self.name}] LDAP bind successful as {bind_name}")
        except Exception as e:
            context.log.error(f"[{self.name}] LDAP bind failed: {e}")
            return

        # Base DN
        base_dn = ",".join([f"dc={part}" for part in domain.split(".")]) if domain else None
        if not base_dn:
            try:
                c.search('', '(objectClass=*)', ldap3.BASE, attributes=['defaultNamingContext'])
                base_dn = c.entries[0].defaultNamingContext.value
            except Exception as e:
                context.log.error(f"[{self.name}] Could not determine base DN: {e}")
                c.unbind()
                return

        users_container_dn = self.__ou or f"cn=Users,{base_dn}"

        def find_user_dn(samname):
            try:
                c.search(base_dn, f"(sAMAccountName={samname})", ldap3.SUBTREE, attributes=['distinguishedName'])
                return c.entries[0].distinguishedName.value if c.entries else None
            except Exception as e:
                context.log.debug(f"[{self.name}] find_user_dn error: {e}")
                return None

        def find_group_dn(groupname):
            try:
                # Search both in OU and domain
                c.search(users_container_dn, f"(cn={groupname})", ldap3.SUBTREE, attributes=['distinguishedName'])
                if c.entries:
                    return c.entries[0].distinguishedName.value
            except Exception:
                pass
            try:
                c.search(base_dn, f"(&(objectClass=group)(|(cn={groupname})(sAMAccountName={groupname})))", ldap3.SUBTREE, attributes=['distinguishedName'])
                if c.entries:
                    return c.entries[0].distinguishedName.value
            except Exception as e:
                context.log.debug(f"[{self.name}] find_group_dn error: {e}")
            return None

        # DELETE
        if self.__delete:
            user_dn = find_user_dn(self.__userName)
            if not user_dn:
                context.log.highlight(f"{self.__userName} not found (no-op)")
                c.unbind()
                return
            if c.delete(user_dn):
                context.log.highlight(f'Successfully deleted user "{self.__userName}" ({user_dn})')
            else:
                context.log.highlight(f'Failed to delete user "{self.__userName}": {c.result}')
            c.unbind()
            return

        # CHANGEPW
        if self.__changepw:
            if not use_ldaps:
                context.log.error(f"[{self.name}] CHANGEPW requires LDAPS (port 636).")
                c.unbind()
                return
            user_dn = find_user_dn(self.__userName)
            if not user_dn:
                context.log.error(f"[{self.name}] User '{self.__userName}' not found.")
                c.unbind()
                return
            try:
                pwd_val = ('"' + self.__userPassword + '"').encode('utf-16-le')
                if c.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [pwd_val])] }):
                    context.log.highlight(f'Successfully changed password for "{self.__userName}"')
                else:
                    context.log.highlight(f'Failed to change password: {c.result}')
            except Exception as e:
                context.log.exception(e)
            c.unbind()
            return

        # ADD
        existing_dn = find_user_dn(self.__userName)
        if existing_dn:
            context.log.highlight(f'User "{self.__userName}" already exists ({existing_dn})')
            user_dn = existing_dn
        else:
            user_dn = f"cn={self.__userName},{users_container_dn}"
            attrs = {
                "cn": self.__userName,
                "sAMAccountName": self.__userName,
                "userAccountControl": 512,
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "displayName": self.__userName,
            }
            if domain:
                attrs["userPrincipalName"] = f"{self.__userName}@{domain}"
            if self.__userPassword and use_ldaps:
                attrs["unicodePwd"] = ('"' + self.__userPassword + '"').encode('utf-16-le')
            elif self.__userPassword and not use_ldaps:
                context.log.highlight(f'[{self.name}] Warning: cannot set password without LDAPS (port 636).')

            try:
                if c.add(user_dn, attributes=attrs):
                    context.log.highlight(f'Successfully added user "{self.__userName}" ({user_dn})')
                else:
                    context.log.highlight(f'Failed to add user "{self.__userName}": {c.result}')
                    c.unbind()
                    return
            except Exception as e:
                context.log.exception(e)
                c.unbind()
                return

        # Add to group (idempotent)
        if self.__groupName:
            group_dn = find_group_dn(self.__groupName)
            if not group_dn:
                context.log.highlight(f'Group "{self.__groupName}" not found; skipping group addition.')
            else:
                try:
                    # Skip automatic Domain Users addition for new users
                    if self.__groupName.lower() == "domain users" and not existing_dn:
                        context.log.highlight(f'User "{self.__userName}" is automatically in "Domain Users"; skipping explicit add.')
                    else:
                        # Read current members
                        c.search(group_dn, '(objectClass=*)', ldap3.BASE, attributes=['member'])
                        members = []
                        if c.entries and hasattr(c.entries[0], 'member'):
                            raw_members = getattr(c.entries[0], 'member', [])
                            members = [str(m).lower() for m in raw_members]
                        
                        if user_dn.lower() in members:
                            context.log.highlight(f'"{self.__userName}" is already a member of "{self.__groupName}"')
                        else:
                            if c.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]}):
                                context.log.highlight(f'Added "{self.__userName}" to group "{self.__groupName}"')
                            else:
                                context.log.highlight(f'Failed to add "{self.__userName}" to group "{self.__groupName}": {c.result}')
                except Exception as e:
                    context.log.exception(e)
                            
        c.unbind()

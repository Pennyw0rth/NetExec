
from sqlalchemy import Boolean, Column, ForeignKeyConstraint, Integer, PrimaryKeyConstraint, String, func, select, delete
from sqlalchemy.dialects.sqlite import Insert  # used for upsert
from sqlalchemy.orm import declarative_base

from nxc.database import BaseDB, format_host_query
from nxc.logger import nxc_logger

Base = declarative_base()


class database(BaseDB):
    def __init__(self, db_engine):
        self.UsersTable = None
        self.HostsTable = None

        super().__init__(db_engine)

    class User(Base):
        __tablename__ = "users"
        id = Column(Integer)
        domain = Column(String)
        username = Column(String)
        password = Column(String)
        credtype = Column(String)
        pillaged_from_hostid = Column(Integer)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
            ForeignKeyConstraint(["pillaged_from_hostid"], ["hosts.id"]),
        )

    class Host(Base):
        __tablename__ = "hosts"
        id = Column(Integer)
        ip = Column(String)
        hostname = Column(String)
        domain = Column(String)
        os = Column(String)
        signing_required = Column(Boolean)
        channel_binding = Column(String)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
        )

    @staticmethod
    def db_schema(db_conn):
        Base.metadata.create_all(db_conn)

    def reflect_tables(self):
        self.UsersTable = self.reflect_table(self.User)
        self.HostsTable = self.reflect_table(self.Host)

    def add_host(self, ip, hostname, domain, os, signing_required, channel_binding):
        """Check if this host has already been added to the database, if not, add it in."""
        hosts = []
        updated_ids = []

        q = select(self.HostsTable).filter(self.HostsTable.c.ip == ip)
        results = self.db_execute(q).all()

        # create new host
        if not results:
            new_host = {
                "ip": ip,
                "hostname": hostname,
                "domain": domain,
                "os": os,
                "signing_required": signing_required,
                "channel_binding": channel_binding
            }
            hosts = [new_host]
        # update existing hosts data
        else:
            for host in results:
                host_data = host._asdict()
                # only update column if it is being passed in
                if ip is not None:
                    host_data["ip"] = ip
                if hostname is not None:
                    host_data["hostname"] = hostname
                if domain is not None:
                    host_data["domain"] = domain
                if os is not None:
                    host_data["os"] = os
                if signing_required is not None:
                    host_data["signing_required"] = signing_required
                if channel_binding is not None:
                    host_data["channel_binding"] = channel_binding
                # only add host to be updated if it has changed
                if host_data not in hosts:
                    hosts.append(host_data)
                    updated_ids.append(host_data["id"])
        nxc_logger.debug(f"Update Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.HostsTable)  # .returning(self.HostsTable.c.id)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)

        self.db_execute(q, hosts)  # .scalar()
        # we only return updated IDs for now - when RETURNING clause is allowed we can return inserted
        if updated_ids:
            nxc_logger.debug(f"add_host() - Host IDs Updated: {updated_ids}")
            return updated_ids

    def add_credential(self, credtype, domain, username, password, pillaged_from=None):
        """Check if this credential has already been added to the database, if not add it in."""
        credentials = []
        groups = []

        if pillaged_from and not self.is_host_valid(pillaged_from):
            nxc_logger.debug("Invalid host")
            return

        q = select(self.UsersTable).filter(
            func.lower(self.UsersTable.c.domain) == func.lower(domain),
            func.lower(self.UsersTable.c.username) == func.lower(username),
            func.lower(self.UsersTable.c.credtype) == func.lower(credtype),
        )
        results = self.db_execute(q).all()

        # add new credential
        if not results:
            new_cred = {
                "credtype": credtype,
                "domain": domain,
                "username": username,
                "password": password,
                "pillaged_from": pillaged_from,
            }
            credentials = [new_cred]
        # update existing cred data
        else:
            for creds in results:
                # this will include the id, so we don't touch it
                cred_data = creds._asdict()
                # only update column if it is being passed in
                if credtype is not None:
                    cred_data["credtype"] = credtype
                if domain is not None:
                    cred_data["domain"] = domain
                if username is not None:
                    cred_data["username"] = username
                if password is not None:
                    cred_data["password"] = password
                if pillaged_from is not None:
                    cred_data["pillaged_from"] = pillaged_from
                # only add cred to be updated if it has changed
                if cred_data not in credentials:
                    credentials.append(cred_data)

        # TODO: find a way to abstract this away to a single Upsert call
        q_users = Insert(self.UsersTable)  # .returning(self.UsersTable.c.id)
        update_columns_users = {col.name: col for col in q_users.excluded if col.name not in "id"}
        q_users = q_users.on_conflict_do_update(index_elements=self.UsersTable.primary_key, set_=update_columns_users)
        nxc_logger.debug(f"Adding credentials: {credentials}")

        self.db_execute(q_users, credentials)  # .scalar()

        if groups:
            q_groups = Insert(self.GroupRelationsTable)

            self.db_execute(q_groups, groups)

    def remove_credentials(self, creds_id):
        """Removes a credential ID from the database"""
        del_hosts = []
        for cred_id in creds_id:
            q = delete(self.UsersTable).filter(self.UsersTable.c.id == cred_id)
            del_hosts.append(q)
        self.db_execute(q)

    def is_credential_valid(self, credential_id):
        """Check if this credential ID is valid."""
        q = select(self.UsersTable).filter(
            self.UsersTable.c.id == credential_id,
            self.UsersTable.c.password is not None,
        )
        results = self.db_execute(q).all()
        return len(results) > 0

    def get_credentials(self, filter_term=None, cred_type=None):
        """Return credentials from the database."""
        # if we're returning a single credential by ID
        if self.is_credential_valid(filter_term):
            q = select(self.UsersTable).filter(self.UsersTable.c.id == filter_term)
        elif cred_type:
            q = select(self.UsersTable).filter(self.UsersTable.c.credtype == cred_type)
        # if we're filtering by username
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.UsersTable).filter(func.lower(self.UsersTable.c.username).like(like_term))
        # otherwise return all credentials
        else:
            q = select(self.UsersTable)

        return self.db_execute(q).all()

    def get_credential(self, cred_type, domain, username, password):
        q = select(self.UsersTable).filter(
            self.UsersTable.c.domain == domain,
            self.UsersTable.c.username == username,
            self.UsersTable.c.password == password,
            self.UsersTable.c.credtype == cred_type,
        )
        results = self.db_execute(q).first()
        return results.id

    def get_hosts(self, filter_term=None, domain=None):
        """Return hosts from the database."""
        q = select(self.HostsTable)

        # if we're returning a single host by ID
        if self.is_host_valid(filter_term):
            q = q.filter(self.HostsTable.c.id == filter_term)
            results = self.db_execute(q).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        elif filter_term is not None and filter_term.startswith("domain"):
            domain = filter_term.split()[1]
            like_term = func.lower(f"%{domain}%")
            q = q.filter(self.HostsTable.c.domain.like(like_term))
        # if we're filtering by ip/hostname
        elif filter_term and filter_term != "":
            q = format_host_query(q, filter_term, self.HostsTable)

        results = self.db_execute(q).all()
        nxc_logger.debug(f"ldap hosts() - results: {results}")
        return results

    def is_host_valid(self, host_id):
        """Check if this host ID is valid."""
        q = select(self.HostsTable).filter(self.HostsTable.c.id == host_id)
        results = self.db_execute(q).all()
        return len(results) > 0

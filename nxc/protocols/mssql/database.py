import sys
import warnings

from sqlalchemy import func, select, insert, update, delete, Table
from sqlalchemy.dialects.sqlite import Insert  # used for upsert
from sqlalchemy.exc import SAWarning, NoInspectionAvailable, NoSuchTableError

from nxc.database import BaseDB
from nxc.logger import nxc_logger

# if there is an issue with SQLAlchemy and a connection cannot be cleaned up properly it spews out annoying warnings
warnings.filterwarnings("ignore", category=SAWarning)


class database(BaseDB):
    def __init__(self, db_engine):
        self.HostsTable = None
        self.UsersTable = None
        self.AdminRelationsTable = None

        super().__init__(db_engine)

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute(
            """CREATE TABLE "hosts" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "domain" text,
            "os" text,
            "instances" integer
            )"""
        )
        # This table keeps track of which credential has admin access over which machine and vice-versa
        db_conn.execute(
            """CREATE TABLE "admin_relations" (
            "id" integer PRIMARY KEY,
            "userid" integer,
            "hostid" integer,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "users" (
            "id" integer PRIMARY KEY,
            "credtype" text,
            "domain" text,
            "username" text,
            "password" text,
            "pillaged_from_hostid" integer,
            FOREIGN KEY(pillaged_from_hostid) REFERENCES hosts(id)
            )"""
        )

    def reflect_tables(self):
        with self.db_engine.connect():
            try:
                self.HostsTable = Table("hosts", self.metadata, autoload_with=self.db_engine)
                self.UsersTable = Table("users", self.metadata, autoload_with=self.db_engine)
                self.AdminRelationsTable = Table("admin_relations", self.metadata, autoload_with=self.db_engine)
            except (NoInspectionAvailable, NoSuchTableError):
                print(
                    f"""
                    [-] Error reflecting tables for the {self.protocol} protocol - this means there is a DB schema mismatch
                    [-] This is probably because a newer version of nxc is being run on an old DB schema
                    [-] Optionally save the old DB data (`cp {self.db_path} ~/nxc_{self.protocol.lower()}.bak`)
                    [-] Then remove the {self.protocol} DB (`rm -f {self.db_path}`) and run nxc to initialize the new DB"""
                )
                sys.exit()

    def add_host(self, ip, hostname, domain, os, instances):
        """
        Check if this host has already been added to the database, if not, add it in.
        TODO: return inserted or updated row ids as a list
        """
        nxc_logger.debug(f"{domain} {ip} {os} {instances}")
        if not domain:
            domain = ""
        hosts = []

        q = select(self.HostsTable).filter(self.HostsTable.c.ip == ip)
        results = self.db_execute(q).all()
        nxc_logger.debug(f"mssql add_host() - hosts returned: {results}")

        host_data = {
            "ip": ip,
            "hostname": hostname,
            "domain": domain,
            "os": os,
            "instances": instances,
        }

        if not results:
            hosts = [host_data]
        else:
            for host in results:
                host_data = host._asdict()
                if ip is not None:
                    host_data["ip"] = ip
                if hostname is not None:
                    host_data["hostname"] = hostname
                if domain is not None:
                    host_data["domain"] = domain
                if os is not None:
                    host_data["os"] = os
                if instances is not None:
                    host_data["instances"] = instances
                if host_data not in hosts:
                    hosts.append(host_data)

        nxc_logger.debug(f"Update Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.HostsTable)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)
        self.db_execute(q, hosts)

    def add_credential(self, credtype, domain, username, password, pillaged_from=None):
        """Check if this credential has already been added to the database, if not add it in."""
        user_rowid = None

        credential_data = {}
        if credtype is not None:
            credential_data["credtype"] = credtype
        if domain is not None:
            credential_data["domain"] = domain
        if username is not None:
            credential_data["username"] = username
        if password is not None:
            credential_data["password"] = password
        if pillaged_from is not None:
            credential_data["pillaged_from"] = pillaged_from

        q = select(self.UsersTable).filter(
            func.lower(self.UsersTable.c.domain) == func.lower(domain),
            func.lower(self.UsersTable.c.username) == func.lower(username),
            func.lower(self.UsersTable.c.credtype) == func.lower(credtype),
        )
        results = self.db_execute(q).all()

        if not results:
            user_data = {
                "domain": domain,
                "username": username,
                "password": password,
                "credtype": credtype,
                "pillaged_from_hostid": pillaged_from,
            }
            q = insert(self.UsersTable).values(user_data)  # .returning(self.UsersTable.c.id)
            self.db_execute(q)  # .first()
        else:
            for user in results:
                # might be able to just remove this if check, but leaving it in for now
                if not user[3] and not user[4] and not user[5]:
                    q = update(self.UsersTable).values(credential_data)  # .returning(self.UsersTable.c.id)
                    results = self.db_execute(q)  # .first()

        nxc_logger.debug(
            f"add_credential(credtype={credtype}, domain={domain}, username={username}, password={password}, pillaged_from={pillaged_from})")
        return user_rowid

    def remove_credentials(self, creds_id):
        """Removes a credential ID from the database"""
        del_hosts = []
        for cred_id in creds_id:
            q = delete(self.UsersTable).filter(self.UsersTable.c.id == cred_id)
            del_hosts.append(q)
        self.db_execute(q)

    def add_admin_user(self, credtype, domain, username, password, host, user_id=None):
        if user_id:
            q = select(self.UsersTable).filter(self.UsersTable.c.id == user_id)
            users = self.db_execute(q).all()
        else:
            q = select(self.UsersTable).filter(
                self.UsersTable.c.credtype == credtype,
                func.lower(self.UsersTable.c.domain) == func.lower(domain),
                func.lower(self.UsersTable.c.username) == func.lower(username),
                self.UsersTable.c.password == password,
            )
            users = self.db_execute(q).all()
        nxc_logger.debug(f"Users: {users}")

        like_term = func.lower(f"%{host}%")
        q = q.filter(self.HostsTable.c.ip.like(like_term))
        hosts = self.db_execute(q).all()
        nxc_logger.debug(f"Hosts: {hosts}")

        if users is not None and hosts is not None:
            for user, host in zip(users, hosts):
                user_id = user[0]
                host_id = host[0]
                link = {"userid": user_id, "hostid": host_id}

                q = select(self.AdminRelationsTable).filter(
                    self.AdminRelationsTable.c.userid == user_id,
                    self.AdminRelationsTable.c.hostid == host_id,
                )
                links = self.db_execute(q).all()

                if not links:
                    self.db_execute(insert(self.AdminRelationsTable).values(link))

    def get_admin_relations(self, user_id=None, host_id=None):
        if user_id:
            q = select(self.AdminRelationsTable).filter(self.AdminRelationsTable.c.userid == user_id)
        elif host_id:
            q = select(self.AdminRelationsTable).filter(self.AdminRelationsTable.c.hostid == host_id)
        else:
            q = select(self.AdminRelationsTable)

        return self.db_execute(q).all()

    def remove_admin_relation(self, user_ids=None, host_ids=None):
        q = delete(self.AdminRelationsTable)
        if user_ids:
            for user_id in user_ids:
                q = q.filter(self.AdminRelationsTable.c.userid == user_id)
        elif host_ids:
            for host_id in host_ids:
                q = q.filter(self.AdminRelationsTable.c.hostid == host_id)
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

    def is_host_valid(self, host_id):
        """Check if this host ID is valid."""
        q = select(self.HostsTable).filter(self.HostsTable.c.id == host_id)
        results = self.db_execute(q).all()
        return len(results) > 0

    def get_hosts(self, filter_term=None, domain=None):
        """Return hosts from the database."""
        q = select(self.HostsTable)

        # if we're returning a single host by ID
        if self.is_host_valid(filter_term):
            q = q.filter(self.HostsTable.c.id == filter_term)
            results = self.db_execute(q).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        # if we're filtering by domain controllers
        elif filter_term == "dc":
            q = q.filter(self.HostsTable.c.dc is True)
            if domain:
                q = q.filter(func.lower(self.HostsTable.c.domain) == func.lower(domain))
        # if we're filtering by ip/hostname
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.HostsTable).filter(
                self.HostsTable.c.ip.like(like_term) | func.lower(self.HostsTable.c.hostname).like(like_term))

        return self.db_execute(q).all()

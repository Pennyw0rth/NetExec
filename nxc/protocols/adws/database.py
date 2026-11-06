from sqlalchemy import Column, ForeignKeyConstraint, Integer, PrimaryKeyConstraint, String, func, select, delete
from sqlalchemy.dialects.sqlite import Insert
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
        adws_reachable = Column(String)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
        )

    @staticmethod
    def db_schema(db_conn):
        Base.metadata.create_all(db_conn)

    def reflect_tables(self):
        self.UsersTable = self.reflect_table(self.User)
        self.HostsTable = self.reflect_table(self.Host)

    def add_host(self, ip, hostname, domain, os, adws_reachable=None):
        hosts = []
        updated_ids = []

        q = select(self.HostsTable).filter(self.HostsTable.c.ip == ip)
        results = self.db_execute(q).all()

        if not results:
            new_host = {
                "ip": ip,
                "hostname": hostname,
                "domain": domain,
                "os": os,
                "adws_reachable": adws_reachable,
            }
            hosts = [new_host]
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
                if adws_reachable is not None:
                    host_data["adws_reachable"] = adws_reachable
                if host_data not in hosts:
                    hosts.append(host_data)
                    updated_ids.append(host_data["id"])

        nxc_logger.debug(f"Update Hosts: {hosts}")

        q = Insert(self.HostsTable)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)

        self.db_execute(q, hosts)

        if updated_ids:
            nxc_logger.debug(f"add_host() - Host IDs Updated: {updated_ids}")
            return updated_ids

    def add_credential(self, credtype, domain, username, password, pillaged_from=None):
        credentials = []

        if pillaged_from and not self.is_host_valid(pillaged_from):
            nxc_logger.debug("Invalid host")
            return

        q = select(self.UsersTable).filter(
            func.lower(self.UsersTable.c.domain) == func.lower(domain),
            func.lower(self.UsersTable.c.username) == func.lower(username),
            func.lower(self.UsersTable.c.credtype) == func.lower(credtype),
        )
        results = self.db_execute(q).all()

        if not results:
            new_cred = {
                "credtype": credtype,
                "domain": domain,
                "username": username,
                "password": password,
                "pillaged_from": pillaged_from,
            }
            credentials = [new_cred]
        else:
            for creds in results:
                cred_data = creds._asdict()
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
                if cred_data not in credentials:
                    credentials.append(cred_data)

        q_users = Insert(self.UsersTable)
        update_columns_users = {col.name: col for col in q_users.excluded if col.name not in "id"}
        q_users = q_users.on_conflict_do_update(index_elements=self.UsersTable.primary_key, set_=update_columns_users)
        nxc_logger.debug(f"Adding credentials: {credentials}")

        self.db_execute(q_users, credentials)

    def remove_credentials(self, creds_id):
        for cred_id in creds_id:
            q = delete(self.UsersTable).filter(self.UsersTable.c.id == cred_id)
            self.db_execute(q)

    def is_credential_valid(self, credential_id):
        q = select(self.UsersTable).filter(
            self.UsersTable.c.id == credential_id,
            self.UsersTable.c.password is not None,
        )
        results = self.db_execute(q).all()
        return len(results) > 0

    def get_credentials(self, filter_term=None, cred_type=None):
        if self.is_credential_valid(filter_term):
            q = select(self.UsersTable).filter(self.UsersTable.c.id == filter_term)
        elif cred_type:
            q = select(self.UsersTable).filter(self.UsersTable.c.credtype == cred_type)
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.UsersTable).filter(func.lower(self.UsersTable.c.username).like(like_term))
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
        q = select(self.HostsTable)

        if self.is_host_valid(filter_term):
            q = q.filter(self.HostsTable.c.id == filter_term)
            results = self.db_execute(q).first()
            return [results]
        elif filter_term is not None and filter_term.startswith("domain"):
            domain = filter_term.split()[1]
            like_term = func.lower(f"%{domain}%")
            q = q.filter(self.HostsTable.c.domain.like(like_term))
        elif filter_term and filter_term != "":
            q = format_host_query(q, filter_term, self.HostsTable)

        results = self.db_execute(q).all()
        nxc_logger.debug(f"adws hosts() - results: {results}")
        return results

    def is_host_valid(self, host_id):
        q = select(self.HostsTable).filter(self.HostsTable.c.id == host_id)
        results = self.db_execute(q).all()
        return len(results) > 0

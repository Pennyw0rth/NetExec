import configparser

from sqlalchemy import Column, ForeignKeyConstraint, Integer, PrimaryKeyConstraint, String, select, func, delete
from sqlalchemy.dialects.sqlite import Insert
from sqlalchemy.orm import declarative_base

from nxc.database import BaseDB, format_host_query
from nxc.logger import nxc_logger
from nxc.paths import CONFIG_PATH

# we can't import config.py due to a circular dependency, so we have to create redundant code unfortunately
nxc_config = configparser.ConfigParser()
nxc_config.read(CONFIG_PATH)
nxc_workspace = nxc_config.get("nxc", "workspace", fallback="default")

Base = declarative_base()


class database(BaseDB):
    def __init__(self, db_engine):
        self.CredentialsTable = None
        self.HostsTable = None
        self.LoggedinRelationsTable = None
        self.AdminRelationsTable = None

        super().__init__(db_engine)

    class Credential(Base):
        __tablename__ = "credentials"
        id = Column(Integer)
        username = Column(String)
        password = Column(String)
        credtype = Column(String)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
        )

    class Host(Base):
        __tablename__ = "hosts"
        id = Column(Integer)
        host = Column(String)
        port = Column(Integer)
        banner = Column(String)
        os = Column(String)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
        )

    class LoggedInRelation(Base):
        __tablename__ = "loggedin_relations"
        id = Column(Integer)
        credid = Column(Integer)
        hostid = Column(Integer)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
            ForeignKeyConstraint(["credid"], ["credentials.id"]),
            ForeignKeyConstraint(["hostid"], ["hosts.id"]),
        )

    class AdminRelation(Base):
        __tablename__ = "admin_relations"
        id = Column(Integer)
        credid = Column(Integer)
        hostid = Column(Integer)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
            ForeignKeyConstraint(["credid"], ["credentials.id"]),
            ForeignKeyConstraint(["hostid"], ["hosts.id"]),
        )

    @staticmethod
    def db_schema(db_conn):
        Base.metadata.create_all(db_conn)

    def reflect_tables(self):
        self.CredentialsTable = self.reflect_table(self.Credential)
        self.HostsTable = self.reflect_table(self.Host)
        self.LoggedinRelationsTable = self.reflect_table(self.LoggedInRelation)
        self.AdminRelationsTable = self.reflect_table(self.AdminRelation)

    def add_host(self, host, port, banner, os=None):
        """Check if this host has already been added to the database, if not, add it in."""
        hosts = []
        updated_ids = []

        q = select(self.HostsTable).filter(self.HostsTable.c.host == host)
        results = self.db_execute(q).all()
        nxc_logger.debug(f"add_host(): Initial hosts results: {results}")

        if not results:
            new_host = {
                "host": host,
                "port": port,
                "banner": banner if banner is not None else "",
                "os": os if os is not None else "",
            }
            hosts = [new_host]
        else:
            for host_result in results:
                host_data = host_result._asdict()
                if host is not None:
                    host_data["host"] = host
                if port is not None:
                    host_data["port"] = port
                if banner is not None:
                    host_data["banner"] = banner
                if os is not None:
                    host_data["os"] = os
                if host_data not in hosts:
                    hosts.append(host_data)
                    updated_ids.append(host_data["id"])

        q = Insert(self.HostsTable)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)
        self.db_execute(q, hosts)

        if updated_ids:
            return updated_ids

    def add_credential(self, credtype, username, password):
        """Check if this credential has already been added to the database, if not add it in."""
        credentials = []

        q = select(self.CredentialsTable).filter(
            func.lower(self.CredentialsTable.c.username) == func.lower(username),
            func.lower(self.CredentialsTable.c.credtype) == func.lower(credtype),
        )
        results = self.db_execute(q).all()

        if not results:
            new_cred = {
                "credtype": credtype,
                "username": username,
                "password": password,
            }
            credentials = [new_cred]
        else:
            for creds in results:
                cred_data = creds._asdict()
                if credtype is not None:
                    cred_data["credtype"] = credtype
                if username is not None:
                    cred_data["username"] = username
                if password is not None:
                    cred_data["password"] = password
                if cred_data not in credentials:
                    credentials.append(cred_data)

        q_users = Insert(self.CredentialsTable)
        update_columns_users = {col.name: col for col in q_users.excluded if col.name not in "id"}
        q_users = q_users.on_conflict_do_update(index_elements=self.CredentialsTable.primary_key,
                                                 set_=update_columns_users)
        self.db_execute(q_users, credentials)

        if len(credentials) == 1:
            return self.get_credential(credtype, username, password)
        return credentials

    def get_credential(self, credtype, username, password):
        q = select(self.CredentialsTable).filter(
            func.lower(self.CredentialsTable.c.username) == func.lower(username),
            func.lower(self.CredentialsTable.c.credtype) == func.lower(credtype),
            self.CredentialsTable.c.password == password,
        )
        results = self.db_execute(q).all()
        return results[0].id if results else None

    def remove_credentials(self, creds_id):
        """Removes a credential ID from the database."""
        for cred_id in creds_id:
            q = delete(self.CredentialsTable).filter(self.CredentialsTable.c.id == cred_id)
            self.db_execute(q)

    def get_credentials(self, filter_term=None, cred_type=None):
        q = select(self.CredentialsTable)
        if cred_type:
            q = q.filter(self.CredentialsTable.c.credtype == cred_type)
        if self.is_credential_valid(filter_term):
            q = q.filter(self.CredentialsTable.c.id == filter_term)
        elif filter_term:
            q = q.filter(self.CredentialsTable.c.username.like(f"%{filter_term}%"))
        return self.db_execute(q).all()

    def is_credential_valid(self, credential_id):
        q = select(self.CredentialsTable).filter(self.CredentialsTable.c.id == credential_id)
        return len(self.db_execute(q).all()) > 0

    def get_hosts(self, filter_term=None):
        q = select(self.HostsTable)
        q = format_host_query(q, filter_term, self.HostsTable)
        return self.db_execute(q).all()

    def add_loggedin_relation(self, credential_id, host_id):
        loggedin_relations = []
        q = select(self.LoggedinRelationsTable).filter(
            self.LoggedinRelationsTable.c.credid == credential_id,
            self.LoggedinRelationsTable.c.hostid == host_id,
        )
        results = self.db_execute(q).all()
        if not results:
            loggedin_relations = [{"credid": credential_id, "hostid": host_id}]
            self.db_execute(Insert(self.LoggedinRelationsTable), loggedin_relations)

    def add_admin_user(self, credential_id, host_id):
        q = select(self.AdminRelationsTable).filter(
            self.AdminRelationsTable.c.credid == credential_id,
            self.AdminRelationsTable.c.hostid == host_id,
        )
        results = self.db_execute(q).all()
        if not results:
            self.db_execute(Insert(self.AdminRelationsTable), [{"credid": credential_id, "hostid": host_id}])

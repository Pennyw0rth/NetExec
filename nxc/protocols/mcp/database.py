from sqlalchemy import Column, ForeignKeyConstraint, Integer, PrimaryKeyConstraint, String, select, delete, func
from sqlalchemy.dialects.sqlite import Insert
from sqlalchemy.orm import declarative_base

from nxc.database import BaseDB, format_host_query
from nxc.logger import nxc_logger

Base = declarative_base()


class database(BaseDB):
    def __init__(self, db_engine):
        self.CredentialsTable = None
        self.HostsTable = None
        self.LoggedinRelationsTable = None
        super().__init__(db_engine)

    class Credential(Base):
        __tablename__ = "credentials"
        id = Column(Integer)
        username = Column(String)
        password = Column(String)
        __table_args__ = (PrimaryKeyConstraint("id"),)

    class Host(Base):
        __tablename__ = "hosts"
        id = Column(Integer)
        host = Column(String)
        port = Column(Integer)
        banner = Column(String)  # JSON server_info
        __table_args__ = (PrimaryKeyConstraint("id"),)

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

    @staticmethod
    def db_schema(db_conn):
        Base.metadata.create_all(db_conn)

    def reflect_tables(self):
        self.CredentialsTable = self.reflect_table(self.Credential)
        self.HostsTable = self.reflect_table(self.Host)
        self.LoggedinRelationsTable = self.reflect_table(self.LoggedInRelation)

    def add_host(self, host, port, banner):
        hosts, updated_ids = [], []
        q = select(self.HostsTable).filter(self.HostsTable.c.host == host)
        results = self.db_execute(q).all()
        if not results:
            hosts = [{"host": host, "port": port, "banner": banner}]
        else:
            for host_result in results:
                host_data = host_result._asdict()
                if banner is not None:
                    host_data["banner"] = banner
                if host_data not in hosts:
                    hosts.append(host_data)
                    updated_ids.append(host_data["id"])
        q = Insert(self.HostsTable)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)
        self.db_execute(q, hosts)
        if updated_ids:
            return updated_ids

    def add_credential(self, username, password):
        credentials = []
        q = select(self.CredentialsTable).filter(
            func.lower(self.CredentialsTable.c.username) == func.lower(username),
            func.lower(self.CredentialsTable.c.password) == func.lower(password),
        )
        results = self.db_execute(q).all()
        if not results:
            credentials = [{"username": username, "password": password}]
        else:
            for creds in results:
                cred_data = creds._asdict()
                if username is not None:
                    cred_data["username"] = username
                if password is not None:
                    cred_data["password"] = password
                if cred_data not in credentials:
                    credentials.append(cred_data)
        q = Insert(self.CredentialsTable)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.CredentialsTable.primary_key, set_=update_columns)
        self.db_execute(q, credentials)
        if len(credentials) == 1:
            return self.get_credential(username, password)
        return credentials

    def get_credential(self, username, password):
        q = select(self.CredentialsTable).filter(
            self.CredentialsTable.c.username == username,
            self.CredentialsTable.c.password == password,
        )
        results = self.db_execute(q).first()
        if results is not None:
            return results.id

    def get_credentials(self, filter_term=None):
        if self.is_credential_valid(filter_term):
            q = select(self.CredentialsTable).filter(self.CredentialsTable.c.id == filter_term)
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.CredentialsTable).filter(func.lower(self.CredentialsTable.c.username).like(like_term))
        else:
            q = select(self.CredentialsTable)
        return self.db_execute(q).all()

    def is_credential_valid(self, credential_id):
        q = select(self.CredentialsTable).filter(
            self.CredentialsTable.c.id == credential_id,
            self.CredentialsTable.c.password is not None,
        )
        return len(self.db_execute(q).all()) > 0

    def remove_credentials(self, creds_id):
        for cred_id in creds_id:
            q = delete(self.CredentialsTable).filter(self.CredentialsTable.c.id == cred_id)
            self.db_execute(q)

    def get_hosts(self, filter_term=None):
        q = select(self.HostsTable)
        if self.is_host_valid(filter_term):
            q = q.filter(self.HostsTable.c.id == filter_term)
            return [self.db_execute(q).first()]
        elif filter_term and filter_term != "":
            q = format_host_query(q, filter_term, self.HostsTable)
        return self.db_execute(q).all()

    def is_host_valid(self, host_id):
        q = select(self.HostsTable).filter(self.HostsTable.c.id == host_id)
        return len(self.db_execute(q).all()) > 0

    def get_users(self, filter_term=None):
        q = select(self.CredentialsTable)
        if self.is_user_valid(filter_term):
            q = q.filter(self.CredentialsTable.c.id == filter_term)
        elif filter_term and filter_term != "":
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(func.lower(self.CredentialsTable.c.username).like(like_term))
        return self.db_execute(q).all()

    def is_user_valid(self, cred_id):
        q = select(self.CredentialsTable).filter(self.CredentialsTable.c.id == cred_id)
        return len(self.db_execute(q).all()) > 0

    def add_loggedin_relation(self, cred_id, host_id):
        q = select(self.LoggedinRelationsTable).filter(
            self.LoggedinRelationsTable.c.credid == cred_id,
            self.LoggedinRelationsTable.c.hostid == host_id,
        )
        if not self.db_execute(q).all():
            relation = {"credid": cred_id, "hostid": host_id}
            try:
                q = Insert(self.LoggedinRelationsTable)
                self.db_execute(q, [relation])
                return self.get_loggedin_relations(cred_id, host_id)[0].id
            except Exception as e:
                nxc_logger.debug(f"Error inserting LoggedinRelation: {e}")

    def get_loggedin_relations(self, cred_id=None, host_id=None):
        q = select(self.LoggedinRelationsTable)
        if cred_id:
            q = q.filter(self.LoggedinRelationsTable.c.credid == cred_id)
        if host_id:
            q = q.filter(self.LoggedinRelationsTable.c.hostid == host_id)
        return self.db_execute(q).all()

    def remove_loggedin_relations(self, cred_id=None, host_id=None):
        q = delete(self.LoggedinRelationsTable)
        if cred_id:
            q = q.filter(self.LoggedinRelationsTable.c.credid == cred_id)
        elif host_id:
            q = q.filter(self.LoggedinRelationsTable.c.hostid == host_id)
        self.db_execute(q)

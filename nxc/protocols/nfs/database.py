from sqlalchemy import Column, ForeignKeyConstraint, Integer, PrimaryKeyConstraint, String
from sqlalchemy.orm import declarative_base


from nxc.database import BaseDB

Base = declarative_base()


class database(BaseDB):
    def __init__(self, db_engine):
        self.CredentialsTable = None
        self.HostsTable = None
        self.LoggedinRelationsTable = None
        self.SharesTable = None

        super().__init__(db_engine)

    class Credential(Base):
        __tablename__ = "credentials"
        id = Column(Integer)
        username = Column(String)
        password = Column(String)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
        )

    class Host(Base):
        __tablename__ = "hosts"
        id = Column(Integer)
        ip = Column(String)
        hostname = Column(String)
        port = Column(Integer)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
        )

    class LoggedInRelation(Base):
        __tablename__ = "loggedin_relations"
        id = Column(Integer)
        cred_id = Column(Integer)
        host_id = Column(Integer)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
            ForeignKeyConstraint(["cred_id"], ["credentials.id"]),
            ForeignKeyConstraint(["host_id"], ["hosts.id"]),
        )

    class Share(Base):
        __tablename__ = "shares"
        id = Column(Integer)
        lir_id = Column(Integer)
        data = Column(String)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
            ForeignKeyConstraint(["lir_id"], ["loggedin_relations.id"]),
        )

    @staticmethod
    def db_schema(db_conn):
        Base.metadata.create_all(db_conn)

    def reflect_tables(self):
        self.CredentialsTable = self.reflect_table(self.Credential)
        self.HostsTable = self.reflect_table(self.Host)
        self.LoggedinRelationsTable = self.reflect_table(self.LoggedInRelation)
        self.SharesTable = self.reflect_table(self.Share)

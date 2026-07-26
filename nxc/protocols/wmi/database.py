from sqlalchemy import Column, Integer, PrimaryKeyConstraint, String
from sqlalchemy.orm import declarative_base
from nxc.database import BaseDB

Base = declarative_base()


class database(BaseDB):
    def __init__(self, db_engine):
        self.CredentialsTable = None
        self.HostsTable = None

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

    @staticmethod
    def db_schema(db_conn):
        Base.metadata.create_all(db_conn)

    def reflect_tables(self):
        self.CredentialsTable = self.reflect_table(self.Credential)
        self.HostsTable = self.reflect_table(self.Host)

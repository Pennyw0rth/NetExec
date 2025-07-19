from sqlalchemy import Boolean, Column, ForeignKeyConstraint, Integer, PrimaryKeyConstraint, String, select
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
        host = Column(String)
        port = Column(Integer)
        version = Column(String)
        root_escape = Column(Boolean)

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

    def add_host(self, host, port, version, escape):
        """Check if this host is already in the DB, if not add it"""
        hosts = []
        updated_ids = []

        q = select(self.HostsTable).filter(self.HostsTable.c.host == host)
        results = self.db_execute(q).all()

        # create new host
        if not results:
            new_host = {
                "host": host,
                "port": port,
                "version": version,
                "root_escape": escape,
            }
            hosts = [new_host]
        # update existing hosts data
        else:
            for host_result in results:
                host_data = host_result._asdict()
                nxc_logger.debug(f"host: {host_result}")
                nxc_logger.debug(f"host_data: {host_data}")
                if host is not None:
                    host_data["host"] = host
                if port is not None:
                    host_data["port"] = port
                if version is not None:
                    host_data["version"] = version
                if escape is not None:
                    host_data["root_escape"] = escape
                if host_data not in hosts:
                    hosts.append(host_data)
                    updated_ids.append(host_data["id"])
        nxc_logger.debug(f"Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.HostsTable)  # .returning(self.HostsTable.c.id)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)

        self.db_execute(q, hosts)  # .scalar()
        if updated_ids:
            nxc_logger.debug(f"add_host() - Host IDs Updated: {updated_ids}")
            return updated_ids

    def get_hosts(self, filter_term=None):
        """Return hosts from the database."""
        q = select(self.HostsTable)

        if self.is_host_valid(filter_term):
            q = q.filter(self.HostsTable.c.id == filter_term)
            results = self.db_execute(q).first()
            return [results]
        elif filter_term and filter_term != "":
            q = format_host_query(q, filter_term, self.HostsTable)

        results = self.db_execute(q).all()
        nxc_logger.debug(f"NFS get_hosts() - results: {results}")
        return results

    def is_host_valid(self, host_id):
        """Check if this host ID is valid."""
        q = select(self.HostsTable).filter(self.HostsTable.c.id == host_id)
        results = self.db_execute(q).all()
        return len(results) > 0

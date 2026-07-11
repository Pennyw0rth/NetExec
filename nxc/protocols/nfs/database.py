from sqlalchemy import Boolean, Column, ForeignKeyConstraint, Integer, PrimaryKeyConstraint, UniqueConstraint, String, select
from sqlalchemy.dialects.sqlite import Insert  # used for upsert
from sqlalchemy.orm import declarative_base

from nxc.database import BaseDB
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
        ip = Column(String)
        hostname = Column(String)
        port = Column(Integer)
        nfs_version = Column(String)
        root_escape = Column(Boolean)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
            UniqueConstraint("ip"),
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

    def get_hosts(self, filter_term=None, domain=None):
        """Return hosts from the database."""
        q = select(self.HostsTable)
        results = self.db_execute(q).all()
        nxc_logger.debug(f"NFS hosts() - results: {results}")
        return results

    def add_host(self, ip, hostname, port, nfs_version, root_escape):
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
                "port": port,
                "nfs_version": str(nfs_version),
                "root_escape": root_escape
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
                if port is not None:
                    host_data["port"] = port
                if nfs_version is not None:
                    host_data["nfs_version"] = str(nfs_version)
                if root_escape is not None:
                    host_data["root_escape"] = root_escape

                # only add host to be updated if it has changed
                if host_data not in hosts:
                    hosts.append(host_data)
                    updated_ids.append(host_data["id"])
        nxc_logger.debug(f"Update Hosts: {hosts}")
        q = Insert(self.HostsTable)  # .returning(self.HostsTable.c.id)

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.HostsTable)  # .returning(self.HostsTable.c.id)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=["ip"], set_=update_columns)

        self.db_execute(q, hosts)  # .scalar()
        # we only return updated IDs for now - when RETURNING clause is allowed we can return inserted
        if updated_ids:
            nxc_logger.debug(f"add_host() - Host IDs Updated: {updated_ids}")
            return updated_ids

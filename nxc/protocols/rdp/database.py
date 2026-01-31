from sqlalchemy import Column, Boolean, UniqueConstraint, Integer, PrimaryKeyConstraint, String, select
from sqlalchemy.dialects.sqlite import Insert
from sqlalchemy.orm import declarative_base

from nxc.database import BaseDB, format_host_query
from nxc.logger import nxc_logger

BaseTable = declarative_base()


class database(BaseDB):
    def __init__(self, db_engine):
        self.HostsTable = None

        super().__init__(db_engine)

    class Host(BaseTable):
        __tablename__ = "hosts"
        id = Column(Integer)
        ip = Column(String)
        port = Column(Integer)
        hostname = Column(String)
        domain = Column(String)
        os = Column(String)
        nla = Column(Boolean)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
            UniqueConstraint("ip"),
        )

    @staticmethod
    def db_schema(db_conn):
        BaseTable.metadata.create_all(db_conn)

    def reflect_tables(self):
        self.HostsTable = self.reflect_table(self.Host)

    def add_host(self, ip, port, hostname, domain, os, nla):
        """
        Check if this host has already been added to the database, if not, add it in.
        TODO: return inserted or updated row ids as a list
        """
        hosts = []

        q = select(self.HostsTable).filter(self.HostsTable.c.ip == ip)
        results = self.db_execute(q).all()
        nxc_logger.debug(f"rdp add_host() - hosts returned: {results}")

        # create new host
        if not results:
            new_host = {
                "ip": ip,
                "port": port,
                "hostname": hostname,
                "domain": domain,
                "os": os,
                "nla": nla
            }
            hosts = [new_host]
        # update existing hosts data
        else:
            for host in results:
                host_data = host._asdict()
                # only update column if it is being passed in
                if ip is not None:
                    host_data["ip"] = ip
                if port is not None:
                    host_data["port"] = port
                if hostname is not None:
                    host_data["hostname"] = hostname
                if domain is not None:
                    host_data["domain"] = domain
                if os is not None:
                    host_data["os"] = os
                if nla is not None:
                    host_data["nla"] = nla
                # only add host to be updated if it has changed
                if host_data not in hosts:
                    hosts.append(host_data)
        nxc_logger.debug(f"Update Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.HostsTable)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)
        self.db_execute(q, hosts)

    def get_hosts(self, filter_term=None, domain=None):
        """Return hosts from the database."""
        q = select(self.HostsTable)

        # if we're returning a single host by ID
        if self.is_host_valid(filter_term):
            q = q.filter(self.HostsTable.c.id == filter_term)
            results = self.db_execute(q).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        # filtering nla False because this is the misconfiguration we are looking for
        elif filter_term == "nla":
            q = q.filter(self.HostsTable.c.nla == False)  # noqa: E712
        # if we're filtering by ip/hostname
        elif filter_term and filter_term != "":
            q = format_host_query(q, filter_term, self.HostsTable)

        results = self.db_execute(q).all()
        nxc_logger.debug(f"rdp hosts() - results: {results}")
        return results

    def is_host_valid(self, host_id):
        """Check if this host ID is valid."""
        q = select(self.HostsTable).filter(self.HostsTable.c.id == host_id)
        results = self.db_execute(q).all()
        return len(results) > 0

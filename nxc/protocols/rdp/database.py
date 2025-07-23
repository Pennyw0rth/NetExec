import sys
from nxc.logger import nxc_logger
from sqlalchemy import select
from sqlalchemy.dialects.sqlite import Insert
from sqlalchemy import Table
from sqlalchemy.exc import (
    NoInspectionAvailable,
    NoSuchTableError,
)

from nxc.database import BaseDB


class database(BaseDB):
    def __init__(self, db_engine):
        self.CredentialsTable = None
        self.HostsTable = None

        super().__init__(db_engine)

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute(
            """CREATE TABLE "credentials" (
            "id" integer PRIMARY KEY,
            "username" text,
            "password" text,
            "pkey" text
            )"""
        )

        db_conn.execute(
            """CREATE TABLE "hosts" (
            "id" integer PRIMARY KEY,
            "host" text,
            "hostname" text,
            "port" integer,
            "domain" text,
            "serveros" text,
            "nla" integer
            )"""
        )

    def reflect_tables(self):
        with self.db_engine.connect():
            try:
                self.CredentialsTable = Table("credentials", self.metadata, autoload_with=self.db_engine)
                self.HostsTable = Table("hosts", self.metadata, autoload_with=self.db_engine)
            except (NoInspectionAvailable, NoSuchTableError):
                print(
                    f"""
                    [-] Error reflecting tables for the {self.protocol} protocol - this means there is a DB schema mismatch
                    [-] This is probably because a newer version of nxc is being run on an old DB schema
                    [-] Optionally save the old DB data (`cp {self.db_path} ~/nxc_{self.protocol.lower()}.bak`)
                    [-] Then remove the {self.protocol} DB (`rm -f {self.db_path}`) and run nxc to initialize the new DB"""
                )
                sys.exit()

    def add_host(self, host, hostname, port, domain, serveros, nla):
        """Check if this host is already in the DB, if not add it"""
        hosts = []
        updated_ids = []

        q = select(self.HostsTable).filter(self.HostsTable.c.host == host)
        results = self.db_execute(q).all()

        # create new host
        if not results:
            new_host = {
                "host": host,
                "hostname": hostname,
                "port": port,
                "domain": domain,
                "serveros": serveros,
                "nla": bool(nla)
            }
            hosts = [new_host]
        # update existing hosts data
        else:
            for host_result in results:
                host_data = host_result._asdict()
                nxc_logger.debug(f"host: {host_result}")
                nxc_logger.debug(f"host_data: {host_data}")
                # only update column if it is being passed in
                if host is not None:
                    host_data["host"] = host
                if hostname is not None:
                    host_data["hostname"] = hostname
                if port is not None:
                    host_data["port"] = port
                if domain is not None:
                    host_data["domain"] = domain
                if serveros is not None:
                    host_data["serveros"] = serveros
                if nla is not None:
                    host_data["nla"] = bool(nla)
                # only add host to be updated if it has changed
                if host_data not in hosts:
                    hosts.append(host_data)
                    updated_ids.append(host_data["id"])
        nxc_logger.debug(f"Hosts: {hosts}")

        # TODO: find a way to abstract this away to a single Upsert call
        q = Insert(self.HostsTable)  # .returning(self.HostsTable.c.id)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.HostsTable.primary_key, set_=update_columns)

        self.db_execute(q, hosts)  # .scalar()
        # we only return updated IDs for now - when RETURNING clause is allowed we can return inserted
        if updated_ids:
            nxc_logger.debug(f"add_host() - Host IDs Updated: {updated_ids}")
            return updated_ids
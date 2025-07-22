from sqlalchemy import Table
from sqlalchemy.exc import (
    NoInspectionAvailable,
    NoSuchTableError,
)
from nxc.database import BaseDB, format_host_query
from nxc.logger import nxc_logger
from sqlalchemy import select, func
from sqlalchemy.dialects.sqlite import Insert
import sys


class database(BaseDB):
    def __init__(self, db_engine):
        self.CredentialsTable = None
        self.HostsTable = None
        self.LoggedinRelationsTable = None
        self.SharesTable = None

        super().__init__(db_engine)

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute(
            """CREATE TABLE "credentials" (
            "id" integer PRIMARY KEY,
            "username" text,
            "password" text
            )"""
        )

        db_conn.execute(
            """CREATE TABLE "hosts" (
            "id" integer PRIMARY KEY,
            "host" text,
            "version" text,
            "root_escape" integer
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "loggedin_relations" (
            "id" integer PRIMARY KEY,
            "cred_id" integer,
            "host_id" integer,
            FOREIGN KEY(cred_id) REFERENCES credentials(id),
            FOREIGN KEY(host_id) REFERENCES hosts(id)
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "shares" (
                "id" integer PRIMARY KEY,
                "host" text,
                "read_perm" boolean,
                "write_perm" boolean,
                "exec_perm" boolean,
                "storage" text,
                "share" text,
                "access" text,
                UNIQUE(host, share)
            )"""
        )

    def reflect_tables(self):
        with self.db_engine.connect():
            try:
                self.CredentialsTable = Table("credentials", self.metadata, autoload_with=self.db_engine)
                self.HostsTable = Table("hosts", self.metadata, autoload_with=self.db_engine)
                self.LoggedinRelationsTable = Table("loggedin_relations", self.metadata, autoload_with=self.db_engine)
                self.SharesTable = Table("shares", self.metadata, autoload_with=self.db_engine)
            except (NoInspectionAvailable, NoSuchTableError):
                print(
                    f"""
                    [-] Error reflecting tables for the {self.protocol} protocol - this means there is a DB schema mismatch
                    [-] This is probably because a newer version of nxc is being run on an old DB schema
                    [-] Optionally save the old DB data (`cp {self.db_path} ~/nxc_{self.protocol.lower()}.bak`)
                    [-] Then remove the {self.protocol} DB (`rm -f {self.db_path}`) and run nxc to initialize the new DB"""
                )
                sys.exit()

    def add_host(self, host, version, escape):
        """Check if this host is already in the DB, if not add it"""
        hosts = []
        updated_ids = []

        q = select(self.HostsTable).filter(self.HostsTable.c.host == host)
        results = self.db_execute(q).all()

        # create new host
        if not results:
            new_host = {
                "host": host,
                "version": version,
                "root_escape": bool(escape)
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
                if version is not None:
                    host_data["version"] = version
                if escape is not None:
                    host_data["root_escape"] = bool(escape)
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

    def get_hosts(self, filter_term=None):
        """Return hosts from the database."""
        q = select(self.HostsTable)

        # if we're returning a single host by ID
        if self.is_host_valid(filter_term):
            q = q.filter(self.HostsTable.c.id == filter_term)
            results = self.db_execute(q).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return [results]
        # if we're filtering by host
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

    def add_share(self, host, permission, storage, share, access):
        """Check if this share is already in the DB, if not add it"""
        read_perm, write_perm, exec_perm = permission
        used, _, total = storage
        storage_str = f"{used} / {total}"
        access_str = ", ".join(access)

        new_share = {
            "host": host,
            "read_perm": read_perm,
            "write_perm": write_perm,
            "exec_perm": exec_perm,
            "storage": storage_str,
            "share": share,
            "access": access_str,
        }

        self.db_execute(
            Insert(self.SharesTable).on_conflict_do_nothing(),
            new_share,
        )

    def get_shares(self, filter_term=None):
        if self.is_share_valid(filter_term):
            q = select(self.SharesTable).filter(self.SharesTable.c.id == filter_term)
        elif filter_term:
            like_term = func.lower(f"%{filter_term}%")
            q = select(self.SharesTable).filter(self.SharesTable.c.name.like(like_term))
        else:
            q = select(self.SharesTable)
        return self.db_execute(q).all()

    def is_share_valid(self, share_id):
        """Check if this share ID is valid."""
        q = select(self.SharesTable).filter(self.SharesTable.c.id == share_id)
        results = self.db_execute(q).all()

        nxc_logger.debug(f"is_share_valid(shareID={share_id}) => {len(results) > 0}")
        return len(results) > 0
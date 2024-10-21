import sys

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
            "ip" text,
            "hostname" text,
            "port" integer,
            "server_banner" text
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

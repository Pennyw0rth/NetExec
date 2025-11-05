"""
Database module for Kerberos protocol.

Currently minimal.
"""


class database:
    """Kerberos protocol database handler"""

    def __init__(self, db_engine):
        self.db_engine = db_engine

    @staticmethod
    def db_schema(db_conn):
        """
        Define database schema for Kerberos protocol

        Currently minimal - can be extended to store:
        - Enumerated users
        - AS-REP roastable accounts
        - Timing information for stealth tracking
        - etc.
        """
        db_conn.execute("""CREATE TABLE IF NOT EXISTS kerberos_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            domain TEXT,
            username TEXT,
            status TEXT,
            timestamp TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id)
        )""")

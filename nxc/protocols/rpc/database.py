import threading
import warnings

from sqlalchemy import Boolean, Column, ForeignKeyConstraint, Integer, PrimaryKeyConstraint, String, UniqueConstraint, func, select
from sqlalchemy.dialects.sqlite import Insert
from sqlalchemy.exc import SAWarning
from sqlalchemy.orm import declarative_base

from nxc.database import BaseDB
from nxc.logger import nxc_logger

warnings.filterwarnings("ignore", category=SAWarning)

BaseTable = declarative_base()


class database(BaseDB):
    def __init__(self, db_engine):
        self.HostsTable = None
        self.UsersTable = None
        self.GroupsTable = None
        self.SharesTable = None

        self._lock = threading.Lock()

        super().__init__(db_engine)

    class Host(BaseTable):
        __tablename__ = "hosts"
        id = Column(Integer)
        ip = Column(String)
        hostname = Column(String)
        domain = Column(String)
        os = Column(String)
        dc = Column(Boolean)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
            UniqueConstraint("ip"),
        )

    class User(BaseTable):
        __tablename__ = "users"
        id = Column(Integer)
        domain = Column(String)
        username = Column(String)
        password = Column(String)
        credtype = Column(String)
        rid = Column(Integer)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
        )

    class Group(BaseTable):
        __tablename__ = "groups"
        id = Column(Integer)
        domain = Column(String)
        name = Column(String)
        rid = Column(Integer)
        group_type = Column(String)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
        )

    class Share(BaseTable):
        __tablename__ = "shares"
        id = Column(Integer)
        hostid = Column(Integer)
        name = Column(String)
        share_type = Column(String)
        remark = Column(String)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
            ForeignKeyConstraint(["hostid"], ["hosts.id"]),
        )

    @staticmethod
    def db_schema(db_conn):
        BaseTable.metadata.create_all(db_conn)

    def reflect_tables(self):
        self.HostsTable = self.reflect_table(self.Host)
        self.UsersTable = self.reflect_table(self.User)
        self.GroupsTable = self.reflect_table(self.Group)
        self.SharesTable = self.reflect_table(self.Share)

    def add_host(self, ip, hostname, domain, os_info, dc=None):
        """Add or update a host in the database."""
        hosts = []
        updated_ids = []

        q = select(self.HostsTable).filter(self.HostsTable.c.ip == ip)
        results = self.db_execute(q).all()

        if not results:
            new_host = {
                "ip": ip,
                "hostname": hostname,
                "domain": domain,
                "os": os_info if os_info is not None else "",
                "dc": dc,
            }
            hosts = [new_host]
        else:
            for host in results:
                host_data = host._asdict()
                if ip is not None:
                    host_data["ip"] = ip
                if hostname is not None:
                    host_data["hostname"] = hostname
                if domain is not None:
                    host_data["domain"] = domain
                if os_info is not None:
                    host_data["os"] = os_info
                if dc is not None:
                    host_data["dc"] = dc
                if host_data not in hosts:
                    hosts.append(host_data)
                    updated_ids.append(host_data["id"])

        nxc_logger.debug(f"Update Hosts: {hosts}")

        q = Insert(self.HostsTable)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=["ip"], set_=update_columns)

        self.db_execute(q, hosts)
        if updated_ids:
            nxc_logger.debug(f"add_host() - Host IDs Updated: {updated_ids}")
            return updated_ids

    def get_hosts(self, filter_term=None):
        """Return hosts from the database."""
        q = select(self.HostsTable)

        if filter_term:
            q = q.filter(self.HostsTable.c.ip == filter_term)

        return self.db_execute(q).all()

    def add_credential(self, credtype, domain, username, password, rid=None):
        """Add or update credential."""
        q = select(self.UsersTable).filter(
            func.lower(self.UsersTable.c.domain) == func.lower(domain),
            func.lower(self.UsersTable.c.username) == func.lower(username),
            func.lower(self.UsersTable.c.credtype) == func.lower(credtype),
        )
        results = self.db_execute(q).all()

        if not results:
            new_cred = {
                "credtype": credtype,
                "domain": domain,
                "username": username,
                "password": password,
                "rid": rid,
            }
            q = Insert(self.UsersTable)
            self.db_execute(q, [new_cred])

    def get_credentials(self, filter_term=None):
        """Return credentials from the database."""
        q = select(self.UsersTable)
        if filter_term:
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(func.lower(self.UsersTable.c.username).like(like_term))
        return self.db_execute(q).all()

    def add_user(self, domain, username, rid=None):
        """Add enumerated user."""
        q = select(self.UsersTable).filter(
            func.lower(self.UsersTable.c.domain) == func.lower(domain),
            func.lower(self.UsersTable.c.username) == func.lower(username),
        )
        results = self.db_execute(q).all()

        if not results:
            new_user = {
                "domain": domain,
                "username": username,
                "credtype": "enumerated",
                "password": "",
                "rid": rid,
            }
            q = Insert(self.UsersTable)
            self.db_execute(q, [new_user])

    def get_users(self, filter_term=None):
        """Return users from the database."""
        q = select(self.UsersTable)
        if filter_term:
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(func.lower(self.UsersTable.c.username).like(like_term))
        return self.db_execute(q).all()

    def add_group(self, domain, name, rid=None, group_type="domain"):
        """Add enumerated group."""
        q = select(self.GroupsTable).filter(
            func.lower(self.GroupsTable.c.domain) == func.lower(domain),
            func.lower(self.GroupsTable.c.name) == func.lower(name),
        )
        results = self.db_execute(q).all()

        if not results:
            new_group = {
                "domain": domain,
                "name": name,
                "rid": rid,
                "group_type": group_type,
            }
            q = Insert(self.GroupsTable)
            self.db_execute(q, [new_group])

    def get_groups(self, filter_term=None):
        """Return groups from the database."""
        q = select(self.GroupsTable)
        if filter_term:
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(func.lower(self.GroupsTable.c.name).like(like_term))
        return self.db_execute(q).all()

    def add_share(self, host_id, name, share_type, remark):
        """Add enumerated share."""
        share_data = {
            "hostid": host_id,
            "name": name,
            "share_type": share_type,
            "remark": remark,
        }
        q = Insert(self.SharesTable).on_conflict_do_nothing()
        self.db_execute(q, [share_data])

    def get_shares(self, filter_term=None):
        """Return shares from the database."""
        q = select(self.SharesTable)
        if filter_term:
            like_term = func.lower(f"%{filter_term}%")
            q = q.filter(func.lower(self.SharesTable.c.name).like(like_term))
        return self.db_execute(q).all()

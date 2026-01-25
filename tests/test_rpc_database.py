import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from nxc.database import delete_workspace, create_workspace
from nxc.first_run import first_run_setup
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.logger import NXCAdapter
from nxc.paths import WORKSPACE_DIR
from sqlalchemy.dialects.sqlite import Insert


@pytest.fixture(scope="session")
def db_engine():
    db_path = os.path.join(WORKSPACE_DIR, "test/rpc.db")
    db_engine = create_engine(f"sqlite:///{db_path}", isolation_level="AUTOCOMMIT", future=True)
    yield db_engine
    db_engine.dispose()


@pytest.fixture(scope="session")
def db_setup(db_engine):
    proto = "rpc"
    logger = NXCAdapter()
    first_run_setup(logger)
    p_loader = ProtocolLoader()
    create_workspace("test", p_loader)

    protocol_db_path = p_loader.get_protocols()[proto]["dbpath"]
    protocol_db_object = p_loader.load_protocol(protocol_db_path).database

    database_obj = protocol_db_object(db_engine)
    database_obj.reflect_tables()
    yield database_obj
    database_obj.shutdown_db()
    delete_workspace("test")


@pytest.fixture
def db(db_setup):
    yield db_setup
    db_setup.clear_database()


@pytest.fixture(scope="session")
def sess(db_engine):
    session_factory = sessionmaker(bind=db_engine, expire_on_commit=True)
    Session = scoped_session(session_factory)
    sess = Session()
    yield sess
    sess.close()


def test_add_host(db):
    db.add_host(
        "127.0.0.1",
        "localhost",
        "TEST.DEV",
        "Windows Server 2019",
        False,
    )
    inserted_host = db.get_hosts()
    assert len(inserted_host) == 1
    host = inserted_host[0]
    assert host.id == 1
    assert host.ip == "127.0.0.1"
    assert host.hostname == "localhost"
    assert host.domain == "TEST.DEV"
    assert host.os == "Windows Server 2019"
    assert host.dc is False


def test_update_host(db, sess):
    host = {
        "ip": "127.0.0.1",
        "hostname": "localhost",
        "domain": "TEST.DEV",
        "os": "Windows Server 2019",
        "dc": False,
    }
    iq = Insert(db.HostsTable)
    sess.execute(iq, [host])
    db.add_host(
        "127.0.0.1",
        "localhost",
        "TEST.DEV",
        "Windows Server 2022",
        True,
    )
    inserted_host = db.get_hosts()
    assert len(inserted_host) == 1
    host = inserted_host[0]
    assert host.id == 1
    assert host.ip == "127.0.0.1"
    assert host.hostname == "localhost"
    assert host.os == "Windows Server 2022"
    assert host.dc is True


def test_add_credential(db):
    db.add_credential("plaintext", "TEST.DEV", "admin", "password123", rid=500)
    creds = db.get_credentials()
    assert len(creds) == 1
    cred = creds[0]
    assert cred.domain == "TEST.DEV"
    assert cred.username == "admin"
    assert cred.password == "password123"
    assert cred.credtype == "plaintext"
    assert cred.rid == 500


def test_add_user(db):
    db.add_user("TEST.DEV", "testuser", rid=1001)
    users = db.get_users()
    assert len(users) == 1
    user = users[0]
    assert user.domain == "TEST.DEV"
    assert user.username == "testuser"
    assert user.credtype == "enumerated"
    assert user.rid == 1001


def test_add_group(db):
    db.add_group("TEST.DEV", "Domain Admins", rid=512, group_type="domain")
    groups = db.get_groups()
    assert len(groups) == 1
    group = groups[0]
    assert group.domain == "TEST.DEV"
    assert group.name == "Domain Admins"
    assert group.rid == 512
    assert group.group_type == "domain"


def test_add_local_group(db):
    db.add_group("BUILTIN", "Administrators", rid=544, group_type="local")
    groups = db.get_groups()
    assert len(groups) == 1
    group = groups[0]
    assert group.domain == "BUILTIN"
    assert group.name == "Administrators"
    assert group.rid == 544
    assert group.group_type == "local"


def test_add_share(db):
    # First add a host
    db.add_host("127.0.0.1", "localhost", "TEST.DEV", "Windows Server 2019", False)
    hosts = db.get_hosts()
    host_id = hosts[0].id

    db.add_share(host_id, "C$", "DISK", "Default share")
    shares = db.get_shares()
    assert len(shares) == 1
    share = shares[0]
    assert share.hostid == host_id
    assert share.name == "C$"
    assert share.share_type == "DISK"
    assert share.remark == "Default share"


def test_get_hosts_filter(db):
    db.add_host("192.168.1.1", "dc01", "TEST.DEV", "Windows Server 2019", True)
    db.add_host("192.168.1.2", "srv01", "TEST.DEV", "Windows Server 2019", False)

    # Filter by IP
    hosts = db.get_hosts("192.168.1.1")
    assert len(hosts) == 1
    assert hosts[0].ip == "192.168.1.1"


def test_get_users_filter(db):
    db.add_user("TEST.DEV", "administrator", rid=500)
    db.add_user("TEST.DEV", "guest", rid=501)
    db.add_user("TEST.DEV", "testadmin", rid=1001)

    # Filter by username
    users = db.get_users("admin")
    assert len(users) == 2  # administrator and testadmin


def test_get_groups_filter(db):
    db.add_group("TEST.DEV", "Domain Admins", rid=512, group_type="domain")
    db.add_group("TEST.DEV", "Domain Users", rid=513, group_type="domain")
    db.add_group("TEST.DEV", "Enterprise Admins", rid=519, group_type="domain")

    # Filter by name
    groups = db.get_groups("Admin")
    assert len(groups) == 2  # Domain Admins and Enterprise Admins


def test_duplicate_user_not_added(db):
    db.add_user("TEST.DEV", "testuser", rid=1001)
    db.add_user("TEST.DEV", "testuser", rid=1001)  # Duplicate
    users = db.get_users()
    assert len(users) == 1


def test_duplicate_group_not_added(db):
    db.add_group("TEST.DEV", "Domain Admins", rid=512, group_type="domain")
    db.add_group("TEST.DEV", "Domain Admins", rid=512, group_type="domain")  # Duplicate
    groups = db.get_groups()
    assert len(groups) == 1


def test_add_builtin_group(db):
    db.add_group("BUILTIN", "Remote Desktop Users", rid=555, group_type="local")
    groups = db.get_groups()
    assert len(groups) == 1
    group = groups[0]
    assert group.domain == "BUILTIN"
    assert group.name == "Remote Desktop Users"
    assert group.rid == 555
    assert group.group_type == "local"


def test_get_groups_by_type(db):
    db.add_group("TEST.DEV", "Domain Admins", rid=512, group_type="domain")
    db.add_group("TEST.DEV", "Domain Users", rid=513, group_type="domain")
    db.add_group("BUILTIN", "Administrators", rid=544, group_type="local")
    db.add_group("BUILTIN", "Users", rid=545, group_type="local")

    all_groups = db.get_groups()
    assert len(all_groups) == 4


def test_user_with_bad_password_count(db):
    db.add_user("TEST.DEV", "lockeduser", rid=1002)
    users = db.get_users("lockeduser")
    assert len(users) == 1
    assert users[0].username == "lockeduser"

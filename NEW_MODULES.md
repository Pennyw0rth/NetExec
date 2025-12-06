# New NetExec Modules

This document describes the new modules added to NetExec to enhance its enumeration and credential dumping capabilities.

## Modules Overview

### 1. enum_shares
**Category:** Enumeration  
**Protocol:** SMB  
**Description:** Enumerate all shares with detailed read/write permissions

This module provides a comprehensive view of all accessible shares on a target system, testing both read and write permissions for each share. It's more detailed than the default share enumeration.

**Options:**
- `VERBOSE` - Show detailed information for each share including those with no access (default: False)

**Example Usage:**
```bash
nxc smb 192.168.1.10 -u admin -p password -M enum_shares
nxc smb 192.168.1.10 -u admin -p password -M enum_shares -o VERBOSE=true
```

**Output:**
- Lists all shares with their permissions (READ/WRITE)
- Highlights writable shares for easy identification
- Provides a summary of readable and writable shares

---

### 2. chrome_cookies
**Category:** Credential Dumping  
**Protocol:** SMB  
**Description:** Extract Chrome/Chromium browser cookies and login credentials

This module locates Chrome and Chromium browser databases containing saved login data and cookies. While it identifies the database files, actual decryption requires the `--dpapi` flag or additional tools like dploot.

**Options:**
- `USER` - Specify a username to target (default: all users)
- `COOKIES` - Extract cookies database as well (default: False)

**Example Usage:**
```bash
nxc smb 192.168.1.10 -u admin -p password -M chrome_cookies
nxc smb 192.168.1.10 -u admin -p password -M chrome_cookies -o USER=john COOKIES=true
```

**Output:**
- Lists found Chrome/Chromium Login Data files
- Lists found Chrome/Chromium Cookies files (if COOKIES=true)
- Provides file paths for manual extraction

---

### 3. scheduled_tasks
**Category:** Enumeration  
**Protocol:** SMB, WMI  
**Description:** Enumerate Windows scheduled tasks and their configurations

This module enumerates scheduled tasks on Windows systems, showing task names, states, execution users, and run times. Useful for identifying persistence mechanisms and privilege escalation opportunities.

**Options:**
- `ENABLED` - Only show enabled tasks (default: False)
- `USER` - Filter tasks by username

**Example Usage:**
```bash
nxc smb 192.168.1.10 -u admin -p password -M scheduled_tasks
nxc smb 192.168.1.10 -u admin -p password -M scheduled_tasks -o ENABLED=true
nxc smb 192.168.1.10 -u admin -p password -M scheduled_tasks -o USER=Administrator
```

**Output:**
- Task names and their states
- User accounts associated with tasks
- Last run and next run times
- Total count of scheduled tasks

---

### 4. startup_items
**Category:** Enumeration  
**Protocol:** SMB, WMI  
**Description:** Enumerate startup programs, services, and autorun registry entries

This module identifies programs and services that run at system startup, including registry Run keys, startup folders, and auto-start services. Essential for finding persistence mechanisms.

**Options:**
- `REGISTRY` - Include registry autorun entries (default: True)
- `STARTUP` - Include startup folder items (default: True)
- `SERVICES` - Include services set to auto-start (default: False)

**Example Usage:**
```bash
nxc smb 192.168.1.10 -u admin -p password -M startup_items
nxc smb 192.168.1.10 -u admin -p password -M startup_items -o SERVICES=true
nxc smb 192.168.1.10 -u admin -p password -M startup_items -o REGISTRY=false STARTUP=true
```

**Output:**
- Registry autorun entries from Run/RunOnce keys (HKLM and HKCU)
- Startup folder contents (All Users and User-specific)
- Auto-start services (when SERVICES=true)

---

### 5. clipboard_history
**Category:** Credential Dumping  
**Protocol:** SMB  
**Description:** Extract Windows 10+ clipboard history if enabled

This module searches for Windows clipboard history databases. Windows 10 version 1809+ can store clipboard history, which may contain sensitive information like passwords, URLs, or other data.

**Options:**
- `USER` - Target specific username (default: all users)

**Example Usage:**
```bash
nxc smb 192.168.1.10 -u admin -p password -M clipboard_history
nxc smb 192.168.1.10 -u admin -p password -M clipboard_history -o USER=john
```

**Output:**
- Lists clipboard database files found
- Shows file paths for manual extraction
- Notes about Windows version requirements

**Note:** Clipboard history must be enabled in Windows Settings. The database files need to be downloaded and parsed locally to extract actual content.

---

### 6. rdp_sessions
**Category:** Enumeration  
**Protocol:** SMB, WMI  
**Description:** Enumerate active and disconnected RDP sessions on target system

This module enumerates Remote Desktop Protocol (RDP) sessions, showing both active and disconnected sessions. Useful for identifying logged-in users and potential lateral movement targets.

**Options:**
- `ACTIVE` - Show only active sessions (default: False)

**Example Usage:**
```bash
nxc smb 192.168.1.10 -u admin -p password -M rdp_sessions
nxc smb 192.168.1.10 -u admin -p password -M rdp_sessions -o ACTIVE=true
```

**Output:**
- Session usernames and states (Active/Disconnected)
- Session IDs and logon times
- Summary of total, active, and disconnected sessions

---

## Installation

These modules are included in the NetExec repository under `nxc/modules/`. No additional installation is required beyond having NetExec installed.

## Security Considerations

- These modules require appropriate credentials (usually administrative) to function
- Some modules (chrome_cookies, clipboard_history) identify sensitive data locations but don't automatically decrypt them
- Always ensure you have proper authorization before using these tools in any environment
- Use these modules responsibly and only in authorized penetration testing or security assessment scenarios

## Contributing

These modules follow NetExec's module development guidelines:
- Proper categorization (Enumeration, Credential Dumping, or Privilege Escalation)
- Clear option documentation
- Appropriate error handling
- Consistent logging using context.log methods

## Support

For issues, suggestions, or improvements, please open an issue or pull request on the NetExec GitHub repository.

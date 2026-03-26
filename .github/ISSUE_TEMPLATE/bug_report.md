---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

# ❗❗❗ Before filing this bug report, MAKE SURE you have already downloaded the newest version of NetExec from GitHub and installed it! Many issues have already been reported and fixed, _especially_ if you are running the native Kali version! Please delete this line before submitting your issue if you have done so.❗❗❗



**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior i.e.:
Command: `netexec smb -u username -p password`
Resulted in:
```
netexec smb 10.10.10.10 -u username -p password -x "whoami"
SMB         10.10.10.10  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:domain) (signing:True) (SMBv1:False)
SMB         10.10.10.10  445    DC01             [+] domain\username:password
Traceback (most recent call last):
...
```

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**NetExec info**
 - OS: [e.g. Kali]
 - Version of nxc: [e.g. v1.5.2] (run nxc --version and post the _exact_ string that is output)
 - Installed from: apt/github/pip/docker/...? Please try with latest release before opening an issue

**Additional context**
Add any other context about the problem here.

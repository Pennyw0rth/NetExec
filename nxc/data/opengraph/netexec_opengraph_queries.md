# NetExec OpenGraph - BloodHound-CE custom queries

Copy/paste these Cypher queries into BloodHound-CE (Explore → Cypher, or save them as
Custom Queries). They filter on the **tags** NetExec adds via OpenGraph.

> Tag keys from `enum_cve` contain spaces/slashes, so they are wrapped in backticks
> (e.g. `` c.`NTLM reflection` ``).

## Vulnerabilities

**All computers with any NetExec vulnerability tag**
```cypher
MATCH (c:Computer) WHERE c.zerologon = true OR c.nopac = true OR c.ms17_010 = true OR c.smbghost = true OR c.cve_2019_1040 = true OR c.printnightmare = true OR c.webclientrunning = true OR c.ntlm_reflection = true OR c.`NTLM reflection` = true OR c.`Ghost SPN` = true OR c.`NTLM MIC Bypass` = true OR c.`BadSuccessor` = true OR c.`ESC15 / EKUwu` = true RETURN c
```

**Zerologon vulnerable (CVE-2020-1472)**
```cypher
MATCH (c:Computer) WHERE c.zerologon = true RETURN c
```

**noPac vulnerable (CVE-2021-42278/42287)**
```cypher
MATCH (c:Computer) WHERE c.nopac = true RETURN c
```

**MS17-010 / EternalBlue vulnerable**
```cypher
MATCH (c:Computer) WHERE c.ms17_010 = true RETURN c
```

**SMBGhost vulnerable (CVE-2020-0796)**
```cypher
MATCH (c:Computer) WHERE c.smbghost = true RETURN c
```

**Drop-the-MIC vulnerable (CVE-2019-1040)**
```cypher
MATCH (c:Computer) WHERE c.cve_2019_1040 = true RETURN c
```

**PrintNightmare vulnerable (CVE-2021-34527)**
```cypher
MATCH (c:Computer) WHERE c.printnightmare = true RETURN c
```

**WebClient / WebDAV running (relay to ADCS/LDAP)**
```cypher
MATCH (c:Computer) WHERE c.webclientrunning = true RETURN c
```

**NTLM reflection vulnerable (CVE-2025-33073)**
```cypher
MATCH (c:Computer) WHERE c.ntlm_reflection = true OR c.`NTLM reflection` = true RETURN c
```

**Ghost SPN vulnerable (CVE-2025-58726)**
```cypher
MATCH (c:Computer) WHERE c.`Ghost SPN` = true RETURN c
```

**NTLM MIC Bypass vulnerable (CVE-2025-54918)**
```cypher
MATCH (c:Computer) WHERE c.`NTLM MIC Bypass` = true RETURN c
```

**BadSuccessor vulnerable (CVE-2025-53779)**
```cypher
MATCH (c:Computer) WHERE c.`BadSuccessor` = true RETURN c
```

**ESC15 / EKUwu vulnerable (CVE-2024-49019)**
```cypher
MATCH (c:Computer) WHERE c.`ESC15 / EKUwu` = true RETURN c
```

## Host configuration

**SMB signing NOT required (relay targets)**
```cypher
MATCH (c:Computer) WHERE c.smbsigning = false RETURN c
```

**LDAP signing NOT required**
```cypher
MATCH (c:Computer) WHERE c.ldapsigning = false RETURN c
```

**LDAPS channel binding NOT enforced**
```cypher
MATCH (c:Computer) WHERE c.ldaps_channel_binding IS NOT NULL AND c.ldaps_channel_binding <> 'Always' RETURN c
```

**RDP NLA disabled**
```cypher
MATCH (c:Computer) WHERE c.rdp_nla = false RETURN c
```


## MSSQL

**MSSQL servers**
```cypher
MATCH (c:Computer) WHERE c.mssql_present = true RETURN c
```

**MSSQL servers with encryption disabled**
```cypher
MATCH (c:Computer) WHERE c.mssql_present = true AND c.mssql_encryption = false RETURN c
```

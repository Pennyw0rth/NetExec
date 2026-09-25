# NetExec OpenGraph - BloodHound-CE custom queries

Copy/paste these Cypher queries into BloodHound-CE (Explore → Cypher, or save as Custom
Queries). They combine the **tags** NetExec adds via OpenGraph with BloodHound's native
graph so you can prioritize targets and find attack paths.


---

## 1. Servers with specific roles vulnerable

**All DCs vulnerable**
```cypher
MATCH (c:Computer)-[:MemberOf*1..]->(dc:Group)
WHERE dc.objectid ENDS WITH '-516' AND (c.zerologon = true OR c.nopac = true OR c.`NTLM MIC Bypass` = true OR c.`BadSuccessor`)
RETURN c
```

**All CAs vulnerable**
```
MATCH (c:Computer)-[:HostsCAService]->(:EnterpriseCA)
WHERE c.`ESC15 / EKUwu`=true OR c.Certighost=true
RETURN c
```

---

## 2. All vulnerable hosts → Domain Admins 


**All hosts with any NetExec vulnerability tag**
```cypher
MATCH (c:Computer)
WHERE c.ms17_010 = true OR c.smbghost = true OR c.cve_2019_1040 = true OR c.printnightmare = true OR c.webclientrunning = true OR c.`NTLM reflection` = true OR c.`Ghost SPN` = true
RETURN c
```

**Vulnerable hosts where a Domain Admin has a session**
```cypher
MATCH p = (c:Computer)-[:HasSession]->(u)-[:MemberOf*1..]->(g:Group)
WHERE (c.ms17_010 = true OR c.smbghost = true OR c.cve_2019_1040 = true OR c.printnightmare = true OR c.webclientrunning = true OR c.`NTLM reflection` = true OR c.`Ghost SPN` = true)
  AND g.objectid ENDS WITH '-512'
RETURN p
```

**Shortest path from any vulnerable host to Domain Admins**
```cypher
MATCH (c:Computer)
WHERE cc.ms17_010 = true OR c.smbghost = true OR c.cve_2019_1040 = true OR c.printnightmare = true OR c.webclientrunning = true OR c.`NTLM reflection` = true OR c.`Ghost SPN` = true
MATCH p = shortestPath((c)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|HasTrustKeys|ManageCA|ManageCertificates|Contains|SameForestTrust|SpoofSIDHistory|AbuseTGTDelegation*1..]->(g:Group))
WHERE g.objectid ENDS WITH '-512'
RETURN p
```

---

## 3. Coercion / NTLM-relay quick lists


**SMB signing NOT required — shortest path to Domain Admins**
```cypher
MATCH (c:Computer)
WHERE c.smbsigning = false
MATCH p = shortestPath((c)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|HasTrustKeys|ManageCA|ManageCertificates|Contains|SameForestTrust|SpoofSIDHistory|AbuseTGTDelegation*1..]->(g:Group))
WHERE g.objectid ENDS WITH '-512'
RETURN p
```

**LDAP signing not required / LDAPS channel binding not enforced**
```cypher
MATCH (c:Computer) WHERE c.ldapsigning = false OR (c.ldaps_channel_binding IS NOT NULL AND c.ldaps_channel_binding <> 'Always') RETURN c
```

---

## 4. MSSQL

**MSSQL servers**
```cypher
MATCH (c:Computer) WHERE c.mssql_present = true RETURN c
```

**MSSQL servers with encryption disabled (sniff/relay TDS)**
```cypher
MATCH (c:Computer) WHERE c.mssql_present = true AND c.mssql_encryption = false RETURN c
```

**Shortest path from an MSSQL server to Domain Admins (prioritize SQL footholds)**
```cypher
MATCH (c:Computer)
WHERE c.mssql_present = true
MATCH p = shortestPath((c)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|AddMember|HasSession|AllowedToDelegate|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|DCSync|ReadLAPSPassword|ReadGMSAPassword|SQLAdmin|AddKeyCredentialLink|Contains*1..]->(g:Group))
WHERE g.objectid ENDS WITH '-512'
RETURN p
```

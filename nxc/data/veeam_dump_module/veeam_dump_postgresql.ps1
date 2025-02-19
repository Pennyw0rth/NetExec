$PostgreSqlExec = "REPLACE_ME_PostgreSqlExec"
$PostgresUserForWindowsAuth = "REPLACE_ME_PostgresUserForWindowsAuth"
$SqlDatabaseName = "REPLACE_ME_SqlDatabaseName"
$b64Salt = "REPLACE_ME_b64Salt"

$SQLStatement = "SELECT user_name AS User, password AS Password, description AS Description  FROM credentials WHERE password != '';"
$output = . $PostgreSqlExec -U $PostgresUserForWindowsAuth -w -d $SqlDatabaseName -c $SQLStatement --csv | ConvertFrom-Csv

if ($output.count -eq 0) {
	Write-Host "No passwords found!"
	exit
}

# Decrypting passwords using DPAPI
Add-Type -assembly System.Security
$output | ForEach-Object -Process {
	$EncryptedPWD = [Convert]::FromBase64String($_.password)
	$enc = [system.text.encoding]::Default

	try {
		# Decrypt password with DPAPI (old Veeam versions)
		$raw = [System.Security.Cryptography.ProtectedData]::Unprotect( $EncryptedPWD, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine )
		$pw_string = $enc.GetString($raw) -replace '\s', 'WHITESPACE_ERROR'
	} catch {
		try{
			# Decrypt password with salted DPAPI (new Veeam versions)
			$salt = [System.Convert]::FromBase64String($b64Salt)
			$hex = New-Object -TypeName System.Text.StringBuilder -ArgumentList ($EncryptedPWD.Length * 2)
			foreach ($byte in $EncryptedPWD)
			{
				$hex.AppendFormat("{0:x2}", $byte) > $null
			}
			$hex = $hex.ToString().Substring(74,$hex.Length-74)
			$EncryptedPWD = New-Object -TypeName byte[] -ArgumentList ($hex.Length / 2)
			for ($i = 0; $i -lt $hex.Length; $i += 2)
			{
				$EncryptedPWD[$i / 2] = [System.Convert]::ToByte($hex.Substring($i, 2), 16)
			}
			$raw = [System.Security.Cryptography.ProtectedData]::Unprotect($EncryptedPWD, $salt, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
			$pw_string = $enc.GetString($raw) -replace '\s', 'WHITESPACE_ERROR'
		}catch {
			$pw_string = "COULD_NOT_DECRYPT"
		}
	}
	$_.user = $_.user -replace '\s', 'WHITESPACE_ERROR'
	$_.password = $pw_string
	$_.description = $_.description -replace '\s', 'WHITESPACE_ERROR'
}

Write-Output $output | Format-Table -HideTableHeaders | Out-String -Width 10000
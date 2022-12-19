<#
.SYNOPSIS
    Will look for cloud accounts configured on a device.

.DESCRIPTION
    Searches device for accounts:
        - Azure Active Directory account that joinde device to Azure AD
        - Azure Active Directory account for currently logged on user
        - "Work or school" account configured on device
        - User that enrolled dvice to Intune
        
    
    Code extracted from DeviceEnrollment script, might come in handy.

.NOTES
    
#>


#Region Functions

Function Test-IsAdmin {

    If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

        # Does not have Admin privileges
        Return $false

    }
    else {

        #Has Admin rights
        Return $true
    
    }
    
}

function Convert-HexToString {
    <#
.DESCRIPTION
Converts Hex data to String 
.NOTES
Based on work from:
François-Xavier Cat: https://twitter.com/lazywinadmin
as described here: https://lazywinadmin.com/2015/08/powershell-remove-special-characters.html#unicode-specific-code-point
#>
param (
    [Parameter(Mandatory=$true)]
    [string]$hexString
)

# Convert data to string and clean it up
$asciiChars = $hexString -split ',' | ForEach-Object {[char][byte]"0x$_"}
$asciiString = $asciiChars -join ''
$asciiString = $asciiString -replace " ",""
$asciiString = $asciiString -replace '[^a-z0-9/@.-]', ''

Return $asciiString

}


Function Confirm-AADuser {
    param ()

    $fReturn = @{
        exist = $false
        username = ""
    }
    
    # Find the currently logged-on user on device.
    #   Get SID for logged-on user

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
    $regValue = "SelectedUserSID"
    
    try {
        $usrSID = Get-ItemPropertyValue -Path $regPath -Name $regValue  -ErrorAction Stop
    }
    catch {
        # SID for logged-on user not found, bye
        $fReturn.username = $null
        Return $fReturn
    }

    #   Get username 
    $basePath = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$usrSID\IdentityCache\$usrSID"
    
    try {
        $userId = (Get-ItemProperty -Path $basePath -Name UserName -ErrorAction Stop).UserName
        $fReturn.username = $userId
        $fReturn.exist = $true
    }
    catch {
        # No username found
    }
    
    Return $fReturn

}

Function Confirm-WhoJoinedDevice {
    <#
    .DESCRIPTION
    Looks for a AzureAD account. Queries Thumbrpint via dsregcmd then looks for the account details in registry.
    Modified to return $true/$false and account details
    .NOTES
    Based on work from:
    Michael Herndon: https://www.linkedin.com/in/nerdymishka/
    as described here: https://nerdymishka.com/articles/azure-ad-domain-join-registry-keys/
    Also inspired by:
        strassenkater79: https://superuser.com/users/1754084/strassenkater79
        Jos Lieben: https://www.linkedin.com/in/joslieben/
    #>

    $userEmail = ""
    $fReturn = @{
        exist = $false
        accountname = ""
    }

    #Get Tenant info for device, if not found exit/terminate
    $dsTenantId = (dsregcmd /status | Select-String "TenantId :" | out-string).split(':')[1].Trim()
    if (($null -eq $dsTenantId) -or ($dsTenantId -eq "")) {
        Write-Warning "Did not find Tenant ID for device"
        Exit 1
    }

    # For the Tenant for which device is joined, go look for the related user e-mail
    try {
        $subKey = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo" -ErrorAction Stop
    }
    catch {
        Return $fReturn
    }

    #    Look for the user in all subkeys, pick the one that corresponds to the device Tenant
    $guids = $subKey.GetSubKeyNames()
    foreach($guid in $guids) {

        $guidSubKey = $subKey.OpenSubKey($guid)
        $tenantId = $guidSubKey.GetValue("TenantId")
        
        if ($tenantId -eq $dsTenantId) {

            $userEmail = $guidSubKey.GetValue("UserEmail")
            $fReturn.exist = $true
            $fReturn.accountname = $userEmail

            #If user found stop the foreach loop, no need for anything else.          
            break
        }

    }

    Return $fReturn
 
}

Function Confirm-EnrolledUsr {
    param ()

    $fReturn = @{
        exist = $false
        Upn = ""
    }

    # Get Tenant info for device, if not found exit/terminate
    $dsTenantId = (dsregcmd /status | Select-String "TenantId :" | out-string).split(':')[1].Trim()
    if (($null -eq $dsTenantId) -or ($dsTenantId -eq "")) {
        Write-Warning "Did not find Tenant ID for device"
        Exit 1
    }

    # For the Tenant for which device is joined, go look for the related user e-mail
    $subKey = Get-Item "HKLM:\SOFTWARE\Microsoft\Enrollments"

    #    Look for the user AAD TenantID in all subkeys, pick the one that corresponds to the device Tenant
    $guids = $subKey.GetSubKeyNames()
    foreach($guid in $guids) {

        $guidSubKey = $subKey.OpenSubKey($guid)
        $tenantId = $guidSubKey.GetValue("AADTenantID")
        
        if ($tenantId -eq $dsTenantId) {

            $usrUpn = $guidSubKey.GetValue("UPN")
            $fReturn.exist = $true
            $fReturn.Upn = $usrUpn

            #If user found stop the foreach loop, no need for anything else.          
            break
        }

    }

    Return $fReturn
    
}


Function Read-SettingsDat {
    <#
    .DESCRIPTION
    Looks for a configurd Work or School account. Reads info from Settings.Dat file by importing it to Registry, then looks for TenantId, if found gets the UPN.
    .NOTES
    Based on work from:
    Damir Arh: https://twitter.com/DamirArh/
    as described here: https://www.damirscorner.com/blog/posts/20150117-ManipulatingSettingsDatFileWithSettingsFromWindowsStoreApps.html
    #>

    $fReturn = @{
        exist = $false
        Upn = ""
    }

    function Read-SettingsFromFile {
        param (
            [Parameter(Mandatory)]
            [string]$filePath,
            [Parameter(Mandatory)]
            [string]$txtValue
        )

        $Data = @{
            hexValue = $null
            valueType = $null
            timeStamo = $null
        }

        $Result = 0

        if (Test-Path -Path $filePath) {
            $fileContents = Get-Content $filePath
        }
        else {
            Write-Warning "Work School registry file not found. **$filePath"
            Return $Data
        }

        $processing = $false

        Foreach ($line in $fileContents) {

            If (-not($processing))
            {
                # scanning for first line of the value
                If ($line.StartsWith($txtValue))
                {
                    # found - switch mode and start reading 
                    $processing = $true
                    $txtValue = $line.Replace($txtValue, "")
                }
            }
            Else
            {
                # non-first lines have leading spaces
                $txtValue += $line.TrimStart(" ")
            }

            If ($processing)
            {
                # scanning for last line of the value
                If ($txtValue.EndsWith("\"))
                {
                    # strip trailing backslash; the value continues
                    $txtValue = $txtValue.TrimEnd("\")
                }
                Else
                {
                    # no backslash; the value is complete
                    
                    # extract type and timestamp from old value
                    $match = $txtValue -match "(.*:)(.*)"
                    $valueType = $matches[1]
                    $timeStamp = $matches[2].Substring($matches[2].Length - 23)
                    $hexValue = $matches[2].Substring(0, $matches[2].Length - 24)

                    $Data = @{
                        hexValue = $hexValue
                        valueType = $valueType
                        timeStamo = $timestamp
                    }
                    $processing = $false

                    # Found what we are looking for, stop
                    Break
                }
            }
        }

        Return $Data
        
    }

    function Confirm-UsrSID {
        param ()

        # Find the currently logged-on user on device.
        #   Get SID for logged-on user

        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
        $regValue = "SelectedUserSID"
        
        try {
            $usrSID = Get-ItemPropertyValue -Path $regPath -Name $regValue  -ErrorAction Stop
        }
        catch {
            # SID for logged-on user not found, bye
            Return = $null
        }

        Return $usrSID
        
    }

    $usrSID = Confirm-UsrSID
    $localDataPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$usrSID" -Name "ProfileImagePath"
    $PackageName = "Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy"
    $SettingsPath = "Settings\Settings.dat" 
    $SettingsBackup  = "Settings\backup.dat"
	$settingsFile = "$localDataPath\AppData\Local\Packages\$PackageName\$SettingsPath"
    $settingsBackupFile = "$localDataPath\AppData\Local\Packages\$PackageName\$SettingsBackup"
    $tempPath = "$localDataPath\AppData\Local\Temp"

    $dsTenantId = (dsregcmd /status | Select-String "TenantId :" | out-string).split(':')[1].Trim()
    
    # Nothing to do if there is no Tenant info
    if (($null -eq $dsTenantId) -or ($dsTenantId -eq "")) {
        Return $fReturn
    }

	# temporary paths
	$regFile = "$tempPath\Settings_$((Get-Date -format yyyyMMddhhmmtt).ToString()).reg"
    $registryImportLocation = "HKLM\_TMP"
	$regPath = "HKLM:\_TMP"

    if (Test-Path $settingsFile) {

        try {
            Copy-Item $settingsFile -Destination $settingsBackupFile -Force -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to read Work or School DAT Settings"
            Return $fReturn
        }
        
    
    }

	$null = reg load $registryImportLocation $settingsBackupFile

	
    # For the Tenant for which device is joined, find a connected Work or School account (AAD account)
    try {

        $subKey = Get-Item "$regPath\LocalState\SSOUsers" -ErrorAction Stop
        $subKeyName = $subKey.Name    
        $guids = $subKey.GetSubKeyNames()

        if (($null -eq $guids.Count) -or ($guids.Count -eq 0)) {
           $result = 1
        }

    }
    catch {
        $result = 1
    }

    if ($result -eq 1) {
        # Something failed. Cleanup and return.

        $subKey = $null
        [System.GC]::GetTotalMemory($true) | Out-Null
        reg unload $registryImportLocation

        # Delete DAT backup file
        if (Test-Path $settingsBackupFile) {
            Remove-Item $settingsBackupFile -Force
        }

        Return $fReturn
    }

 
    foreach($guid in $guids) {

        $null = reg export "$subKeyName\$guid" $regFile

        $valueTenantId = """TenantId""="
        $valueUpn = """UPN""="
        
        $datTenantId = Read-SettingsFromFile $regFile $valueTenantId

        if ((!($null -eq $datTenantId.hexValue)) -or (!($datTenantId.hexValue -eq ""))) {
            $tenantId = Convert-HexToString $($datTenantId.hexValue)
            #Write-Host "Tenand ID (WS): " $tenantId
        }
        else {
            Return $fReturn
        }
        

        # See if there Tenant is a match
        if ($tenantId -eq $dsTenantId) {

            # Found TenantID match, get the UPN
            $datUPN = Read-SettingsFromFile $regFile $valueUpn
            $usrUpn = Convert-HexToString $($datUpn.hexValue)
            
            $fReturn.exist = $true
            $fReturn.Upn = $usrUpn

            #If user found stop the foreach loop, no need for anything else.          
            break
        }

    }


    Remove-Variable -Name "subKey"
    [System.GC]::GetTotalMemory($true) | Out-Null
    reg unload $registryImportLocation

    # Delete temp Settings Reg File
    if (Test-Path $regFile) {
        Remove-Item $regFile -Force
    }

    # Delete DAT backup file
    if (Test-Path $settingsBackupFile) {
        Remove-Item $settingsBackupFile -Force
    }

    Return $fReturn

}

#Endregion Functions


#Region Main

Write-Host "`n`n"

if (Test-IsAdmin) {         # Part of the code require Admin privileges.

    # Confirm if there is informaion of AzureAD that joined device to Azure AD Domain.
    $usrJoinedDevice = Confirm-WhoJoinedDevice

    # Find if currently logged on user has Azure AD Identity.
    $usrAAD = Confirm-AADuser

    # Find if there is a connected Azure AD Account (Work or school acccount?) registered on the device.
    $usrWS = Read-SettingsDat


    Write-Host "Account information found for device: `n" -ForegroundColor Yellow

    Write-Host "Device Azure AD joined by`t: " -NoNewline -ForegroundColor Green
    if ($usrJoinedDevice.exist) {
        Write-Host """$($usrJoinedDevice.accountname)""."
    }
    else {
        Write-Host "Not found."
    }

    Write-Host "Logged on user AAD identity`t: " -NoNewline -ForegroundColor Green
    if ($usrAAD.exist) {
        Write-Host """$($usrAAD.username)""."
    }
    else {
        Write-Host "Not found."
    }

    Write-Host "Work/school registered account`t: " -NoNewline -ForegroundColor Green
    if ($usrWS.exist) {
        Write-Host """$($usrWS.Upn)""."
    }
    else {
        Write-Host "Not found."
    }

}
else {
    Write-Host "Script needs to be executed with Administrative privileges." -ForegroundColor Red
}

Write-Host "`n`n"


#Endregion Main

<#
.SYNOPSIS
    Silently enroll a Windows device to Microsoft Intune if already joined to Azure AD and has an AAD user account.

.DESCRIPTION
    Script to help automatically enroll existing Windows devices (Hybrid or Azure AD joined) into Intune.

    Verifies if device is Azure AD join, that has an Azure AD from same Tenant and verifies that Intune services do not exist.
    Configures MDM urls and execites Device Enrollment.
    
    Based on Rudy Ooms (tw:@Mister_MDM) blog: 
    https://call4cloud.nl/2020/05/intune-auto-mdm-enrollment-for-devices-already-azure-ad-joined/

.NOTES
    
    All enrollment logic based on Rudy Ooms blog:
    https://call4cloud.nl/2020/05/intune-auto-mdm-enrollment-for-devices-already-azure-ad-joined/
    
    Added verifications:
        - Validate admin privilige
        - Confirm device is AzureAd join
        - Confirm existing user from same Tenant as device
        - Execute enrollment as system

    Function to execute as SYSTEM from Ondrej Sebela (tw:@AndrewZtrhgf), described in the following blog:
    https://doitpsway.com/fixing-hybrid-azure-ad-join-on-a-device-using-powershell
    Source: https://github.com/ztrhgf/useful_powershell_functions/blob/master/INTUNE/Reset-HybridADJoin.ps1

    Other source:
    https://nerdymishka.com/articles/azure-ad-domain-join-registry-keys/

    To do:
    - At end verify that Device correctly received Intune Certificate.


#>

#Region Functions
Function Test-IsAdmin {

    If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

        # Does not have Admin privileges
        Write-Warning "Script needs to run with Administrative privileges"
        Exit 9

    }
    else {

        #Has Admin rights
        Write-Host "Administrator rights have been confirmed"
    
    }
    
}

Function Test-AzureAdJoin {
    
    $dsreg = dsregcmd.exe /status
    if (($dsreg | Select-String "AzureAdJoined :") -match "YES") {

        Write-Host "Device is Azure AD Joined"
        Return $true

    }
    else {

        Write-Warning "Device is not joined to Azure AD"
        Return $false

    }

}

Function Test-IntuneEnrollment {

    <#
    .NOTES
    To verify Intune service used logic from script https://github.com/ztrhgf/useful_powershell_functions/blob/master/INTUNE/Get-IntuneEnrollmentStatus.ps1
    Author: Ondrej Sebela
    #>

    $Result = 1

    #Look for MDMUrl
    $mdmUrl = (dsregcmd /status | Select-String "MdmUrl :" | out-string) -Split("Url :")
    $mdmUrl = $mdmUrl[1].Trim()

    if (($null -eq $mdmUrl) -or ($mdmUrl -eq "")) {
        Write-Host "No MDM URL found"
        $Result = 1
    }
    else {
        Write-Warning "Found MDM $mdmUrl"
        $Result = 0
    }

    #Search for Intune Service
    $MDMService = Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue
    if ($MDMService) {
        
        Write-Warning "Found Intune service on device"
        $Result = 0
    }

    
    if ($Result -eq 0) {
        Return $true
    }
    else {
        Write-Host "Intune service not found on device"
        Return $false
    }


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
                    $timestamp = $matches[2].Substring($matches[2].Length - 23)
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
    $SettingsPath = "Settings\Settings.dat" # Change to "Settings\settings.dat" after done testing
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
	#$regFile = "$tempPath\Settings_$((Get-Date -format yyyyMMddhhmmtt).ToString()).reg"  #Temporary reg file
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
            Write-Host "Tenand ID (WS): " $tenantId
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





Function Invoke-AsSystem {
    <#
    .SYNOPSIS
    Function for running specified code under SYSTEM account.

    .DESCRIPTION
    Function for running specified code under SYSTEM account.

    Helper files and sched. tasks are automatically deleted.

    .PARAMETER scriptBlock
    Scriptblock that should be run under SYSTEM account.

    .PARAMETER computerName
    Name of computer, where to run this.

    .PARAMETER returnTranscript
    Add creating of transcript to specified scriptBlock and returns its output.

    .PARAMETER cacheToDisk
    Necessity for long scriptBlocks. Content will be saved to disk and run from there.

    .PARAMETER argument
    If you need to pass some variables to the scriptBlock.
    Hashtable where keys will be names of variables and values will be, well values :)

    Example:
    [hashtable]$Argument = @{
        name = "John"
        cities = "Boston", "Prague"
        hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }}
    }

    Will in beginning of the scriptBlock define variables:
    $name = 'John'
    $cities = 'Boston', 'Prague'
    $hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }

    ! ONLY STRING, ARRAY and HASHTABLE variables are supported !

    .PARAMETER runAs
    Let you change if scriptBlock should be running under SYSTEM, LOCALSERVICE or NETWORKSERVICE account.

    Default is SYSTEM.

    .EXAMPLE
    Invoke-AsSystem {New-Item $env:TEMP\abc}

    On local computer will call given scriptblock under SYSTEM account.

    .EXAMPLE
    Invoke-AsSystem {New-Item "$env:TEMP\$name"} -computerName PC-01 -ReturnTranscript -Argument @{name = 'someFolder'} -Verbose

    On computer PC-01 will call given scriptblock under SYSTEM account i.e. will create folder 'someFolder' in C:\Windows\Temp.
    Transcript will be outputted in console too.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock] $scriptBlock,

        [string] $computerName,

        [switch] $returnTranscript,

        [hashtable] $argument,

        [ValidateSet('SYSTEM', 'NETWORKSERVICE', 'LOCALSERVICE')]
        [string] $runAs = "SYSTEM",

        [switch] $CacheToDisk
    )

    (Get-Variable runAs).Attributes.Clear()
    $runAs = "NT Authority\$runAs"

    #region prepare Invoke-Command parameters
    # export this function to remote session (so I am not dependant whether it exists there or not)
    $allFunctionDefs = "function Create-VariableTextDefinition { ${function:Create-VariableTextDefinition} }"

    $param = @{
        argumentList = $scriptBlock, $runAs, $CacheToDisk, $allFunctionDefs, $VerbosePreference, $ReturnTranscript, $Argument
    }

    if ($computerName -and $computerName -notmatch "localhost|$env:COMPUTERNAME") {
        $param.computerName = $computerName
    } else {
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "You don't have administrator rights"
        }
    }
    #endregion prepare Invoke-Command parameters

    Invoke-Command @param -ScriptBlock {
        param ($scriptBlock, $runAs, $CacheToDisk, $allFunctionDefs, $VerbosePreference, $ReturnTranscript, $Argument)

        foreach ($functionDef in $allFunctionDefs) {
            . ([ScriptBlock]::Create($functionDef))
        }

        $TranscriptPath = "$ENV:TEMP\Invoke-AsSYSTEM_$(Get-Random).log"

        if ($Argument -or $ReturnTranscript) {
            # define passed variables
            if ($Argument) {
                # convert hash to variables text definition
                $VariableTextDef = Create-VariableTextDefinition $Argument
            }

            if ($ReturnTranscript) {
                # modify scriptBlock to contain creation of transcript
                $TranscriptStart = "Start-Transcript $TranscriptPath"
                $TranscriptEnd = 'Stop-Transcript'
            }

            $ScriptBlockContent = ($TranscriptStart + "`n`n" + $VariableTextDef + "`n`n" + $ScriptBlock.ToString() + "`n`n" + $TranscriptStop)
            Write-Verbose "####### SCRIPTBLOCK TO RUN"
            Write-Verbose $ScriptBlockContent
            Write-Verbose "#######"
            $scriptBlock = [Scriptblock]::Create($ScriptBlockContent)
        }

        if ($CacheToDisk) {
            $ScriptGuid = New-Guid
            $null = New-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Value $ScriptBlock -Force
            $pwshcommand = "-ExecutionPolicy Bypass -Window Hidden -noprofile -file `"$($ENV:TEMP)\$($ScriptGuid).ps1`""
        } else {
            $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
            $pwshcommand = "-ExecutionPolicy Bypass -Window Hidden -noprofile -EncodedCommand $($encodedcommand)"
        }

        $OSLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion
        if ($OSLevel -lt 6.2) { $MaxLength = 8190 } else { $MaxLength = 32767 }
        if ($encodedcommand.length -gt $MaxLength -and $CacheToDisk -eq $false) {
            throw "The encoded script is longer than the command line parameter limit. Please execute the script with the -CacheToDisk option."
        }

        try {
            #region create&run sched. task
            $A = New-ScheduledTaskAction -Execute "$($ENV:windir)\system32\WindowsPowerShell\v1.0\powershell.exe" -Argument $pwshcommand
            if ($runAs -match "\$") {
                # pod gMSA uctem
                $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType Password
            } else {
                # pod systemovym uctem
                $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType ServiceAccount
            }
            $S = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
            $taskName = "RunAsSystem_" + (Get-Random)
            try {
                $null = New-ScheduledTask -Action $A -Principal $P -Settings $S -ErrorAction Stop | Register-ScheduledTask -Force -TaskName $taskName -ErrorAction Stop
            } catch {
                if ($_ -match "No mapping between account names and security IDs was done") {
                    throw "Account $runAs doesn't exist or cannot be used on $env:COMPUTERNAME"
                } else {
                    throw "Unable to create helper scheduled task. Error was:`n$_"
                }
            }

            # run scheduled task
            Start-Sleep -Milliseconds 200
            Start-ScheduledTask $taskName

            # wait for sched. task to end
            Write-Verbose "waiting on sched. task end ..."
            $i = 0
            while (((Get-ScheduledTask $taskName -ErrorAction silentlyContinue).state -ne "Ready") -and $i -lt 1000) {
                ++$i
                Start-Sleep -Milliseconds 500
            }

            # get sched. task result code
            $result = (Get-ScheduledTaskInfo $taskName).LastTaskResult

            # read & delete transcript
            if ($ReturnTranscript) {
                # return just interesting part of transcript
                if (Test-Path $TranscriptPath) {
                    $transcriptContent = (Get-Content $TranscriptPath -Raw) -Split [regex]::escape('**********************')
                    # return command output
                    ($transcriptContent[2] -split "`n" | Select-Object -Skip 2 | Select-Object -SkipLast 3) -join "`n"

                    Remove-Item $TranscriptPath -Force
                } else {
                    Write-Warning "There is no transcript, command probably failed!"
                }
            }

            if ($CacheToDisk) { $null = Remove-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Force }

            try {
                Unregister-ScheduledTask $taskName -Confirm:$false -ErrorAction Stop
            } catch {
                throw "Unable to unregister sched. task $taskName. Please remove it manually"
            }

            if ($result -ne 0) {
                throw "Command wasn't successfully ended ($result)"
            }
            #endregion create&run sched. task
        } catch {
            throw $_.Exception
        }
    }
}

#Endregion Functions

#Region Main

Write-Host "`n`n"

#Verify admin priviliges
Test-IsAdmin

# Confirm if there is informaion of AzureAD that joined device to Azure AD Domain.
$usrJoinedDevice = Confirm-WhoJoinedDevice

# Find if currently logged on user has Azure AD Identity.
$usrAAD = Confirm-AADuser

# Find if there is a connected Azure AD Account (Work or school acccount?) registered on the device.
$usrWS = Read-SettingsDat

# Get info of Intune Enrolled user
#$usrEnrolled = Confirm-EnrolledUsr   # Might be worth it tryinf to get this user at the end for Enrollment.


if ($usrJoinedDevice.exist) {
    Write-Host "Device joined to Azure AD by: ""$($usrJoinedDevice.accountname)"""
}
else {
    Write-Host "No Azure AD account found for device join."
}


if ($usrAAD.exist) {
    Write-Host "Found Azure AD identity for Logged user: ""$($usrAAD.username)""."
}
else {
    Write-Host "No Azure AD identity found for logged on user."
}


if ($usrWS.exist) {
    Write-Host "Found Work or School (Azure AD) Account registered on device: ""$($usrWS.Upn)""."
}
else {
    Write-Host "No Work or School account found on device."
}


# Verify if device is AzureAD joined
#       -And ($usrAAD.exist) -And ($usrJoinedDevice.exist)
if ((Test-AzureAdJoin) -and (!(Test-IntuneEnrollment)) -and (($usrAAD.exist) -or ($usrWS.exist))) {

    Write-Host "Device is Azure AD Join, has Azure AD account and does not have Intune service installed"
    Write-Warning  "Executing Device Enrollment"

    #Write MDM enrollment URLs directly to registry
    $key = 'SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\*'
    $keyinfo = Get-Item "HKLM:\$key"
    $url = $keyinfo.name
    $url = $url.Split("\")[-1]
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\$url"
    $mdmUrl = "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc"
    $mdmTocUrl = "https://portal.manage.microsoft.com/TermsofUse.aspx"
    $mdmCUrl = "https://portal.manage.microsoft.com/?portalAction=Compliance"


    Write-Host "Writing MDM enrollment URLs directly to registry `n"
    New-ItemProperty -LiteralPath $path -Name 'MdmEnrollmentUrl' -Value $mdmUrl -PropertyType String -Force -ErrorAction SilentlyContinue | out-null
    New-ItemProperty -LiteralPath $path  -Name 'MdmTermsOfUseUrl' -Value $mdmTocUrl -PropertyType String -Force -ErrorAction SilentlyContinue | out-null
    New-ItemProperty -LiteralPath $path -Name 'MdmComplianceUrl' -Value $mdmCUrl -PropertyType String -Force -ErrorAction SilentlyContinue | out-null

    #Run Device Enrollment from System context
    $Script = "$env:SystemRoot\system32\deviceenroller.exe /c /AutoEnrollMDM"
#    $Script = "$env:SystemRoot\system32\ipconfig.exe /all" # This is for testing SYSTEM context
    $ScriptBlock = [scriptblock]::Create($Script)

    Write-Host "Executing $Script as SYSTEM..."
    
    Invoke-AsSystem $ScriptBlock -ReturnTranscript

    Write-Host "Successfully invoked Intune Enrollment"

}
else {
    Write-Host "Device already enrolled to Intune"
}



Write-Host "`n`n"

#Endregion Main

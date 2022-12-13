<#
.SYNOPSIS
    Silently enroll a Windows device to Microsoft Intune.

.DESCRIPTION
    Script to help automatically enroll existing Windows devices (Hybrid or Azure AD joined) into Intune.

    Verifies if device is Azure AD join, that has an Azure AD from same Tenant and that Intune services do not exist.
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
        Write-Host "Adminitrator rights have been confirmed"
    
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


Function CheckForBusinessOrSchoolAccount {
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
    $subKey = Get-Item "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo"

        # Look for the user in all subkeys, pick the one that corresponds to the device Tenant
    $guids = $subKey.GetSubKeyNames()
    foreach($guid in $guids) {

        $guidSubKey = $subKey.OpenSubKey($guid)
        $tenantId = $guidSubKey.GetValue("TenantId")
        
        if ($tenantId -eq $dsTenantId) {

            $userEmail = $guidSubKey.GetValue("UserEmail")
            $fReturn.exist = $true
            $fReturn.accountname = $userEmail

            #If user found stop the for loop, no need for anything else.          
            break
        }

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
            while (((Get-ScheduledTask $taskName -ErrorAction silentlyContinue).state -ne "Ready") -and $i -lt 500) {
                ++$i
                Start-Sleep -Milliseconds 200
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

#Verify admin priviliges
Test-IsAdmin

#Confirm if there is an AzureAD account configured in device
$AzAccount = CheckForBusinessOrSchoolAccount
if ($AzAccount.exist) {
    Write-Host "Found an existing account with the following Mail-Address: ""$($AzAccount.accountname)"""
}
else {
    Write-Host "No AzureAD Business/School-Account found on device"
}

#Verify if device is AzureAD joined
if ((Test-AzureAdJoin) -And (!(Test-IntuneEnrollment)) -And ($AzAccount.exist)) {

    Write-Host "Device is Azure AD Join, has Azure AD account and does not have Intune service installed"
    Write-Warning  "Executing Device Enrollment"

    #Write MDM enrollment URLs directly to registry
    $key = 'SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\*'
    $keyinfo = Get-Item "HKLM:\$key"
    $url = $keyinfo.name
    $url = $url.Split("\")[-1]
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\$url"

    Write-Host "Writing MDM enrollment URLs directly to registry `n"
    New-ItemProperty -LiteralPath $path -Name 'MdmEnrollmentUrl' -Value 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc' -PropertyType String -Force -ErrorAction SilentlyContinue | out-null
    New-ItemProperty -LiteralPath $path  -Name 'MdmTermsOfUseUrl' -Value 'https://portal.manage.microsoft.com/TermsofUse.aspx' -PropertyType String -Force -ErrorAction SilentlyContinue | out-null
    New-ItemProperty -LiteralPath $path -Name 'MdmComplianceUrl' -Value 'https://portal.manage.microsoft.com/?portalAction=Compliance' -PropertyType String -Force -ErrorAction SilentlyContinue | out-null

    #Run Device Enrollment from System context
    $Script = "$env:SystemRoot\system32\deviceenroller.exe /c /AutoEnrollMDM"
#    $Script = "$env:SystemRoot\system32\ipconfig.exe /all" #This is for testing
    $ScriptBlock = [scriptblock]::Create($Script)

    Write-Host "Executing $Script as SYSTEM..."
    
    Invoke-AsSystem $ScriptBlock -ReturnTranscript

    Write-Host "Successfully invoked Intune Enrollment"

}
else {
    Write-Host "Device already enrolled to Intune"
}

#Endregion Main

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  # Relaunch as an elevated process:
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}
# Now running elevated so launch the script:
#& "c:\run.ps1"
<#----------------------------------------------------------------
#__      __     _____  _____          ____  _      ______  _____ #
#\ \    / /\   |  __ \|_   _|   /\   |  _ \| |    |  ____|/ ____|#
# \ \  / /  \  | |__) | | |    /  \  | |_) | |    | |__  | (___  #
#  \ \/ / /\ \ |  _  /  | |   / /\ \ |  _ <| |    |  __|  \___ \ #
#   \  / ____ \| | \ \ _| |_ / ____ \| |_) | |____| |____ ____) |#
#    \/_/    \_\_|  \_\_____/_/    \_\____/|______|______|_____/ #
<#----------------------------------------------------------------------------#>
$sysmonDir = "C:\Windows\secops"
$sysmonPath = "C:\WINDOWS\Sysmon64.exe"
$sysmonConfigPath = "C:\WINDOWS\secops\sysmonConfig.xml"
$sysmonurl = "http://live.sysinternals.com/Sysmon64.exe"
$sysmonconfigurl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-ExecutionPolicy Bypass
#Sysmon folder
If(!(test-path $sysmonDir)) {
    New-Item -ItemType Directory -Force -Path $sysmonDir
  } Else {
    Write-Host "Sysmon directory exists."
  }
##---------------------------------------#
#  _____                                 #
# / ____|                                #
#| (___  _   _ ___ _ __ ___   ___  _ __  #
# \___ \| | | / __| '_ ` _ \ / _ \| '_ \ #
# ____) | |_| \__ \ | | | | | (_) | | | |#
#|_____/ \__, |___/_| |_| |_|\___/|_| |_|#
#         __/ |                          #
#        |___/                           #
##---------------------------------------#
(New-Object System.Net.WebClient).DownloadFile("$sysmonconfigurl", "$sysmonConfigPath")
(New-Object System.Net.WebClient).DownloadFile("$sysmonurl", $sysmonPath)
cmd.exe /C "C:\WINDOWS\Sysmon64.exe" -accepteula -i "C:\WINDOWS\secops\sysmonConfig.xml" 2> $null
#----------------------------------------------------------------------------------------------------#
# _____                       _____ _          _      _        _                       _             #
#|  __ \                     / ____| |        | |    | |      | |                     (_)            #
#| |__) |____      _____ _ _| (___ | |__   ___| |    | |      | |     ___   __ _  __ _ _ _ __   __ _ #
#|  ___/ _ \ \ /\ / / _ \ '__\___ \| '_ \ / _ \ |    | |      | |    / _ \ / _` |/ _` | | '_ \ / _` |#
#| |  | (_) \ V  V /  __/ |  ____) | | | |  __/ |____| |____  | |___| (_) | (_| | (_| | | | | | (_| |#
#|_|   \___/ \_/\_/ \___|_| |_____/|_| |_|\___|______|______| |______\___/ \__, |\__, |_|_| |_|\__, |#
#                                                                           __/ | __/ |         __/ |#
#                                                                          |___/ |___/         |___/ #
#----------------------------------------------------------------------------------------------------#
#Disable old powershell version
#Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
#Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
# Setup some variables
$PSLoggingRegRoot       = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell'
$ModuleLoggingRoot      = (Join-Path $PSLoggingRegRoot 'ModuleLogging')
$ModulesToLog           = (Join-Path $ModuleLoggingRoot 'ModuleNames')
$ScriptBlockLoggingRoot = (Join-Path $PSLoggingRegRoot 'ScriptBlockLogging')
$TranscriptLoggingRoot  = (Join-Path $PSLoggingRegRoot 'Transcription')
#region Module logging
# Create the subkeys if they don't already exist
If ((Test-Path $ModuleLoggingRoot) -eq $false) {
    "[PSLOG] Create the ModuleLogging subdirectory"
    New-Item -Path $ModuleLoggingRoot -Force
    "[PSLOG] Create the ModuleNames subdirectory"
    New-Item -Path $ModulesToLog -Force
}
"[PSLOG] Create (-force) and set the EnableModuleLogging key"
Set-ItemProperty -Path $ModuleLoggingRoot -Name EnableModuleLogging -Value 1 -Force
"[PSLOG] Configure module logging to log all modules"
Set-ItemProperty -Path $ModulesToLog -Name '*' -Value '*' -Force
#endregion
#region Scriptblock logging
# Create the subkeys if they don't exist
if ((Test-Path $ScriptBlockLoggingRoot) -eq $false) {
    "[PSLOG] Create the ScriptBlockLogging subdirectory"
    New-Item -Path $ScriptBlockLoggingRoot -Force
}
# Create (-force) and set the EnableScriptBlockLogging key
Set-ItemProperty -Path $ScriptBlockLoggingRoot -Name EnableScriptBlockLogging -Value 1 -Force
#endregion
#region Transcript logging
if (-not(Test-Path $TranscriptLoggingRoot)) {
    "[PSLOG] Create the Transcription subdirectory"
    New-Item -Path $TranscriptLoggingRoot -Force
}
"[PSLOG] Create (-force) and set transcription settings"
Set-ItemProperty -Path $TranscriptLoggingRoot -Name EnableTranscripting -Value 1 -Force
Set-ItemProperty -Path $TranscriptLoggingRoot -Name EnableInvocationHeader -Value 1
#Set-ItemProperty -Path $TranscriptLoggingRoot -Name OutputDirectory -Value 'c:\Windows\secops\ps_transcripts_log'
#endregion
<#----------------------------------------------------------------------------------#
#  _____               _ _      _              _                       _             #
# / ____|             | | |    (_)            | |                     (_)            #
#| |     _ __ ___   __| | |     _ _ __   ___  | |     ___   __ _  __ _ _ _ __   __ _ #
#| |    | '_ ` _ \ / _` | |    | | '_ \ / _ \ | |    / _ \ / _` |/ _` | | '_ \ / _` |#
#| |____| | | | | | (_| | |____| | | | |  __/ | |___| (_) | (_| | (_| | | | | | (_| |#
# \_____|_| |_| |_|\__,_|______|_|_| |_|\___| |______\___/ \__, |\__, |_|_| |_|\__, |#
#                                                           __/ | __/ |         __/ |#
#                                                          |___/ |___/         |___/ #
<#----------------------------------------------------------------------------------#>
auditpol.exe /set /subcategory:"Process Termination,Process Creation" /success:Enable /failure:Disable
$cmdlogkey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
Remove-ItemProperty -Path $cmdlogkey -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
"[CMDLog] force enable..."
New-ItemProperty -Path $cmdlogkey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWORD | Out-Null
if ($?){"[CMDLog] Command-line arguments will be logged."} else { "[CMDLog] ERROR!`n" + $Error[0] }
<#----------------------------------------------------------------------------
# ______      _                 _          _                     _ _ _   #
#|  ____|    | |               | |        | |     /\            | (_) |  #
#| |__  __  _| |_ ___ _ __   __| | ___  __| |    /  \  _   _  __| |_| |_ #
#|  __| \ \/ / __/ _ \ '_ \ / _` |/ _ \/ _` |   / /\ \| | | |/ _` | | __|#
#| |____ >  <| ||  __/ | | | (_| |  __/ (_| |  / ____ \ |_| | (_| | | |_ #
#|______/_/\_\\__\___|_| |_|\__,_|\___|\__,_| /_/    \_\__,_|\__,_|_|\__|#
<#----------------------------------------------------------------------------#>
#https://github.com/dumpvn/SANS-SEC505/blob/c5e42e283c36429a3649345abd330b09b4d116b3/Day6-Servers/Set-AdvancedAuditPolicy.ps1
#Param ( [Switch] $DisableAllAuditPolicies, [Switch] $ShowCurrentPolicies, [Switch] $ShowCommands ) 
# Add "Success" and/or "Failure" after the colon for each audit subcategory,
# or leave blank to disable all auditing for that subcategory.  Do not delete
# or add any lines, there must be exactly 59 policies in the list.  Space
# characters do not matter, except inside the name of the policy on the left.
# Do not add comment markers (#) anywhere inside the $AuditPolicyList.
#
# To see your current audit policies, run this command:
#     auditpol.exe /get /category:*
$AuditPolicyList = @'
Credential Validation                  : Success Failure
Kerberos Authentication Service        : Success Failure
Kerberos Service Ticket Operations     : Success Failure
Other Account Logon Events             : Success Failure
Application Group Management           : Success Failure
Computer Account Management            : Success Failure
Distribution Group Management          : Success Failure
Other Account Management Events        : Success Failure
Security Group Management              : Success Failure
User Account Management                : Success Failure
DPAPI Activity                         : Success Failure
Plug and Play Events                   : Success Failure
Process Creation                       : Success Failure
Process Termination                    : Success Failure
RPC Events                             : Success Failure
Token Right Adjusted                   : Success Failure
Detailed Directory Service Replication : Success Failure
Directory Service Access               : Success Failure
Directory Service Changes              : Success Failure
Directory Service Replication          : Success Failure
Account Lockout                        : Success Failure
Group Membership                       : Success Failure
IPSec Extended Mode                    : 
IPSec Main Mode                        : 
IPSec Quick Mode                       : 
Logoff                                 : Success Failure
Logon                                  : Success Failure
Network Policy Server                  : Success Failure
Other Logon/Logoff Events              : Success Failure
Special Logon                          : Success Failure
User / Device Claims                   : Success Failure
Application Generated                  : Success Failure
Central Access Policy Staging          : Success Failure
Certification Services                 : Success Failure
Detailed File Share                    : Success Failure
File Share                             : Success Failure
File System                            : Success Failure
Filtering Platform Connection          : Success Failure
Filtering Platform Packet Drop         : Success Failure
Handle Manipulation                    : Success Failure
Kernel Object                          : Success Failure
Other Object Access Events             : Success Failure
Registry                               : Success Failure
Removable Storage                      : Success Failure
SAM                                    : Success Failure
Policy Change                          : Success Failure
Authentication Policy Change           : Success Failure
Authorization Policy Change            : Success Failure
Filtering Platform Policy Change       : Success Failure
MPSSVC Rule-Level Policy Change        : Success Failure
Other Policy Change Events             : Success Failure
Non Sensitive Privilege Use            : Success Failure
Other Privilege Use Events             : Success Failure
Sensitive Privilege Use                : Success Failure
IPSec Driver                           : Success Failure
Other System Events                    : Success Failure
Security State Change                  : Success Failure
Security System Extension              : Success Failure
System Integrity                       : Success Failure
'@
# Sanity check: Path to auditpol.exe:
$AuditPolExePath = Resolve-Path -Path "$env:WinDir\System32\auditpol.exe" | Select -ExpandProperty Path
if (-not $? -or $AuditPolExePath.Length -lt 8){ Write-Error -Message "Cannot Find AUDITPOL.EXE" ; Return } 
# Parse audit policy list into an array:
$AuditPolicyList = $AuditPolicyList -split "`n"
# Sanity check: must have 59 policies:
# Has the number of advanced audit policies changed from 59?
# auditpol.exe /get /category:* | Select-String -Pattern 'Success|Failure|No Auditing' | Measure-Object
if ($AuditPolicyList.Count -ne 59)
{ Write-Error -Message "Wrong Count of Audit Policies: Must Be 59" ; Return }
# Sanity check: every line has a colon: 
$AuditPolicyList | ForEach-Object { if ($_ -notlike '*:*'){ Write-Error -Message "Missing Colon: $_" ; Return } } 
# Apply audit policy array:
ForEach ($Policy in $AuditPolicyList)
{
    # $PolicyPart[0] is the name of the policy
    # $PolicyPart[1] is Success and/or Failure
    $PolicyPart = $Policy -split ':'
    # Neither Success nor Failure? Continue to next:
    if ($PolicyPart[1].Trim().Length -eq 0){ Continue }  
    # Construct arguments to auditpol.exe:
    $EndingArgs = ''
    if ($PolicyPart[1] -like '*Success*'){ $EndingArgs =  '/success:enable ' }
    if ($PolicyPart[1] -like '*Failure*'){ $EndingArgs += '/failure:enable'  } 
    $EndingArgs = '/set /subcategory:"' + $PolicyPart[0].Trim() + '" ' + $EndingArgs
    # Run auditpol.exe with the arguments:
    if ($ShowCommands){ "$AuditPolExePath $EndingArgs" } 
    Start-Process -FilePath $AuditPolExePath -ArgumentList $EndingArgs -NoNewWindow
}
Start-Sleep -Seconds 5
do { $myInput = (Read-Host 'BACKUP LOGS? (y/n)').ToLower() } while ($myInput -notin @('y','n'))
if ($myInput -eq 'y') {
    # Provide the path with ending "\" to store the log file extraction.
    $destinationpath = "C:\WindowsEventLogs\"
    New-Item -ItemType Directory -Force -Path $destinationpath
    $destinationpathzip = "C:\WindowsEventLogs.zip"
    Write-Host -Fore Green "Copying Event log Files...."
    wevtutil epl Security $destinationpath\Security.evtx
    wevtutil epl System $destinationpath\System.evtx
    wevtutil epl Application $destinationpath\Application.evtx
    wevtutil epl Microsoft-Windows-TaskScheduler/Operational $destinationpath\TaskScheduler.evtx
    wevtutil epl Microsoft-Windows-PowerShell/Operational $destinationpath\Powershell.evtx
    wevtutil epl 'Microsoft-Windows-User Profile Service/Operational' $destinationpath\UserProfileService.evtx
    wevtutil epl Microsoft-Windows-Sysmon/Operational $destinationpath\sysmon.evtx
    Write-Host -Fore Green "Done"
    Compress-Archive -Path $destinationpath -DestinationPath $destinationpathzip
} else {
exit
}

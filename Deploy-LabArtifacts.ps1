<#
Deploy-LabArtifacts.ps1
Instructor PowerShell script for Windows 10 lab VMs.
This script deploys simulated attack artifacts for student analysis.
No cleanup or reset logic included.
Run as Administrator.

Timeline Logic:
- All events are sequenced from the TimeBase parameter (default: 1 day ago)
- Events follow a logical attack progression with realistic time gaps
- Total attack timeline spans approximately 12-41 minutes
- Timestamps are designed to appear as a coordinated attack sequence
#>

param(
    [datetime]$TimeBase = (Get-Date).AddDays(-1),                   # base time for artifacts/timestamps (adjust per scenario)
    [string]$ImpersonateUser = "Bruce.Wayne",                       # fake remote user who appears to perform actions
    [string]$TargetUser = "John.Hacksmith",                         # fake target user for actions
    [string]$ruleName = "Definitely-Not-Malicious",                 # name of firewall rule to create
    [string]$exePath = "$env:TEMP\Totally-Not-Malware.exe",         # path for placeholder EXE to create and execute
    [int]$FirewallPort = (Get-Random -Minimum 2000 -Maximum 9999)   # randomize firewall port
)

$ErrorActionPreference = 'Stop'

function New-RandomSid { # Generate random SID for users/groups
    param([string]$Prefix = "S-1-5-21")
    $part1 = Get-Random -Minimum 1000000000 -Maximum 4000000000
    $part2 = Get-Random -Minimum 1000000000 -Maximum 4000000000  
    $part3 = Get-Random -Minimum 1000000000 -Maximum 4000000000
    $rid = Get-Random -Minimum 1000 -Maximum 9999
    return "$Prefix-$part1-$part2-$part3-$rid"
}

function New-RandomLogonId { # Generate random logon ID in hex format
    $hex = Get-Random -Minimum 0x100000 -Maximum 0xFFFFFF
    return "0x$($hex.ToString('X'))"
}

function New-RandomIP { # Get the current machine's IP address and subnet
    $networkAdapter = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
        $_.IPAddress -notmatch '^(127\.|169\.254\.|0\.)' -and 
        $_.PrefixLength -ne 32 -and
        $_.InterfaceAlias -notmatch 'Loopback'
    } | Select-Object -First 1
    
    if ($networkAdapter) {
        $currentIP = $networkAdapter.IPAddress
        $prefixLength = $networkAdapter.PrefixLength
        
        # Parse current IP
        $octets = $currentIP.Split('.')
        $octet1 = [int]$octets[0]
        $octet2 = [int]$octets[1] 
        $octet3 = [int]$octets[2]
        
        # Generate random IP in same subnet based on prefix length
        if ($prefixLength -ge 24) {
            # /24 or smaller - randomize last octet only
            $octet4 = Get-Random -Minimum 1 -Maximum 254
            return "$octet1.$octet2.$octet3.$octet4"
        } elseif ($prefixLength -ge 16) {
            # /16 to /23 - randomize last two octets  
            $octet3 = Get-Random -Minimum 1 -Maximum 254
            $octet4 = Get-Random -Minimum 1 -Maximum 254
            return "$octet1.$octet2.$octet3.$octet4"
        } else {
            # /8 to /15 - randomize last three octets
            $octet2 = Get-Random -Minimum 1 -Maximum 254
            $octet3 = Get-Random -Minimum 1 -Maximum 254  
            $octet4 = Get-Random -Minimum 1 -Maximum 254
            return "$octet1.$octet2.$octet3.$octet4"
        }
    } else {
        # Fallback to common private ranges if detection fails
        $privateRanges = @(
            @{o1=192; o2=168},
            @{o1=10; o2=(Get-Random -Minimum 0 -Maximum 255)},
            @{o1=172; o2=(Get-Random -Minimum 16 -Maximum 31)}
        )
        $range = $privateRanges | Get-Random
        $octet3 = Get-Random -Minimum 1 -Maximum 254
        $octet4 = Get-Random -Minimum 1 -Maximum 254
        return "$($range.o1).$($range.o2).$octet3.$octet4"
    }
}

function New-RandomGuid { # Generate random GUID for logon sessions (sometimes null, sometimes actual GUID)
    $nullChance = Get-Random -Minimum 1 -Maximum 5
    if ($nullChance -eq 1) {
        return "{00000000-0000-0000-0000-000000000000}"
    } else {
        return "{$([System.Guid]::NewGuid().ToString())}"
    }
}

function New-RandomProcessId { # Generate realistic process ID in hex format
    $processId = Get-Random -Minimum 100 -Maximum 9999
    return "0x$($processId.ToString('X'))"
}

function Write-SecurityEvent { # Main function to write Security events with realistic metadata
    param(
        [int]$EventID,
        [string]$Message,
        [datetime]$EventTime = (Get-Date)
    )
    
    # Generate random metadata for realistic Security Event variation
    $randomVersion = Get-Random -Minimum 0 -Maximum 3
    $randomTask = switch ($EventID) {
        4720 { 13824 }  # User Account Management
        4732 { 13824 }  # User Account Management  
        4656 { 12544 }  # File System
        4688 { 13312 }  # Process Creation
        default { Get-Random -Minimum 12544 -Maximum 13824 }
    }
    $randomOpcode = Get-Random -Minimum 0 -Maximum 2
    $randomKeywords = "0x802000000000$(Get-Random -Minimum 0000 -Maximum 9999)"
    $randomEventRecordID = Get-Random -Minimum 100000 -Maximum 999999
    $randomProcessID = Get-Random -Minimum 500 -Maximum 9999
    $randomThreadID = Get-Random -Minimum 1000 -Maximum 9999
    
    # Create XML for Security event injection
    $eventXml = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>$EventID</EventID>
    <Version>$randomVersion</Version>
    <Level>0</Level>
    <Task>$randomTask</Task>
    <Opcode>$randomOpcode</Opcode>
    <Keywords>$randomKeywords</Keywords>
    <TimeCreated SystemTime="$($EventTime.ToUniversalTime().ToString('o'))" />
    <EventRecordID>$randomEventRecordID</EventRecordID>
    <Correlation />
    <Execution ProcessID="$randomProcessID" ThreadID="$randomThreadID" />
    <Channel>Security</Channel>
    <Computer>$env:COMPUTERNAME</Computer>
    <Security />
  </System>
  <EventData>
    $Message
  </EventData>
</Event>
"@
    
    # Write to temporary file and inject using wevtutil
    $tempFile = "$env:TEMP\SecurityEvent_$EventID.xml"
    try {
        $eventXml | Out-File -FilePath $tempFile -Encoding UTF8
        $result = & wevtutil.exe im $tempFile 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully injected Security Event $EventID" -ForegroundColor Green
        } else {
            Write-Warning "Failed to inject Security Event: $result"
            # Fallback to Application log
            Write-AppEvent -Source "Security-Simulation" -EventID $EventID -Message $Message.Replace('<Data Name="', '').Replace('">', ': ').Replace('</Data>', "`n")
        }
        
        Remove-Item $tempFile -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Security event injection failed: $($_.Exception.Message)"
        # Fallback to Application log with clear marking
        $fallbackMsg = "SECURITY EVENT SIMULATION (EventID $EventID):`n$($Message.Replace('<Data Name="', '').Replace('">', ': ').Replace('</Data>', "`n"))"
        Write-AppEvent -Source "Security-Simulation" -EventID $EventID -Message $fallbackMsg
    }
}

function Write-AppEvent { # Used for fallback logging to Application log, for when Security log injection fails
    param($Source,$EventID,$Message)
    
    # Ensure the custom event source exists in the Application log
    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
        try {
            New-EventLog -LogName Application -Source $Source
            Write-Host "Created custom event source: $Source" -ForegroundColor Green
            # Wait a moment for the source to be fully registered
            Start-Sleep -Seconds 1
        } catch {
            Write-Warning "Failed to create event source $Source : $($_.Exception.Message)"
            return
        }
    }
    
    # Use Write-EventLog instead of eventcreate for better reliability
    try {
        Write-EventLog -LogName Application -Source $Source -EventId $EventID -EntryType Information -Message $Message
        Write-Host "Successfully created event ID $EventID from source '$Source'" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to write event: $($_.Exception.Message)"
        # Fallback to eventcreate if Write-EventLog fails
        try {
            Write-Host "Trying alternative method with eventcreate..." -ForegroundColor Yellow
            $result = cmd.exe /c "eventcreate /ID $EventID /L APPLICATION /T INFORMATION /SO `"$Source`" /D `"$Message`"" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Successfully created event ID $EventID using eventcreate" -ForegroundColor Green
            } else {
                Write-Warning "Both methods failed. EventCreate error: $result"
            }
        } catch {
            Write-Warning "Both Write-EventLog and eventcreate failed: $($_.Exception.Message)"
        }
    }
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Run as Administrator. Exiting."
    return
}


# Ensure running as Administrator before calling auditpol
Write-Host "Enabling audit policies: Account Management, Policy Change, Detailed Tracking (process creation)..." -ForegroundColor Yellow

# Enable auditing for account management (user/group changes), policy changes (firewall/MPSSVC), and detailed tracking (process creation)
# These take effect immediately; no reboot required.
& auditpol.exe /set /category:"Account Management" /success:enable /failure:enable
& auditpol.exe /set /category:"Policy Change" /success:enable /failure:enable
& auditpol.exe /set /category:"Detailed Tracking" /success:enable /failure:enable

Write-Host "Audit policies configured. You can now rely on native Security/MPSSVC logs for user creation, group changes, firewall rule changes and process creation." -ForegroundColor Green
Write-Host "Generating simulated attack artifacts..." -ForegroundColor Yellow

# Create a believable timeline starting from the TimeBase parameter
$currentTime = $TimeBase
$src = "SimLabGenerator"

# 1) Simulated RDP log — do NOT perform an RDP connection, only log a believable Application event
$rdpUser    = "$ImpersonateUser"
$sourceHost = "SERVER$(Get-Random -Minimum 01 -Maximum 99)"
$logonID    = New-RandomLogonId
$accountSid = New-RandomSid
$srcPort    = "3389"
$sourceIP   = New-RandomIP

# Generate proper Security Event 4624 (An account was successfully logged on) for RDP
# This is the initial attack vector - RDP logon happens first
$rdpLogonTime = $currentTime.AddMinutes($(Get-Random -Minimum 1 -Maximum 5))
$rdpGuid = New-RandomGuid
$rdpProcessId = New-RandomProcessId
$rdpProcessName = if ((Get-Random -Minimum 1 -Maximum 3) -eq 1) { "C:\Windows\System32\winlogon.exe" } else { "-" }

$event4624Data = @"
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="SubjectUserName">SYSTEM</Data>
<Data Name="SubjectDomainName">NT AUTHORITY</Data>
<Data Name="SubjectLogonId">0x3E7</Data>
<Data Name="TargetUserSid">$accountSid</Data>
<Data Name="TargetUserName">$rdpUser</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="TargetLogonId">$logonID</Data>
<Data Name="LogonType">10</Data>
<Data Name="LogonProcessName">User32</Data>
<Data Name="AuthenticationPackageName">Negotiate</Data>
<Data Name="WorkstationName">$sourceHost</Data>
<Data Name="LogonGuid">$rdpGuid</Data>
<Data Name="TransmittedServices">-</Data>
<Data Name="LmPackageName">-</Data>
<Data Name="KeyLength">0</Data>
<Data Name="ProcessId">$rdpProcessId</Data>
<Data Name="ProcessName">$rdpProcessName</Data>
<Data Name="IpAddress">$sourceIP</Data>
<Data Name="IpPort">$srcPort</Data>
<Data Name="ImpersonationLevel">%%1833</Data>
<Data Name="RestrictedAdminMode">-</Data>
<Data Name="TargetOutboundUserName">-</Data>
<Data Name="TargetOutboundDomainName">-</Data>
<Data Name="VirtualAccount">%%1843</Data>
<Data Name="TargetLinkedLogonId">0x0</Data>
<Data Name="ElevatedToken">%%1842</Data>
"@

Write-SecurityEvent -EventID 4624 -Message $event4624Data -EventTime $rdpLogonTime

# 2) Create local user $TargetUser with Security events showing $ImpersonateUser as creator
$user = "$TargetUser"
$pass = "ChangeMe!2025"
$impersonateLogonId = New-RandomLogonId
$impersonateSid = New-RandomSid  # Random SID for impersonation user
$targetUserSid = New-RandomSid -Prefix "S-1-5-21-$([Math]::Abs($env:COMPUTERNAME.GetHashCode()))"  # Generate consistent SID for target user

if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
    # Generate Security Event 4720 (User Account Created) showing impersonation user as creator
    # User creation happens after RDP logon (5-15 minutes after initial logon)
    $userCreateTime = $rdpLogonTime.AddMinutes($(Get-Random -Minimum 5 -Maximum 15))
    
    # Actually create the user
    $secure = ConvertTo-SecureString $pass -AsPlainText -Force
    New-LocalUser -Name $user -Password $secure -FullName $TargetUser -Description "Simulated lab account" -PasswordNeverExpires:$true
    
    # create a simple marker file in profile
    $profileDir = "C:\Users\$user"
    if (-not (Test-Path $profileDir)) { New-Item -Path $profileDir -ItemType Directory -Force | Out-Null }
    "Simulated account profile for $user" | Out-File -FilePath (Join-Path $profileDir "README.txt") -Encoding utf8
    # Set file creation time to match user creation timeline
    (Get-Item (Join-Path $profileDir "README.txt")).CreationTime = $userCreateTime
    $event4720Data = @"
<Data Name="TargetUserName">$user</Data>
<Data Name="TargetDomainName">$env:COMPUTERNAME</Data>
<Data Name="TargetSid">$targetUserSid</Data>
<Data Name="SubjectUserSid">$impersonateSid</Data>
<Data Name="SubjectUserName">$ImpersonateUser</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">$impersonateLogonId</Data>
<Data Name="PrivilegeList">-</Data>
<Data Name="SamAccountName">$user</Data>
<Data Name="DisplayName">$TargetUser</Data>
<Data Name="UserPrincipalName">-</Data>
<Data Name="HomeDirectory">-</Data>
<Data Name="HomePath">-</Data>
<Data Name="ScriptPath">-</Data>
<Data Name="ProfilePath">-</Data>
<Data Name="UserWorkstations">-</Data>
<Data Name="PasswordLastSet">$($userCreateTime.ToString('M/d/yyyy h:mm:ss tt'))</Data>
<Data Name="AccountExpires">Never</Data>
<Data Name="PrimaryGroupId">513</Data>
<Data Name="AllowedToDelegateTo">-</Data>
<Data Name="OldUacValue">0x0</Data>
<Data Name="NewUacValue">0x15</Data>
<Data Name="UserAccountControl">Account Disabled, 'Password Not Required' - Enabled, 'Normal Account' - Enabled</Data>
<Data Name="UserParameters">-</Data>
<Data Name="SidHistory">-</Data>
<Data Name="LogonHours">All</Data>
"@
    
    Write-SecurityEvent -EventID 4720 -Message $event4720Data -EventTime $userCreateTime
    write-host "Created local user $user with password $pass (Security Event 4720 logged as $ImpersonateUser)" -ForegroundColor Green
} else {
    write-host "User $user already exists, skipping creation" -ForegroundColor DarkYellow
}

# 3) Elevate $TargetUser to Administrators with Security Event showing ImpersonateUser as performer
try {
    Add-LocalGroupMember -Group "Administrators" -Member $user -ErrorAction Stop
    
    # Generate Security Event 4732 (Member Added to Security Group) showing impersonation user as performer
    # Group elevation happens shortly after user creation (1-5 minutes later)
    $groupAddTime = $userCreateTime.AddMinutes($(Get-Random -Minimum 1 -Maximum 5))
    $event4732Data = @"
<Data Name="MemberName">-</Data>
<Data Name="MemberSid">$targetUserSid</Data>
<Data Name="TargetUserName">$user</Data>
<Data Name="TargetDomainName">$env:COMPUTERNAME</Data>
<Data Name="TargetSid">S-1-5-32-544</Data>
<Data Name="SubjectUserSid">$impersonateSid</Data>
<Data Name="SubjectUserName">$ImpersonateUser</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">$impersonateLogonId</Data>
<Data Name="PrivilegeList">-</Data>
"@
    
    Write-SecurityEvent -EventID 4732 -Message $event4732Data -EventTime $groupAddTime
    Write-Host "Added $user to local Administrators group (Security Event 4732 logged as $ImpersonateUser)" -ForegroundColor Green
} catch {
    write-host "User $user is already a member of Administrators group, skipping" -ForegroundColor DarkYellow
}

# Variables for target user's logon session (for subsequent actions)
$targetUserLogonId = New-RandomLogonId  # Different logon session for target user

# 4) Create firewall rule as target user using runas for authentic logging
# Firewall creation happens after gaining admin rights (2-10 minutes after group elevation)
$firewallCreateTime = $groupAddTime.AddMinutes($(Get-Random -Minimum 2 -Maximum 10))
try {
    # Primary method: Use runas to execute netsh as target user (generates authentic Windows Firewall logs)
    $netshCommand = "netsh advfirewall firewall add rule name=`"$ruleName`" dir=in action=allow protocol=TCP localport=$FirewallPort"
    
    Write-Host "Attempting to create firewall rule as $TargetUser using runas..." -ForegroundColor Cyan
    
    # Create a temporary batch file to execute the command
    $tempBatch = "$env:TEMP\firewall_$(Get-Random).bat"
    "@echo off`n$netshCommand" | Out-File -FilePath $tempBatch -Encoding ASCII
    
    try {
        # Execute as target user using runas with password
        $runasArgs = "/user:$TargetUser /savecred"
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = "runas.exe"
        $startInfo.Arguments = "$runasArgs `"$tempBatch`""
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        $process.Start()
        
        # Send password to stdin
        $process.StandardInput.WriteLine($pass)
        $process.StandardInput.Close()
        $process.WaitForExit(10000)  # 10 second timeout
        
        Remove-Item $tempBatch -ErrorAction SilentlyContinue
        
        if ($process.ExitCode -eq 0) {
            Write-Host "Successfully created firewall rule '$ruleName' as $TargetUser (authentic Windows Firewall logs generated)" -ForegroundColor Green
        } else {
            throw "Runas failed with exit code $($process.ExitCode)"
        }
        
    } catch {
        Write-Warning "Runas method failed: $($_.Exception.Message)"
        Write-Host "Falling back to direct netsh execution..." -ForegroundColor Yellow
        
        # Fallback 1: Direct netsh execution (will log current user)
        $result = cmd.exe /c $netshCommand 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            # Generate Application event to indicate target user performed action (since direct execution won't show target user)
            $firewallMsg = "Administrative Action Performed`nUser: $TargetUser`nAction: Firewall Rule Creation`nRule Name: $ruleName`nDirection: Inbound`nProtocol: TCP`nPort: $FirewallPort`nAction: Allow`nMethod: Fallback execution`nTimestamp: $(Get-Date)`nNote: Windows Firewall logs may show script runner instead of target user"
            Write-AppEvent -Source "AdminActivity" -EventID 1001 -Message $firewallMsg
            Write-Host "Created firewall rule '$ruleName' using netsh fallback (Application event indicates $TargetUser activity)" -ForegroundColor Yellow
        } else {
            # Fallback 2: PowerShell method
            Write-Warning "netsh fallback failed: $result"
            Write-Host "Using PowerShell New-NetFirewallRule as final fallback..." -ForegroundColor Yellow
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $FirewallPort -Action Allow -Profile Any -ErrorAction Stop | Out-Null
            
            # Generate Application event for final fallback
            $firewallMsg = "Administrative Action Performed`nUser: $TargetUser`nAction: Firewall Rule Creation`nRule Name: $ruleName`nDirection: Inbound`nProtocol: TCP`nPort: $FirewallPort`nAction: Allow`nMethod: PowerShell fallback`nTimestamp: $(Get-Date)`nNote: Windows logs may show script runner instead of target user"
            Write-AppEvent -Source "AdminActivity" -EventID 1001 -Message $firewallMsg
            Write-Host "Created firewall rule '$ruleName' using PowerShell fallback" -ForegroundColor Yellow
        }
    }
    
} catch {
    Write-Host "Firewall rule '$ruleName' already exists, skipping creation" -ForegroundColor DarkYellow
}

# 5) Create a harmless placeholder executable and "execute" a benign payload as target user
# Build and compile a tiny benign EXE that logs its execution and sleeps briefly
$code = @"
using System;
using System.IO;
using System.Threading;

public class Program {
    public static int Main(string[] args) {
        try {
            var log = Path.Combine(Path.GetTempPath(), "Totally-Not-Malware.log");
            File.AppendAllText(log, string.Format("Executed at {0}\r\n", DateTime.UtcNow.ToString("O")));
            Thread.Sleep(2000);
        } catch {}
        return 0;
    }
}
"@

try {
    # First, create the executable normally (this step needs to happen as current user)
    Add-Type -TypeDefinition $code -OutputAssembly $path -OutputType ConsoleApplication
    Write-Host "Successfully compiled placeholder EXE: $path" -ForegroundColor Green
    
    # File creation happens after firewall rule creation (3-8 minutes later)
    $fileCreateTime = $firewallCreateTime.AddMinutes($(Get-Random -Minimum 3 -Maximum 8))
    # Set file timestamp to match the timeline
    (Get-Item $path).CreationTime = $fileCreateTime
    
    # Generate proper Security Events for file access and process creation
    # These belong in Security log with correct Event IDs
    
    # Generate Security Event 4656 (File System Object Access) for file creation
    $fileCreateEventData = @"
<Data Name="SubjectUserSid">$targetUserSid</Data>
<Data Name="SubjectUserName">$TargetUser</Data>
<Data Name="SubjectDomainName">$env:COMPUTERNAME</Data>
<Data Name="SubjectLogonId">$targetUserLogonId</Data>
<Data Name="ObjectName">$path</Data>
<Data Name="ObjectType">File</Data>
<Data Name="HandleId">$(New-RandomProcessId)</Data>
<Data Name="TransactionId">$(New-RandomGuid)</Data>
<Data Name="AccessList">WriteData (or AddFile)</Data>
<Data Name="AccessReason">-</Data>
<Data Name="AccessMask">0x2</Data>
<Data Name="PrivilegeList">-</Data>
<Data Name="RestrictedSidCount">0</Data>
"@
    
    Write-SecurityEvent -EventID 4656 -Message $fileCreateEventData -EventTime $fileCreateTime
    
    # Execute the file and generate proper Security Event
    $processStart = Start-Process -FilePath $path -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
    
    if ($processStart) {
        # Generate Security Event 4688 (Process Creation) for execution  
        # Execution happens shortly after file creation (1-3 minutes later)
        $execTime = $fileCreateTime.AddMinutes($(Get-Random -Minimum 1 -Maximum 3))
        $processEventData = @"
<Data Name="SubjectUserSid">$targetUserSid</Data>
<Data Name="SubjectUserName">$TargetUser</Data>
<Data Name="SubjectDomainName">$env:COMPUTERNAME</Data>
<Data Name="SubjectLogonId">$targetUserLogonId</Data>
<Data Name="NewProcessId">0x$('{0:x}' -f $processStart.Id)</Data>
<Data Name="NewProcessName">$path</Data>
<Data Name="TokenElevationType">%%1938</Data>
<Data Name="ProcessId">0x$('{0:x}' -f $PID)</Data>
<Data Name="CommandLine">$path</Data>
<Data Name="TargetUserSid">$targetUserSid</Data>
<Data Name="TargetUserName">$TargetUser</Data>
<Data Name="TargetDomainName">$env:COMPUTERNAME</Data>
<Data Name="TargetLogonId">$targetUserLogonId</Data>
<Data Name="ParentProcessName">$($MyInvocation.MyCommand.Path)</Data>
<Data Name="MandatoryLabel">S-1-16-8192</Data>
"@
        
        Write-SecurityEvent -EventID 4688 -Message $processEventData -EventTime $execTime
        Write-Host "Successfully compiled and executed placeholder EXE (Security Events 4656/4688 generated for $TargetUser)" -ForegroundColor Green
    } else {
        Write-Warning "Failed to start process, but file creation Security Event still generated"
    }
} catch {
    Write-Warning "Failed to compile placeholder EXE: $($_.Exception.Message)"
    Write-Host "Falling back to benign PowerShell process..." -ForegroundColor Yellow
    
    # Fallback process execution with proper Security Event
    $fallbackProcess = Start-Process -FilePath $PSHome\pwsh.exe -ArgumentList '-NoProfile','-WindowStyle','Hidden','-Command','Start-Sleep -Seconds 2' -PassThru -ErrorAction SilentlyContinue
    
    if ($fallbackProcess) {
        # Fallback execution uses same timeline as main execution
        $fallbackTime = $fileCreateTime.AddMinutes($(Get-Random -Minimum 1 -Maximum 3))
        $fallbackEventData = @"
<Data Name="SubjectUserSid">$targetUserSid</Data>
<Data Name="SubjectUserName">$TargetUser</Data>
<Data Name="SubjectDomainName">$env:COMPUTERNAME</Data>
<Data Name="SubjectLogonId">$targetUserLogonId</Data>
<Data Name="NewProcessId">0x$('{0:x}' -f $fallbackProcess.Id)</Data>
<Data Name="NewProcessName">$PSHome\pwsh.exe</Data>
<Data Name="TokenElevationType">%%1938</Data>
<Data Name="ProcessId">0x$('{0:x}' -f $PID)</Data>
<Data Name="CommandLine">$PSHome\pwsh.exe -NoProfile -WindowStyle Hidden -Command Start-Sleep -Seconds 2</Data>
<Data Name="TargetUserSid">$targetUserSid</Data>
<Data Name="TargetUserName">$TargetUser</Data>
<Data Name="TargetDomainName">$env:COMPUTERNAME</Data>
<Data Name="TargetLogonId">$targetUserLogonId</Data>
<Data Name="ParentProcessName">$($MyInvocation.MyCommand.Path)</Data>
<Data Name="MandatoryLabel">S-1-16-8192</Data>
"@
        
        Write-SecurityEvent -EventID 4688 -Message $fallbackEventData -EventTime $fallbackTime
        Write-Host "Fallback process execution logged as $TargetUser (Security Event 4688)" -ForegroundColor Green
    }
}

Write-Host "Done. User created by $ImpersonateUser, then $TargetUser performed: admin elevation, firewall rule creation, exe compilation, and execution." -ForegroundColor Green

# Timeline Summary:
# $TimeBase (parameter default: 1 day ago)
# +1-5 minutes:     RDP logon by $ImpersonateUser
# +5-15 minutes:    User account creation ($TargetUser) 
# +1-5 minutes:     User added to Administrators group
# +2-10 minutes:    Firewall rule creation
# +3-8 minutes:     Malicious file creation
# +1-3 minutes:     File execution
# Total timeline span: Approximately 12-41 minutes of activity

Write-Host "`nTimeline created spanning approximately $([math]::Round(($fileCreateTime.AddMinutes(3) - $rdpLogonTime).TotalMinutes)) minutes of simulated attack activity" -ForegroundColor Cyan

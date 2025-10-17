<#
.SYNOPSIS
    Deploy-LabArtifacts.ps1 - Cybersecurity Training Lab Artifact Generator

.DESCRIPTION
    This PowerShell script creates realistic attack artifacts for cybersecurity training environments.
    It simulates a coordinated attack scenario by generating authentic Windows Security Events,
    creating user accounts, modifying firewall rules, and executing benign processes.
    
    The script is designed for educational purposes in controlled lab environments.
    All artifacts are clearly marked as simulated and use non-malicious payloads.
    
    WARNING: This script makes system changes. Run only in isolated lab environments.
    No cleanup or reset logic is included - use Undo-Events.ps1 for cleanup.
    
.REQUIREMENTS
    - Windows 10/11 or Windows Server
    - Administrator privileges (script will verify and exit if not elevated)
    - PowerShell 5.0 or later

.SCENARIO BACKGROUND - INSIDER THREAT INVESTIGATION
    COMPANY: TechCorp Industries
    VICTIM: CEO Jennifer Martinez (this computer)
    THREAT ACTOR: Marcus Thompson - Former Senior IT Administrator
    
    INCIDENT OVERVIEW:
    Marcus Thompson was a trusted Senior IT Administrator at TechCorp Industries for 8 years.
    Last month, he was terminated for policy violations and inappropriate conduct. During his 
    employment, Marcus had extensive access to company systems and knew executive schedules.
    
    Two weeks after termination, Marcus used his insider knowledge to target CEO Jennifer 
    Martinez's workstation during her business trip to London. Using credentials he had 
    previously obtained and cached, Marcus remotely accessed the CEO's computer to:
    
    • Establish persistent backdoor access for future reconnaissance
    • Create hidden administrative accounts for continued access
    • Modify security settings to evade detection
    • Deploy tools for potential data exfiltration
    • Maintain access for corporate espionage or sabotage
    
    The attack was discovered when automated security monitoring flagged suspicious account
    creation activities on executive workstations. Your team is now conducting forensic
    analysis of the CEO's computer to determine the scope of the breach and gather evidence
    for potential prosecution.
    
    INVESTIGATION OBJECTIVES:
    • Reconstruct the complete attack timeline
    • Identify all accounts and backdoors created
    • Determine what data may have been accessed
    • Gather evidence of Marcus Thompson's involvement
    • Assess potential for ongoing unauthorized access

.ATTACK TIMELINE OVERVIEW
    ════════════════════════════════════════════════════════════════════════════════════════
    COMPLETE TIMELINE BREAKDOWN - ALL POSSIBLE TIMESTAMP VARIATIONS
    ════════════════════════════════════════════════════════════════════════════════════════
    
    BASE TIME: [TimeBase Parameter] - Default: 24 hours ago
    │
    ├─ PHASE 1: INITIAL BREACH (Remote Desktop Access)
    │  ├─ Event: Security Event 4624 (Successful Logon)
    │  ├─ Timestamp Range: TimeBase + 1 to 5 minutes
    │  ├─ Possible Windows: 4 different minute offsets
    │  ├─ Actor: Marcus Thompson (Bruce.Wayne parameter)
    │  ├─ Method: RDP connection using cached credentials
    │  ├─ Source: Remote workstation/VPN connection
    │  └─ Significance: Establishes initial compromise baseline
    │
    ├─ PHASE 2: PERSISTENCE ESTABLISHMENT (Backdoor Account Creation)
    │  ├─ Event: Security Event 4720 (User Account Created)
    │  ├─ Timestamp Range: RDP Time + 5 to 15 minutes
    │  ├─ Possible Windows: 10 different minute offsets
    │  ├─ Gap Analysis: 5-15 min = Reconnaissance and planning phase
    │  ├─ Target: Creates "John.Hacksmith" backdoor account
    │  ├─ Method: Using elevated RDP session privileges
    │  └─ Significance: Shows progression from access to persistence
    │
    ├─ PHASE 3: PRIVILEGE ESCALATION (Administrative Access)
    │  ├─ Event: Security Event 4732 (Member Added to Security Group)
    │  ├─ Timestamp Range: User Creation + 1 to 5 minutes
    │  ├─ Possible Windows: 4 different minute offsets
    │  ├─ Gap Analysis: 1-5 min = Immediate privilege escalation
    │  ├─ Action: Adds backdoor account to Administrators group
    │  ├─ Method: Automated script or manual command execution
    │  └─ Significance: Rapid escalation indicates experienced attacker
    │
    ├─ PHASE 4: DEFENSE EVASION (Firewall Manipulation)
    │  ├─ Event: Windows Firewall logs + MPSSVC Service events
    │  ├─ Timestamp Range: Group Addition + 2 to 10 minutes
    │  ├─ Possible Windows: 8 different minute offsets
    │  ├─ Gap Analysis: 2-10 min = Planning network access channels
    │  ├─ Action: Creates "Definitely-Not-Malicious" firewall rule
    │  ├─ Method: Opens TCP port for backdoor communication
    │  └─ Significance: Shows use of admin rights for persistent access
    │
    └─ PHASE 5: MALICIOUS TOOL DEPLOYMENT (File Drop and Execution)
       ├─ Sub-Phase 5A: File Creation
       │  ├─ Event: Security Event 4656 (File System Object Access)
       │  ├─ Timestamp Range: Firewall Creation + 3 to 8 minutes
       │  ├─ Possible Windows: 5 different minute offsets
       │  ├─ Gap Analysis: 3-8 min = Tool download/compilation phase
       │  └─ Action: Creates "Totally-Not-Malware.exe" in temp directory
       │
       └─ Sub-Phase 5B: Tool Execution
          ├─ Event: Security Event 4688 (Process Creation)
          ├─ Timestamp Range: File Creation + 1 to 3 minutes
          ├─ Possible Windows: 2 different minute offsets
          ├─ Gap Analysis: 1-3 min = Immediate execution (automation)
          └─ Action: Executes reconnaissance/backdoor tool
    
    TOTAL TIMELINE SPAN: 12 to 41 minutes (varies based on random timing)
    MINIMUM ATTACK DURATION: 12 minutes (all shortest gaps)
    MAXIMUM ATTACK DURATION: 41 minutes (all longest gaps)
    
    FORENSIC CORRELATION POINTS:
    • All events tied to Marcus Thompson's initial RDP session
    • Backdoor account "John.Hacksmith" used for persistent access
    • Firewall rule name indicates attempt at deception
    • File naming convention suggests awareness of detection
    • Tight timing indicates pre-planned, scripted attack
    
    INVESTIGATIVE TIMELINE ANALYSIS:
    • Short gaps (1-5 min) = Automated tools or practiced manual execution
    • Medium gaps (5-15 min) = Reconnaissance, planning, or manual navigation
    • Consistent progression = Experienced insider threat with system knowledge
    • Tool naming = Psychological indicators of disgruntled employee
    
.TIMELINE LOGIC
    - All events are chronologically sequenced from the TimeBase parameter (default: 1 day ago)
    - Events follow a realistic attack progression with authentic time gaps between actions
    - Total simulated attack timeline spans approximately 12-41 minutes
    - Timestamps create the appearance of a coordinated, multi-stage cyber attack
    - Random elements ensure each simulation produces unique but realistic timing patterns
    
.EDUCATIONAL VALUE
    Students will practice analyzing:
    - Windows Security Event logs (4624, 4720, 4732, 4656, 4688)
    - User account creation and privilege escalation
    - Firewall rule modifications and network security bypass
    - Process execution artifacts and file system traces
    - Timeline reconstruction techniques for insider threat investigations
    - Correlation analysis between multiple log sources
    - Insider threat behavioral patterns and TTPs (Tactics, Techniques, Procedures)
#>

param(
    [datetime]$TimeBase = (Get-Date).AddDays(-1),                   # Starting timestamp for the attack timeline (when Marcus began his assault)
    [string]$ImpersonateUser = "Marcus.Thompson",                   # The disgruntled ex-IT admin conducting the insider attack
    [string]$TargetUser = "Jennifer.Martinez.Backup",               # Backdoor account created by Marcus for persistent CEO computer access
    [string]$ruleName = "Windows-System-Update-Service",            # Deceptive firewall rule name to avoid detection by other IT staff
    [string]$exePath = "$env:TEMP\WindowsUpdateManager.exe",        # Malicious tool disguised as legitimate Windows component
    [int]$FirewallPort = (Get-Random -Minimum 2000 -Maximum 9999)   # TCP port for backdoor communication channel (randomized per attack)
)

$ErrorActionPreference = 'Stop'

function New-RandomSid {
    <#
    .SYNOPSIS
        Generates a realistic Windows Security Identifier (SID) for simulated users and groups
    .DESCRIPTION
        Creates properly formatted SIDs that match Windows domain/local account patterns.
        Used to make Security Event logs appear authentic during forensic analysis exercises.
    #>
    param([string]$Prefix = "S-1-5-21")
    $part1 = Get-Random -Minimum 1000000000 -Maximum 4000000000
    $part2 = Get-Random -Minimum 1000000000 -Maximum 4000000000  
    $part3 = Get-Random -Minimum 1000000000 -Maximum 4000000000
    $rid = Get-Random -Minimum 1000 -Maximum 9999
    return "$Prefix-$part1-$part2-$part3-$rid"
}

function New-RandomLogonId {
    <#
    .SYNOPSIS
        Creates a realistic Windows logon session ID in hexadecimal format
    .DESCRIPTION
        Generates session IDs that appear in Windows Security Events for user logon tracking.
        Essential for creating believable forensic artifacts in training scenarios.
    #>
    $hex = Get-Random -Minimum 0x100000 -Maximum 0xFFFFFF
    return "0x$($hex.ToString('X'))"
}

function New-RandomIP {
    <#
    .SYNOPSIS
        Intelligently generates IP addresses within the current network's subnet range
    .DESCRIPTION
        Analyzes the local network configuration and creates realistic IP addresses
        that would appear in the same subnet. Used for simulating remote connections
        and network-based attack vectors in Security Event logs.
    #>
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

function Write-AppEvent {
    <#
    .SYNOPSIS
        Fallback function to write events to Application log when Security log injection fails
    .DESCRIPTION
        Provides a reliable backup method for event logging when direct Security log
        injection is blocked by system policies or permissions. Creates custom event
        sources and uses multiple methods to ensure event creation succeeds.
    #>
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
    Write-Warning "ADMINISTRATOR PRIVILEGES REQUIRED: This script must be run as Administrator to create users, modify firewall rules, and inject Security Events. Please restart PowerShell as Administrator and try again."
    return
}


# Configure Windows audit policies to ensure all simulated activities are properly logged
Write-Host "🔍 INITIATING FORENSIC LAB SIMULATION - CEO COMPUTER BREACH INVESTIGATION" -ForegroundColor Yellow -BackgroundColor DarkRed
Write-Host ""
Write-Host "INCIDENT BRIEFING:" -ForegroundColor Yellow
Write-Host "  • VICTIM: CEO Jennifer Martinez (this workstation)" -ForegroundColor White
Write-Host "  • SUSPECT: Marcus Thompson - Former Senior IT Administrator" -ForegroundColor White  
Write-Host "  • ATTACK DATE: $($TimeBase.ToString('yyyy-MM-dd')) during CEO's business trip to London" -ForegroundColor White
Write-Host "  • DISCOVERY: Automated alerts flagged suspicious administrative account creation" -ForegroundColor White
Write-Host ""
Write-Host "CONFIGURING AUDIT POLICIES: Enabling comprehensive Security Event logging for investigation..." -ForegroundColor Yellow
Write-Host "This ensures that Marcus Thompson's attack activities will generate authentic Windows Security Events for analysis." -ForegroundColor Cyan

# Enable critical audit categories that will capture our simulated attack activities
# These policies take effect immediately without requiring a system reboot
& auditpol.exe /set /category:"Account Management" /success:enable /failure:enable     # Captures user/group creation and modifications
& auditpol.exe /set /category:"Policy Change" /success:enable /failure:enable        # Captures firewall rule changes and system policy modifications  
& auditpol.exe /set /category:"Detailed Tracking" /success:enable /failure:enable    # Captures process creation and execution events

Write-Host "✓ AUDIT POLICIES SUCCESSFULLY CONFIGURED" -ForegroundColor Green
Write-Host "  → Account Management events (4720, 4732) will be logged to Security Event Log" -ForegroundColor Green
Write-Host "  → Policy Change events (firewall modifications) will be logged to Windows Firewall log" -ForegroundColor Green  
Write-Host "  → Process Tracking events (4688) will be logged to Security Event Log" -ForegroundColor Green
Write-Host ""
Write-Host "RECONSTRUCTING ATTACK TIMELINE: Simulating Marcus Thompson's insider attack on CEO workstation..." -ForegroundColor Yellow

# ═══════════════════════════════════════════════════════════════════════════════════
# PHASE 1: INITIAL BREACH - INSIDER REMOTE DESKTOP ACCESS
# ═══════════════════════════════════════════════════════════════════════════════════
#
# TIMELINE ANALYSIS - Marcus Thompson's RDP Access (Security Event 4624):
# • Timestamp Range: TimeBase + 1-5 minutes (4-minute window)
# • Possible Variations: Could occur 1, 2, 3, 4, or 5 minutes after TimeBase
# • Time Gap Analysis: 4-minute window simulates time to establish secure VPN connection
# • Forensic Significance: Establishes the initial compromise baseline timestamp
# • Event Correlation: This timestamp becomes reference point for all subsequent activities
# • Insider Context: Marcus knew CEO was traveling, used cached admin credentials
#                    and connected during London business hours to avoid suspicion
# • Log Location: Security Event Log (Event ID 4624)
# • Key Investigation Fields: Source IP (Marcus's location), Workstation Name, Logon Type 10

# Initialize attack timeline variables based on when Marcus began his assault
$currentTime = $TimeBase
$src = "ForensicLabGenerator"

Write-Host "[PHASE 1] RECONSTRUCTING INITIAL BREACH: Marcus Thompson's remote access to CEO workstation..." -ForegroundColor Magenta

# Generate realistic network connection details for Marcus Thompson's insider attack
$rdpUser    = "$ImpersonateUser"                                    # Marcus Thompson - the disgruntled ex-IT admin
$sourceHost = "MARCUS-HOME-PC"                                      # Marcus's personal computer used for the attack
$logonID    = New-RandomLogonId                                     # Unique session identifier for this breach
$accountSid = New-RandomSid                                         # Security identifier for Marcus's account
$srcPort    = "3389"                                                # Standard RDP port
$sourceIP   = New-RandomIP                                          # Marcus's home internet connection IP

# Calculate realistic timing for Marcus's initial RDP connection (1-5 minutes after TimeBase)
# This represents when Marcus successfully authenticated using his cached admin credentials
$rdpLogonTime = $currentTime.AddMinutes($(Get-Random -Minimum 1 -Maximum 5))

Write-Host "  → Marcus Thompson connecting from $sourceIP via $sourceHost workstation" -ForegroundColor Cyan
Write-Host "  → Using cached administrative credentials from his former IT position" -ForegroundColor DarkCyan
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
Write-Host "✓ Security Event 4624 (Successful Logon) injected - RDP session established" -ForegroundColor Green

# ═══════════════════════════════════════════════════════════════════════════════════
# PHASE 2: PERSISTENCE - LOCAL USER ACCOUNT CREATION  
# ═══════════════════════════════════════════════════════════════════════════════════
#
# TIMELINE ANALYSIS - Backdoor Account Creation (Security Event 4720):
# • Timestamp Range: RDP Logon Time + 5-15 minutes (10-minute window)
# • Possible Variations: Could occur 5-15 minutes after successful RDP logon
# • Time Gap Analysis: 5-15 minute delay simulates Marcus's reconnaissance phase
#                      as he navigates the CEO's computer and plans his persistence strategy
# • Forensic Significance: Shows progression from initial access to establishing backdoors
# • Event Correlation: Links back to Marcus's RDP logon event via same session
# • Insider Context: Marcus knows CEO travel schedule, creates account during trip
#                    to avoid immediate detection by CEO returning to workstation
# • Log Location: Security Event Log (Event ID 4720)
# • Key Investigation Fields: Creator SID (Marcus), Target Username (backup account)
# • Timeline Delta: Always occurs AFTER RDP logon (minimum 5-minute reconnaissance gap)

Write-Host ""
Write-Host "[PHASE 2] ESTABLISHING PERSISTENCE: Marcus creates backdoor account for future CEO computer access..." -ForegroundColor Magenta

# Configure backdoor account details for Marcus's persistence strategy
$user = "$TargetUser"                                               # The backup account Marcus will create
$pass = "TechCorp2025!"                                             # Strong password to avoid detection by security scans
$impersonateLogonId = New-RandomLogonId                             # Session ID for Marcus's actions
$impersonateSid = New-RandomSid                                     # SID for Marcus Thompson
$targetUserSid = New-RandomSid -Prefix "S-1-5-21-$([Math]::Abs($env:COMPUTERNAME.GetHashCode()))"  # Consistent SID for backdoor account

if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
    Write-Host "  → Creating backdoor account: $user (disguised as backup account for CEO)" -ForegroundColor Cyan
    
    # Calculate timing for backdoor account creation (5-15 minutes after RDP logon)
    # This represents Marcus's planning phase before establishing persistent access
    $userCreateTime = $rdpLogonTime.AddMinutes($(Get-Random -Minimum 5 -Maximum 15))
    Write-Host "  → Scheduled for: $($userCreateTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkCyan
    Write-Host "  → Marcus leveraging his IT knowledge to create convincing backup account name" -ForegroundColor DarkCyan
    
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
    Write-Host "✓ Backdoor account '$user' created successfully by Marcus Thompson" -ForegroundColor Green
    Write-Host "  → Password: $pass (strong password to avoid automated security scans)" -ForegroundColor Green
    Write-Host "  → Security Event 4720 (User Account Created) logged with Marcus as creator" -ForegroundColor Green
} else {
    Write-Host "⚠ Account '$user' already exists - Marcus may have accessed this system before" -ForegroundColor DarkYellow
}

# ═══════════════════════════════════════════════════════════════════════════════════
# PHASE 3: PRIVILEGE ESCALATION - ADMINISTRATOR GROUP MEMBERSHIP
# ═══════════════════════════════════════════════════════════════════════════════════
#
# TIMELINE ANALYSIS - Administrative Privilege Escalation (Security Event 4732):
# • Timestamp Range: User Creation Time + 1-5 minutes (4-minute window)
# • Possible Variations: Could occur 1-5 minutes after backdoor account creation
# • Time Gap Analysis: Short 1-5 minute gap indicates immediate privilege escalation
#                      typical of insider attacks where system knowledge allows rapid execution
# • Forensic Significance: Shows Marcus's progression from persistence to full administrative control
# • Event Correlation: Links to both RDP logon and backdoor account creation events
# • Insider Context: Marcus immediately elevates privileges to maximize access to CEO data
#                    before any defensive measures can be implemented
# • Log Location: Security Event Log (Event ID 4732)
# • Key Investigation Fields: Group SID (S-1-5-32-544 = Administrators), Member SID, Performer
# • Timeline Delta: Always occurs AFTER backdoor creation (1-5 minute gap)
# • Cumulative Timeline: RDP + 6-20 minutes total from initial breach

Write-Host ""
Write-Host "[PHASE 3] ESCALATING PRIVILEGES: Marcus grants administrative rights to backdoor account..." -ForegroundColor Magenta

try {
    Add-LocalGroupMember -Group "Administrators" -Member $user -ErrorAction Stop
    
    # Calculate timing for privilege escalation (1-5 minutes after backdoor creation)
    # This represents Marcus immediately elevating privileges for maximum CEO data access
    $groupAddTime = $userCreateTime.AddMinutes($(Get-Random -Minimum 1 -Maximum 5))
    Write-Host "  → Scheduled privilege escalation for: $($groupAddTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkCyan
    Write-Host "  → Marcus using his insider knowledge to rapidly escalate backdoor account privileges" -ForegroundColor DarkCyan
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
    Write-Host "✓ Backdoor account '$user' successfully granted Administrator privileges" -ForegroundColor Green
    Write-Host "  → Security Event 4732 (Member Added to Security Group) logged with Marcus as performer" -ForegroundColor Green
    Write-Host "  → Marcus now has persistent administrative access to CEO's computer" -ForegroundColor Green
} catch {
    Write-Host "⚠ Account '$user' already has Administrator privileges - Marcus maintaining existing access" -ForegroundColor DarkYellow
}

# ═══════════════════════════════════════════════════════════════════════════════════
# PHASE 4: DEFENSE EVASION - FIREWALL RULE MANIPULATION
# ═══════════════════════════════════════════════════════════════════════════════════
#
# TIMELINE ANALYSIS - Deceptive Firewall Rule Creation (Windows Firewall Logs):
# • Timestamp Range: Group Addition Time + 2-10 minutes (8-minute window)
# • Possible Variations: Could occur 2-10 minutes after privilege escalation
# • Time Gap Analysis: 2-10 minute delay represents Marcus's planning phase for establishing
#                      covert communication channels and preparing for data exfiltration
# • Forensic Significance: Shows use of administrative privileges for defense evasion
# • Event Correlation: Links to privilege escalation event and demonstrates insider knowledge
# • Insider Context: Marcus creates legitimate-sounding firewall rule to avoid detection
#                    by other IT staff who might review firewall configurations
# • Log Location: Windows Firewall with Advanced Security logs + MPSSVC Service logs
# • Key Investigation Fields: Rule Name, Direction, Protocol, Port, Action, Creator
# • Timeline Delta: Always occurs AFTER privilege escalation (2-10 minute gap)
# • Cumulative Timeline: RDP + 8-30 minutes total from initial breach

Write-Host ""
Write-Host "[PHASE 4] ESTABLISHING COVERT CHANNELS: Marcus creates deceptive firewall rule for persistent access..." -ForegroundColor Magenta

# Generate unique logon session for the backdoor account's future actions
$targetUserLogonId = New-RandomLogonId

# Calculate timing for firewall manipulation (2-10 minutes after privilege escalation)
# This represents Marcus planning his covert communication channels for ongoing access
$firewallCreateTime = $groupAddTime.AddMinutes($(Get-Random -Minimum 2 -Maximum 10))
Write-Host "  → Scheduled firewall modification for: $($firewallCreateTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkCyan

try {
    # Construct the netsh command with deceptive rule name to avoid IT detection
    $netshCommand = "netsh advfirewall firewall add rule name=`"$ruleName`" dir=in action=allow protocol=TCP localport=$FirewallPort"
    
    Write-Host "  → Creating deceptive inbound TCP rule '$ruleName' for port $FirewallPort" -ForegroundColor Cyan
    Write-Host "  → Using legitimate-sounding name to avoid detection by other IT staff" -ForegroundColor Cyan
    Write-Host "  → Attempting execution as backdoor account '$TargetUser' for stealth..." -ForegroundColor Cyan
    
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
            Write-Host "✓ Firewall rule '$ruleName' created successfully as user '$TargetUser'" -ForegroundColor Green
            Write-Host "  → Authentic Windows Firewall logs generated showing $TargetUser as rule creator" -ForegroundColor Green
            Write-Host "  → Students can analyze Windows Firewall logs for suspicious rule creation" -ForegroundColor Green
        } else {
            throw "Runas failed with exit code $($process.ExitCode)"
        }
        
    } catch {
        Write-Warning "Primary method (runas) failed: $($_.Exception.Message)"
        Write-Host "⤷ FALLBACK METHOD 1: Attempting direct netsh execution..." -ForegroundColor Yellow
        
        # Fallback 1: Direct netsh execution (will log current user)
        $result = cmd.exe /c $netshCommand 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            # Generate Application event to indicate target user performed action (since direct execution won't show target user)
            $firewallMsg = "SIMULATED ADMINISTRATIVE ACTION`nUser: $TargetUser`nAction: Firewall Rule Creation`nRule Name: $ruleName`nDirection: Inbound Allow`nProtocol: TCP`nPort: $FirewallPort`nExecution Method: Fallback (direct netsh)`nTimestamp: $(Get-Date)`n`nNOTE FOR ANALYSTS: Windows Firewall logs may show script runner instead of target user due to execution method limitations."
            Write-AppEvent -Source "AdminActivity" -EventID 1001 -Message $firewallMsg
            Write-Host "✓ Firewall rule '$ruleName' created using netsh fallback method" -ForegroundColor Yellow
            Write-Host "  → Application Event 1001 logged to indicate $TargetUser activity" -ForegroundColor Yellow
        } else {
            # Fallback 2: PowerShell method
            Write-Warning "⤷ Netsh fallback also failed: $result"
            Write-Host "⤷ FALLBACK METHOD 2: Using PowerShell New-NetFirewallRule as final attempt..." -ForegroundColor Yellow
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $FirewallPort -Action Allow -Profile Any -ErrorAction Stop | Out-Null
            
            # Generate Application event for final fallback
            $firewallMsg = "SIMULATED ADMINISTRATIVE ACTION`nUser: $TargetUser`nAction: Firewall Rule Creation`nRule Name: $ruleName`nDirection: Inbound Allow`nProtocol: TCP`nPort: $FirewallPort`nExecution Method: Final Fallback (PowerShell)`nTimestamp: $(Get-Date)`n`nNOTE FOR ANALYSTS: Windows Firewall logs may show script runner instead of target user due to execution method limitations."
            Write-AppEvent -Source "AdminActivity" -EventID 1001 -Message $firewallMsg
            Write-Host "✓ Firewall rule '$ruleName' created using PowerShell final fallback method" -ForegroundColor Yellow
            Write-Host "  → Application Event 1001 logged to indicate $TargetUser activity" -ForegroundColor Yellow
        }
    }
    
} catch {
    Write-Host "⚠ Firewall rule '$ruleName' already exists - skipping creation step" -ForegroundColor DarkYellow
}

# ═══════════════════════════════════════════════════════════════════════════════════
# PHASE 5: MALICIOUS ACTIVITY - FILE CREATION AND EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════════
#
# TIMELINE ANALYSIS - File Creation (Security Event 4656) and Execution (Security Event 4688):
# FILE CREATION:
# • Timestamp Range: Firewall Creation Time + 3-8 minutes (5-minute window)
# • Possible Variations: Could occur 3-8 minutes after firewall rule creation
# • Time Gap Analysis: 3-8 minute delay represents malware download/compilation phase
#                      after establishing network access channels
# 
# PROCESS EXECUTION:
# • Timestamp Range: File Creation Time + 1-3 minutes (2-minute window)
# • Possible Variations: Could occur 1-3 minutes after file creation
# • Time Gap Analysis: Short 1-3 minute gap indicates immediate execution after deployment
#                      typical of automated malware deployment scripts
#
# FORENSIC SIGNIFICANCE:
# • Event Correlation: Links file creation to execution, showing complete attack chain
# • Timeline Progression: Demonstrates full kill chain from access to execution
# • Real-world Context: Attackers quickly execute payloads to minimize detection window
# • Log Locations: Security Event Log (Events 4656, 4688)
# • Key Fields: Process ID, Command Line, Parent Process, File Path, Access Rights
# • Timeline Deltas: File creation AFTER firewall (3-8 min), execution AFTER creation (1-3 min)
# • Cumulative Timeline: RDP + 12-41 minutes total attack duration

Write-Host ""
Write-Host "[PHASE 5] SIMULATING MALICIOUS PAYLOAD: Creating and executing benign test executable..." -ForegroundColor Magenta

# Create a completely harmless C# program that only logs its execution and sleeps
# This simulates malware deployment without any actual malicious functionality
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
    Write-Host "  → Compiling benign C# executable to simulate malware deployment..." -ForegroundColor Cyan
    
    # Compile the harmless C# code into an executable file
    Add-Type -TypeDefinition $code -OutputAssembly $exePath -OutputType ConsoleApplication
    Write-Host "✓ Test executable compiled successfully: $exePath" -ForegroundColor Green
    Write-Host "  → This is a completely benign program that only logs execution and sleeps for 2 seconds" -ForegroundColor Green
    
    # Calculate timing for file creation (3-8 minutes after firewall rule creation)
    # This represents the attacker downloading/creating their payload after establishing network access
    $fileCreateTime = $firewallCreateTime.AddMinutes($(Get-Random -Minimum 3 -Maximum 8))
    Write-Host "  → Scheduled file creation for: $($fileCreateTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkCyan
    
    # Modify file timestamp to match the realistic attack timeline
    (Get-Item $exePath).CreationTime = $fileCreateTime
    
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
    Write-Host "✓ Security Event 4656 (File System Object Access) logged for file creation" -ForegroundColor Green
    
    Write-Host "  → Executing test program to simulate malicious payload execution..." -ForegroundColor Cyan
    
    # Execute the benign test program and capture process information
    $processStart = Start-Process -FilePath $exePath -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
    
    if ($processStart) {
        # Calculate timing for process execution (1-3 minutes after file creation)
        # This represents the attacker executing their payload shortly after deployment
        $execTime = $fileCreateTime.AddMinutes($(Get-Random -Minimum 1 -Maximum 3))
        Write-Host "  → Scheduled execution for: $($execTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkCyan
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
        Write-Host "✓ Test executable executed successfully (Process ID: $($processStart.Id))" -ForegroundColor Green
        Write-Host "  → Security Event 4688 (Process Creation) logged showing $TargetUser as executor" -ForegroundColor Green
        Write-Host "  → Students can analyze process creation events for suspicious executable launches" -ForegroundColor Green
    } else {
        Write-Warning "⚠ Process failed to start, but file creation Security Event was still generated for analysis"
    }
} catch {
    Write-Warning "⚠ Failed to compile test executable: $($_.Exception.Message)"
    Write-Host "⤷ FALLBACK: Using benign PowerShell process for execution simulation..." -ForegroundColor Yellow
    
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
        Write-Host "✓ Fallback PowerShell process execution logged as $TargetUser" -ForegroundColor Green
        Write-Host "  → Security Event 4688 (Process Creation) generated for analysis" -ForegroundColor Green
    }
}

# ═══════════════════════════════════════════════════════════════════════════════════
# INSIDER THREAT INVESTIGATION COMPLETE - EVIDENCE RECONSTRUCTION SUCCESSFUL
# ═══════════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "🔍 INSIDER THREAT INVESTIGATION SUCCESSFULLY RECONSTRUCTED" -ForegroundColor Green -BackgroundColor Black
Write-Host ""
Write-Host "MARCUS THOMPSON'S ATTACK SEQUENCE EVIDENCE:" -ForegroundColor Yellow
Write-Host "  1. Initial Breach: Remote RDP access using cached admin credentials" -ForegroundColor White
Write-Host "  2. Persistence: Backdoor account '$TargetUser' created on CEO's computer" -ForegroundColor White  
Write-Host "  3. Privilege Escalation: Backdoor account granted Administrator privileges" -ForegroundColor White
Write-Host "  4. Defense Evasion: Deceptive firewall rule '$ruleName' created for covert access" -ForegroundColor White
Write-Host "  5. Tool Deployment: Reconnaissance/exfiltration tool deployed and executed" -ForegroundColor White
Write-Host ""
Write-Host "DIGITAL FORENSIC EVIDENCE GENERATED:" -ForegroundColor Yellow
Write-Host "  → Security Event 4624: Marcus Thompson's RDP authentication to CEO workstation" -ForegroundColor Cyan
Write-Host "  → Security Event 4720: Backdoor account creation by Marcus Thompson" -ForegroundColor Cyan
Write-Host "  → Security Event 4732: Administrative privilege escalation of backdoor account" -ForegroundColor Cyan
Write-Host "  → Windows Firewall logs: Deceptive firewall rule creation for persistent access" -ForegroundColor Cyan
Write-Host "  → Security Event 4656: Suspicious file creation in CEO's temp directory" -ForegroundColor Cyan
Write-Host "  → Security Event 4688: Malicious tool execution under backdoor account context" -ForegroundColor Cyan
Write-Host ""
Write-Host "INSIDER THREAT INDICATORS IDENTIFIED:" -ForegroundColor Yellow
Write-Host "  → 📅 Attack occurred during CEO's known business travel (insider knowledge)" -ForegroundColor White
Write-Host "  → 🔑 Use of cached administrative credentials from previous employment" -ForegroundColor White
Write-Host "  → 🎯 Targeted attack specifically on CEO's personal workstation" -ForegroundColor White
Write-Host "  → 🕰️ Rapid execution indicating familiarity with target environment" -ForegroundColor White
Write-Host "  → 🎭 Deceptive naming conventions to avoid detection by IT security" -ForegroundColor White
Write-Host "  → 📊 Timeline pattern consistent with planned insider attack methodology" -ForegroundColor White
Write-Host ""
Write-Host "ATTACK TIMELINE DETAILS:" -ForegroundColor Yellow
Write-Host "  📅 Base Time: $($TimeBase.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
Write-Host "  ⏰ Total Duration: Approximately $([math]::Round(($fileCreateTime.AddMinutes(3) - $rdpLogonTime).TotalMinutes)) minutes of coordinated activity" -ForegroundColor White
Write-Host "  🔍 Students can now analyze these realistic artifacts using standard forensic techniques" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  CLEANUP REMINDER: Use 'Undo-Events.ps1' to remove simulated artifacts when training is complete" -ForegroundColor Red

# ═══════════════════════════════════════════════════════════════════════════════════════════
# ACTUAL TIMELINE ANALYSIS - SPECIFIC TIMESTAMPS USED IN THIS SIMULATION
# ═══════════════════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "📊 ACTUAL TIMELINE BREAKDOWN - SPECIFIC TIMESTAMPS GENERATED:" -ForegroundColor Yellow -BackgroundColor DarkBlue
Write-Host ""

# Calculate actual time differences for forensic analysis
$rdpToUserCreation = ($userCreateTime - $rdpLogonTime).TotalMinutes
$userToGroupAdd = ($groupAddTime - $userCreateTime).TotalMinutes  
$groupToFirewall = ($firewallCreateTime - $groupAddTime).TotalMinutes
$firewallToFile = ($fileCreateTime - $firewallCreateTime).TotalMinutes
$fileToExecution = if ($execTime) { ($execTime - $fileCreateTime).TotalMinutes } else { 0 }
$totalDuration = if ($execTime) { ($execTime - $rdpLogonTime).TotalMinutes } else { ($fileCreateTime - $rdpLogonTime).TotalMinutes }

Write-Host "🕐 PHASE 1 - INITIAL BREACH:" -ForegroundColor Cyan
Write-Host "   📅 RDP Logon Time: $($rdpLogonTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
Write-Host "   ⏱️  Time from BaseTime: +$([math]::Round(($rdpLogonTime - $TimeBase).TotalMinutes, 1)) minutes" -ForegroundColor Gray
Write-Host ""

Write-Host "🕑 PHASE 2 - PERSISTENCE:" -ForegroundColor Cyan  
Write-Host "   📅 User Creation Time: $($userCreateTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
Write-Host "   ⏱️  Time Gap from RDP: +$([math]::Round($rdpToUserCreation, 1)) minutes" -ForegroundColor Gray
Write-Host ""

Write-Host "🕒 PHASE 3 - PRIVILEGE ESCALATION:" -ForegroundColor Cyan
Write-Host "   📅 Group Addition Time: $($groupAddTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White  
Write-Host "   ⏱️  Time Gap from User Creation: +$([math]::Round($userToGroupAdd, 1)) minutes" -ForegroundColor Gray
Write-Host ""

Write-Host "🕓 PHASE 4 - DEFENSE EVASION:" -ForegroundColor Cyan
Write-Host "   📅 Firewall Rule Time: $($firewallCreateTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
Write-Host "   ⏱️  Time Gap from Group Addition: +$([math]::Round($groupToFirewall, 1)) minutes" -ForegroundColor Gray  
Write-Host ""

Write-Host "🕔 PHASE 5 - MALICIOUS ACTIVITY:" -ForegroundColor Cyan
Write-Host "   📅 File Creation Time: $($fileCreateTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
Write-Host "   ⏱️  Time Gap from Firewall: +$([math]::Round($firewallToFile, 1)) minutes" -ForegroundColor Gray

if ($execTime) {
    Write-Host "   📅 Process Execution Time: $($execTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White  
    Write-Host "   ⏱️  Time Gap from File Creation: +$([math]::Round($fileToExecution, 1)) minutes" -ForegroundColor Gray
}
Write-Host ""

Write-Host "⏰ TOTAL ATTACK TIMELINE SUMMARY:" -ForegroundColor Yellow
Write-Host "   🎯 Total Attack Duration: $([math]::Round($totalDuration, 1)) minutes" -ForegroundColor White
Write-Host "   📊 Longest Gap: $([math]::Round([math]::Max([math]::Max([math]::Max([math]::Max($rdpToUserCreation, $userToGroupAdd), $groupToFirewall), $firewallToFile), $fileToExecution), 1)) minutes (between phases)" -ForegroundColor White
Write-Host "   📊 Shortest Gap: $([math]::Round([math]::Min([math]::Min([math]::Min([math]::Min($rdpToUserCreation, $userToGroupAdd), $groupToFirewall), $firewallToFile), $fileToExecution), 1)) minutes (between phases)" -ForegroundColor White
Write-Host ""

Write-Host "🎓 STUDENT FORENSIC ANALYSIS OBJECTIVES:" -ForegroundColor Yellow
Write-Host "   • Correlate Marcus Thompson's RDP access with subsequent malicious activities" -ForegroundColor White
Write-Host "   • Identify insider threat indicators: timing, naming patterns, system knowledge" -ForegroundColor White  
Write-Host "   • Trace the complete attack kill chain: Access → Persistence → Escalation → Evasion → Tools" -ForegroundColor White
Write-Host "   • Analyze time gaps to distinguish reconnaissance vs. automated execution phases" -ForegroundColor White
Write-Host "   • Evaluate deceptive techniques used to avoid IT security detection" -ForegroundColor White
Write-Host "   • Build timeline evidence for potential criminal prosecution of insider threat" -ForegroundColor White
Write-Host "   • Short gaps ($([math]::Round($userToGroupAdd, 1))min, $([math]::Round($fileToExecution, 1))min) suggest automation or practiced execution" -ForegroundColor White
Write-Host "   • Longer gaps ($([math]::Round($rdpToUserCreation, 1))min, $([math]::Round($firewallToFile, 1))min) suggest manual reconnaissance and planning" -ForegroundColor White

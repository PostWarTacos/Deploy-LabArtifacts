<#
Undo-Events.ps1
Cleanup script to undo all artifacts created by Generate-Events.ps1

This script removes:
- Created local users and their profile directories
- Firewall rules created by the script
- Custom event log sources
- Temporary files and executables
- Audit policy changes

Run as Administrator.
#>

param(
    [string]$TargetUser = "John.Hacksmith",                    # Target user to remove (must match Generate-Events.ps1)
    [string]$ruleName = "Definitely-Not-Malicious",            # Firewall rule name to remove (must match Generate-Events.ps1)
    [switch]$KeepAuditPolicies,                                # Keep audit policies enabled if specified
    [switch]$WhatIf                                           # Show what would be done without actually doing it
)

$ErrorActionPreference = 'Stop'

# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Run as Administrator. Exiting."
    return
}

Write-Host "Starting cleanup of artifacts created by Generate-Events.ps1..." -ForegroundColor Yellow

if ($WhatIf) {
    Write-Host "WHATIF MODE: No changes will be made, only showing what would be done" -ForegroundColor Cyan
}

# Function to handle WhatIf operations
function Invoke-UndoAction {
    param(
        [string]$Description,
        [scriptblock]$Action,
        [string]$SuccessMessage,
        [string]$SkipMessage = $null
    )
    
    if ($WhatIf) {
        Write-Host "WHATIF: Would $Description" -ForegroundColor Cyan
        return
    }
    
    try {
        $result = & $Action
        if ($null -ne $result -and $result -eq "SKIP") {
            if ($SkipMessage) {
                Write-Host $SkipMessage -ForegroundColor DarkYellow
            }
        } else {
            Write-Host $SuccessMessage -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to $Description : $($_.Exception.Message)"
    }
}

# 1) Remove the created local user and profile
Invoke-UndoAction -Description "remove local user '$TargetUser'" -Action {
    $user = Get-LocalUser -Name $TargetUser -ErrorAction SilentlyContinue
    if (-not $user) {
        return "SKIP"
    }
    
    # First remove from Administrators group if member
    try {
        Remove-LocalGroupMember -Group "Administrators" -Member $TargetUser -ErrorAction SilentlyContinue
        Write-Host "Removed $TargetUser from Administrators group" -ForegroundColor Green
    } catch {
        # User might not be in the group
    }
    
    # Remove the user account
    Remove-LocalUser -Name $TargetUser -ErrorAction Stop
    
} -SuccessMessage "Successfully removed local user '$TargetUser' and group memberships" -SkipMessage "User '$TargetUser' does not exist, skipping removal"

# 2) Remove user profile directory and files
Invoke-UndoAction -Description "remove user profile directory for '$TargetUser'" -Action {
    $profileDir = "C:\Users\$TargetUser"
    if (-not (Test-Path $profileDir)) {
        return "SKIP"
    }
    
    # Remove the profile directory and all contents
    Remove-Item -Path $profileDir -Recurse -Force -ErrorAction Stop
    
} -SuccessMessage "Successfully removed user profile directory for '$TargetUser'" -SkipMessage "Profile directory for '$TargetUser' does not exist, skipping"

# 3) Remove firewall rule created by the script
Invoke-UndoAction -Description "remove firewall rule '$ruleName'" -Action {
    # Try multiple methods to find and remove the rule
    $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $rule) {
        # Try with netsh as backup
        $netshResult = netsh advfirewall firewall show rule name="$ruleName" 2>&1
        if ($netshResult -match "No rules match") {
            return "SKIP"
        }
    }
    
    # Remove using PowerShell method first
    try {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
    } catch {
        # Fallback to netsh
        $result = netsh advfirewall firewall delete rule name="$ruleName" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to remove firewall rule: $result"
        }
    }
    
} -SuccessMessage "Successfully removed firewall rule '$ruleName'" -SkipMessage "Firewall rule '$ruleName' does not exist, skipping removal"

# 4) Remove temporary executable files
$tempPaths = @(
    "$env:TEMP\Totally-Not-Malware.exe",
    "$env:TEMP\Totally-Not-Malware.log",
    "$env:TEMP\Totally-Not-Malware.pdb"
)

foreach ($tempPath in $tempPaths) {
    Invoke-UndoAction -Description "remove temporary file '$tempPath'" -Action {
        if (-not (Test-Path $tempPath)) {
            return "SKIP"
        }
        
        Remove-Item -Path $tempPath -Force -ErrorAction Stop
        
    } -SuccessMessage "Successfully removed temporary file '$tempPath'" -SkipMessage "Temporary file '$tempPath' does not exist, skipping"
}

# 5) Remove temporary batch files that might have been created
$tempBatchPattern = "$env:TEMP\firewall_*.bat"
Invoke-UndoAction -Description "remove temporary firewall batch files" -Action {
    $batchFiles = Get-ChildItem -Path $tempBatchPattern -ErrorAction SilentlyContinue
    if (-not $batchFiles) {
        return "SKIP"
    }
    
    foreach ($batchFile in $batchFiles) {
        Remove-Item -Path $batchFile.FullName -Force -ErrorAction SilentlyContinue
    }
    
} -SuccessMessage "Successfully removed temporary batch files" -SkipMessage "No temporary batch files found, skipping"

# 6) Remove custom event log sources (cannot remove individual events, but can remove sources)
$eventSources = @(
    "SimLabGenerator",
    "Security-Simulation", 
    "AdminActivity"
)

foreach ($source in $eventSources) {
    Invoke-UndoAction -Description "remove event log source '$source'" -Action {
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            return "SKIP"
        }
        
        # Note: This requires a restart to fully take effect
        Remove-EventLog -Source $source -ErrorAction Stop
        
    } -SuccessMessage "Successfully removed event log source '$source' (restart required for full effect)" -SkipMessage "Event log source '$source' does not exist, skipping"
}

# 7) Reset audit policies (optional)
if (-not $KeepAuditPolicies) {
    Invoke-UndoAction -Description "reset audit policies to default" -Action {
        # Reset the audit policies that were enabled by Generate-Events.ps1
        & auditpol.exe /set /category:"Account Management" /success:disable /failure:disable
        & auditpol.exe /set /category:"Policy Change" /success:disable /failure:disable  
        & auditpol.exe /set /category:"Detailed Tracking" /success:disable /failure:disable
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to reset audit policies"
        }
        
    } -SuccessMessage "Successfully reset audit policies to default (disabled)"
} else {
    Write-Host "Keeping audit policies enabled as requested (use -KeepAuditPolicies:$false to disable)" -ForegroundColor Yellow
}

# 8) Clean up any temporary XML event files that might be left behind
Invoke-UndoAction -Description "remove temporary XML event files" -Action {
    $xmlFiles = Get-ChildItem -Path "$env:TEMP\SecurityEvent_*.xml" -ErrorAction SilentlyContinue
    if (-not $xmlFiles) {
        return "SKIP"
    }
    
    foreach ($xmlFile in $xmlFiles) {
        Remove-Item -Path $xmlFile.FullName -Force -ErrorAction SilentlyContinue
    }
    
} -SuccessMessage "Successfully removed temporary XML event files" -SkipMessage "No temporary XML event files found, skipping"

# 9) Stop any processes that might still be running from the generated executable
Invoke-UndoAction -Description "stop any running 'Totally-Not-Malware' processes" -Action {
    $processes = Get-Process | Where-Object { $_.ProcessName -like "*Totally-Not-Malware*" -or $_.Path -like "*Totally-Not-Malware*" }
    if (-not $processes) {
        return "SKIP"
    }
    
    foreach ($process in $processes) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
    
} -SuccessMessage "Successfully stopped running processes" -SkipMessage "No related processes found running, skipping"

Write-Host "`nCleanup Summary:" -ForegroundColor Green
Write-Host "===============" -ForegroundColor Green

if ($WhatIf) {
    Write-Host "WHATIF MODE: No actual changes were made." -ForegroundColor Cyan
    Write-Host "Run without -WhatIf to perform the actual cleanup." -ForegroundColor Cyan
} else {
    Write-Host "✓ Removed local user account and profile" -ForegroundColor Green
    Write-Host "✓ Removed firewall rules" -ForegroundColor Green  
    Write-Host "✓ Cleaned up temporary files" -ForegroundColor Green
    Write-Host "✓ Removed custom event log sources" -ForegroundColor Green
    if (-not $KeepAuditPolicies) {
        Write-Host "✓ Reset audit policies" -ForegroundColor Green
    } else {
        Write-Host "- Kept audit policies enabled" -ForegroundColor Yellow
    }
}

Write-Host "`nNOTE: Individual log events cannot be removed programmatically." -ForegroundColor Yellow
Write-Host "Security and Application log events will remain until they expire naturally" -ForegroundColor Yellow
Write-Host "or the logs are manually cleared through Event Viewer." -ForegroundColor Yellow

if (-not $WhatIf -and $eventSources.Count -gt 0) {
    Write-Host "`nNOTE: Event log source removal requires a system restart to fully take effect." -ForegroundColor Yellow
}

Write-Host "`nCleanup complete!" -ForegroundColor Green
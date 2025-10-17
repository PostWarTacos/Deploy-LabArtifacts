# PsExec Troubleshooting Guide

## When "cmd fails to load through psexec"

### 1. **Most Common Issues:**

#### A. PsExec Not Downloaded/Installed
```powershell
# Download PsExec from Microsoft Sysinternals
# https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
# Extract psexec.exe to a folder in your PATH or current directory
```

#### B. Basic Connectivity Test
```powershell
# Test if you can reach the target at all
ping IP_ADDRESS
telnet IP_ADDRESS 445    # SMB port
telnet IP_ADDRESS 135    # RPC port
```

#### C. Firewall Blocking SMB/RPC
```powershell
# On target machine, allow these through Windows Firewall:
# - File and Printer Sharing (SMB-In)
# - Windows Management Instrumentation (WMI-In)
# Or disable Windows Firewall temporarily for testing
```

### 2. **Authentication Issues:**

#### Try Different Credential Formats:
```powershell
# Domain account
psexec \\IP -u DOMAIN\username -p password cmd

# Local account
psexec \\IP -u .\username -p password cmd
psexec \\IP -u computername\username -p password cmd

# UPN format
psexec \\IP -u username@domain.com -p password cmd
```

#### Administrator Account Issues:
```powershell
# If using built-in Administrator account, it might be disabled
# Enable it on target machine:
net user administrator /active:yes
```

### 3. **Service Dependencies:**

#### Required Services on Target:
- **Server** service (for SMB shares)
- **Remote Registry** service
- **Windows Management Instrumentation** service

```powershell
# Check/start services remotely via WMI (if WMI works):
Get-Service -ComputerName IP -Name Server,RemoteRegistry,Winmgmt
```

### 4. **Registry/Policy Issues:**

#### LocalAccountTokenFilterPolicy:
```powershell
# On target machine, this registry setting might block remote admin:
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
# LocalAccountTokenFilterPolicy = 1 (DWORD)
```

#### Admin Shares Disabled:
```powershell
# Check if admin shares are available:
# \\IP\admin$
# \\IP\c$
```

### 5. **Alternative Methods:**

#### A. Use WinRS (if WinRM is already enabled):
```powershell
winrs -r:IP -u:username -p:password "powershell Enable-PSRemoting -Force"
```

#### B. Use WMI to start services:
```powershell
# If WMI works but PsExec doesn't
$cred = Get-Credential
Invoke-CimMethod -ComputerName IP -ClassName Win32_Service -Filter "Name='WinRM'" -MethodName StartService -Credential $cred
```

#### C. Use WMIC:
```cmd
wmic /node:IP /user:username /password:password service where name="WinRM" call startservice
wmic /node:IP /user:username /password:password process call create "powershell Enable-PSRemoting -Force"
```

### 6. **Step-by-Step Troubleshooting:**

#### Step 1: Test Basic PsExec
```powershell
# Download psexec.exe to current directory first
psexec \\IP -u username -p password -accepteula cmd /c "echo test"
```

#### Step 2: If Step 1 fails, try without credentials (if on domain):
```powershell
psexec \\IP -accepteula cmd /c "echo test"
```

#### Step 3: Test with elevated privileges:
```powershell
psexec \\IP -u username -p password -h -accepteula cmd /c "echo test"
```

#### Step 4: Use hostname instead of IP:
```powershell
psexec \\COMPUTERNAME -u username -p password -accepteula cmd /c "echo test"
```

### 7. **Network Environment Considerations:**

- **Corporate Networks**: May block SMB/RPC ports
- **Cloud VMs**: Security groups might block required ports
- **Home Networks**: Router/firewall settings
- **VPN**: May not route SMB traffic properly

### 8. **Quick Alternative Script:**

If PsExec completely fails, use this PowerShell-only approach:

```powershell
# Try enabling PSRemoting via WMI/CIM only
$cred = Get-Credential
$computer = "IP_ADDRESS"

try {
    # Start WinRM service via WMI
    $service = Get-CimInstance -ComputerName $computer -ClassName Win32_Service -Filter "Name='WinRM'" -Credential $cred
    if ($service.State -ne "Running") {
        Invoke-CimMethod -InputObject $service -MethodName StartService
        Start-Sleep 2
    }
    
    # Set to automatic startup
    Invoke-CimMethod -InputObject $service -MethodName ChangeStartMode -Arguments @{StartMode="Automatic"}
    
    # Test if WinRM responds
    Test-WSMan -ComputerName $computer
    Write-Host "SUCCESS: WinRM enabled via WMI" -ForegroundColor Green
    
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
}
```
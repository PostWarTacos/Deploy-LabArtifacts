# Undo-Events.ps1 - Cleanup Script

This PowerShell script undoes all the artifacts created by `Generate-Events.ps1`. It provides a safe and thorough cleanup of the simulated attack artifacts.

## What it cleans up

The script removes the following items created by `Generate-Events.ps1`:

### User Accounts & Profiles
- Removes the created local user (default: "John.Hacksmith")
- Removes the user from the Administrators group
- Deletes the user's profile directory and all contents (`C:\Users\[username]`)

### Firewall Rules
- Removes the firewall rule created by the script (default: "Definitely-Not-Malicious")
- Works with both netsh and PowerShell methods

### Files & Executables
- Removes `Totally-Not-Malware.exe` and related files from temp directory
- Cleans up temporary batch files used for firewall creation
- Removes temporary XML event files
- Stops any running processes from the generated executable

### Event Log Sources
- Removes custom event log sources:
  - `SimLabGenerator`
  - `Security-Simulation` 
  - `AdminActivity`

### Audit Policies
- Optionally resets audit policies to default (disabled) state
- Can keep policies enabled with `-KeepAuditPolicies` parameter

## Usage

### Basic Usage (Administrator Required)
```powershell
# Run with default parameters
.\Undo-Events.ps1

# Preview what would be done without making changes
.\Undo-Events.ps1 -WhatIf
```

### Advanced Usage
```powershell
# Clean up specific user and firewall rule
.\Undo-Events.ps1 -TargetUser "John.Hacksmith" -ruleName "Definitely-Not-Malicious"

# Keep audit policies enabled
.\Undo-Events.ps1 -KeepAuditPolicies

# Preview cleanup for custom parameters
.\Undo-Events.ps1 -TargetUser "CustomUser" -ruleName "CustomRule" -WhatIf
```

## Parameters

- **`-TargetUser`** (string): Name of the user account to remove (default: "John.Hacksmith")
- **`-ruleName`** (string): Name of the firewall rule to remove (default: "Definitely-Not-Malicious") 
- **`-KeepAuditPolicies`** (switch): Keep audit policies enabled instead of resetting them
- **`-WhatIf`** (switch): Show what would be done without making actual changes

## Important Notes

### Administrator Rights Required
This script must be run as Administrator to perform cleanup operations.

### Log Events Cannot Be Removed
Individual Security and Application log events created by `Generate-Events.ps1` cannot be programmatically removed. These events will remain until they expire naturally or the logs are manually cleared through Event Viewer.

### Event Source Removal
Removing custom event log sources requires a system restart to fully take effect.

### Safe Operation
The script includes error handling and will skip operations for items that don't exist, making it safe to run multiple times.

## Examples

### Complete Cleanup
```powershell
# Remove everything including audit policies
.\Undo-Events.ps1
```

### Forensics Lab Cleanup
```powershell
# Keep audit policies for continued monitoring
.\Undo-Events.ps1 -KeepAuditPolicies
```

### Preview Mode
```powershell
# See what would be cleaned up
.\Undo-Events.ps1 -WhatIf
```

### Custom Parameters
```powershell
# Clean up custom user and rule names
.\Undo-Events.ps1 -TargetUser "Alice.Smith" -ruleName "Custom-Rule-Name"
```

## Verification

After running the script, you can verify the cleanup by checking:

1. **User Account**: `Get-LocalUser` - should not list the target user
2. **Firewall Rules**: `Get-NetFirewallRule` or `netsh advfirewall firewall show rule all`
3. **Temp Files**: Check `$env:TEMP` directory for remaining artifacts
4. **Event Sources**: Event Viewer > Windows Logs > Application (custom sources should be gone after restart)
5. **Audit Policies**: `auditpol /get /category:*` (if reset option used)

## Troubleshooting

If the script fails to remove certain items:
1. Ensure you're running as Administrator
2. Check if any processes are using the files (use `Get-Process`)
3. Restart the system if event log sources persist
4. Manually remove stubborn files through File Explorer with Administrator rights

The script is designed to be robust and will continue with other cleanup tasks even if individual operations fail.
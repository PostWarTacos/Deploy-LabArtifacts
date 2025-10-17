# Enable-PSRemoting-Remotely.ps1

This small helper attempts to enable PowerShell Remoting (WinRM) on one or more remote Windows hosts using several safe, idempotent methods.

Usage examples

- Interactive credential prompt:

    .\Enable-PSRemoting-Remotely.ps1 -ComputerName server01,server02 -Credential (Get-Credential)

- Use current credentials (run elevated where needed):

    .\Enable-PSRemoting-Remotely.ps1 -ComputerName 192.168.1.50

Notes and requirements

- Run from an elevated PowerShell session on a machine that can reach the target hosts.
- You must have administrative privileges on the remote machine(s).
- For domain environments, enabling WinRM and firewall rules via Group Policy (preferred) scales better.

What the script does

- Checks whether WinRM already responds (Test-WSMan). If so, it skips the host.
- Attempts Enable-PSRemoting via Invoke-Command when possible.
- Attempts to start/configure the WinRM service via CIM/WMI if Invoke-Command isn't available.
- Attempts to create firewall rules for WSMan (TCP 5985/5986) remotely as needed.

Troubleshooting

- If the script fails on many hosts, check network connectivity and whether RPC/SMB or WinRM ports are reachable.
- Use Group Policy to enable WinRM and firewall rules if you manage the hosts centrally.
- For isolated cases, run Enable-PSRemoting locally on-console or use a remote execution tool (PSExec) with care.

Security

- Enabling PSRemoting opens administrative remote management — ensure only trusted admin accounts have access.
- Prefer Kerberos/Negotiate authentication in domain environments; avoid using basic auth over HTTP unless behind secure tunnels.

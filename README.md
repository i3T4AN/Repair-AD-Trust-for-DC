# AD Broken-Trust Audit Script

This PowerShell script queries Active Directory computers, filters them by enabled/disabled status and recent activity, then remotely tests domain trust using `Test-ComputerSecureChannel`. It can optionally attempt an automatic repair (`-AutoRepair`). When exporting, it generates **two** reports from one base output name:
- `_Total_List` = everything that failed the trust check (Broken + Unreachable)
- `_Failed_rebind` = everything still unresolved after repair attempts (plus Unreachable)

## Requirements
- Windows with the **ActiveDirectory** PowerShell module  
  - Windows 10/11: install RSAT (Active Directory module) via Optional Features  
  - Windows Server: `Install-WindowsFeature -Name RSAT-AD-PowerShell`  
- WinRM access to endpoints for best results (unreachable endpoints are still reported)
- PowerShell execution policy that allows scripts (`RemoteSigned` or `Bypass`)

## Usage
.\Find-BrokenTrust.ps1 [parameters]

### Parameters
- `-Domain <string>` — Domain name (default: current domain)
- `-Server <string>` — Domain Controller / ADWS endpoint for AD queries (DC FQDN, name, or IP)
- `-SearchBase <string>` — LDAP distinguished name to scope the search
- `-IncludeDisabled` — Include disabled computer accounts
- `-StaleDays <int>` — Days of inactivity cutoff (default: 180, range: 1–365)
- `-OutputFile <path>` — Base CSV output path (script will create two files with suffixes)
- `-Credential <pscredential>` — Alternate credential for remoting (optional)
- `-OperationTimeoutSec <int>` — Per remote operation timeout (default: 10)
- `-SessionTimeoutSec <int>` — Remote session open timeout (default: 20)
- `-ThrottleLimit <int>` — Remoting throttle hint (default: 24)
- `-PingFirst` — Pre-filter by ICMP ping (faster, but misses ICMP-blocked hosts)
- `-AutoRepair` — Attempt `Test-ComputerSecureChannel -Repair` on reachable broken-trust machines, then re-test

## Examples
List enabled, active computers with broken/unreachable trust (no CSV):  
`.\Find-BrokenTrust.ps1`

Target a specific domain:  
`.\Find-BrokenTrust.ps1 -Domain example.org`

Force a specific DC for the AD query:  
`.\Find-BrokenTrust.ps1 -Server dc01.example.org`

Limit to an OU:  
`.\Find-BrokenTrust.ps1 -SearchBase "DC=example,DC=org"`

Include disabled accounts and extend inactivity window:  
`.\Find-BrokenTrust.ps1 -IncludeDisabled -StaleDays 365`

Export reports (two files):  
`.\Find-BrokenTrust.ps1 -OutputFile "C:\Reports\broken-trust.csv"`

Export + attempt auto-repair:  
`.\Find-BrokenTrust.ps1 -AutoRepair -OutputFile "C:\Reports\broken-trust.csv"`

Full example (sanitized):  
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; .\Find-BrokenTrust.ps1 -Domain example.org -Server dc01.example.org -SearchBase "DC=example,DC=org" -AutoRepair -OutputFile "C:\Reports\broken-trust.csv"`

Use alternate creds for WinRM:  
`$cred = Get-Credential; .\Find-BrokenTrust.ps1 -Credential $cred -AutoRepair -OutputFile "C:\Reports\broken-trust.csv"`

## Output

### Console
- Returns objects to the pipeline when `-OutputFile` is not provided (defaults to the unresolved list)

### CSV Reports
If `-OutputFile` is specified, the script generates:

1) **Total list** (everything that failed initial trust or was unreachable)  
`<base>_Total_List.csv`

2) **Failed rebind** (still broken after repair attempts + unreachable)  
`<base>_Failed_rebind.csv`

### Columns
Both reports include:
- Name
- DNSHostName
- SerialNumber
- OperatingSystem
- LastLogonDate (`yyyy-MM-dd HH:mm:ss` or `Never`)
- PasswordLastSet (`yyyy-MM-dd HH:mm:ss` or `Never`)
- CanonicalName
- TrustStatus (`Broken` or `Unreachable`)
- Error (reason for unreachable / remoting failure)
- RepairAttempted
- RepairResult
- TrustOkAfter
- RepairMessage

## Notes
- If you see `running scripts is disabled`, allow scripts for the session:  
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
- AD timestamps are normalized: `LastLogonDate` preferred, fallback to `LastLogonTimestamp`.
- “Unreachable” is intentional: offline / WinRM disabled / firewall / auth failures still need follow-up.
- Auto-repair is only attempted for machines marked `Broken` (reachable). `Unreachable` cannot be repaired via WinRM and is carried into the unresolved report.

## What changed from the original script
- Kept your AD query + stale filtering intact (same structure, same normalized time handling).
- Added DC targeting (`-Server`) so AD queries can be pinned to a specific controller.
- Added a remote trust test loop:
  - `Invoke-Command` runs `Test-ComputerSecureChannel`
  - Same remote call also pulls BIOS serial via CIM
- Added optional auto-repair (`-AutoRepair`) for reachable broken-trust machines, with a post-repair re-test.
- Export behavior changed from “single inventory CSV” to **two actionable reports**:
  - `_Total_List` (all failures)
  - `_Failed_rebind` (still unresolved after repair)

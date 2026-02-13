
---

## Find-BrokenTrust.ps1
## Ethan Blair
## 2/13/26
## Code Review by: 
```powershell
[CmdletBinding()]
param(
    [Parameter()]
    [string]$Domain = (Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot,

    [Parameter()]
    [Alias('DC','DomainController')]
    [string]$Server,

    [Parameter()]
    [string]$GlobalCatalog,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [ValidateRange(1,365)]
    [int]$StaleDays = 180,

    [Parameter()]
    [ValidateRange(1,600)]
    [int]$OperationTimeoutSec = 10,

    [Parameter()]
    [ValidateRange(1,600)]
    [int]$SessionTimeoutSec = 20,

    [Parameter()]
    [ValidateRange(1,256)]
    [int]$ThrottleLimit = 24,

    [Parameter()]
    [switch]$PingFirst,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [switch]$AutoRepair,

    [Parameter()]
    [ValidateScript({
        if ($_ -eq '') { return $true }
        $parent = Split-Path $_ -Parent
        if ($parent -and !(Test-Path $parent)) { throw "Directory '$parent' does not exist" }
        return $true
    })]
    [string]$OutputFile
)

function Convert-AdTime {
    param([Parameter(ValueFromPipeline=$true)] $Value)
    process {
        if ($null -eq $Value) { return $null }
        try {
            if ($Value -is [datetime]) {
                if ($Value.Year -le 1601) { return $null }
                return [datetime]$Value
            }
            if ($Value -is [int64] -or $Value -is [uint64]) {
                if ([int64]$Value -le 0) { return $null }
                return [datetime]::FromFileTime([int64]$Value)
            }
            $d = [datetime]$Value
            if ($d.Year -le 1601) { return $null }
            return $d
        } catch { return $null }
    }
}

function Resolve-AdServer {
    param([string]$Domain, [string]$Server, [string]$GlobalCatalog)
    if ($GlobalCatalog) { return $GlobalCatalog }
    if ($Server) { return $Server }
    if ($Domain) { return $Domain }
    throw "Unable to determine AD Server/DC. Provide -Server (recommended) or -Domain."
}

function Get-OutputPaths {
    param([string]$OutputFile)
    if (-not $OutputFile) { return $null }

    $dir  = Split-Path $OutputFile -Parent
    $base = [System.IO.Path]::GetFileNameWithoutExtension($OutputFile)
    $ext  = [System.IO.Path]::GetExtension($OutputFile)
    if (-not $ext) { $ext = ".csv" }

    [pscustomobject]@{
        Total  = (Join-Path $dir ("{0}_Total_List{1}" -f $base, $ext))
        Failed = (Join-Path $dir ("{0}_Failed_rebind{1}" -f $base, $ext))
    }
}

try {
    if (!(Get-Module -Name ActiveDirectory -ListAvailable)) {
        throw "ActiveDirectory module not found (RSAT AD PowerShell required)."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Failed to load ActiveDirectory module: $_"
    exit 1
}

$adServer = Resolve-AdServer -Domain $Domain -Server $Server -GlobalCatalog $GlobalCatalog
Write-Verbose "AD query target (-Server): $adServer"

$ldapFilter = "(&(objectCategory=computer)(dNSHostName=*))"
$staleDate  = (Get-Date).AddDays(-$StaleDays)

$getADComputerParams = @{
    LDAPFilter = $ldapFilter
    Server     = $adServer
    Properties = @(
        'DNSHostName','Enabled','OperatingSystem',
        'LastLogonTimestamp','LastLogonDate','PasswordLastSet','CanonicalName'
    )
}
if ($SearchBase) { $getADComputerParams['SearchBase'] = $SearchBase }

try {
    $allComputers = Get-ADComputer @getADComputerParams -ErrorAction Stop | ForEach-Object {
        $ll  = Convert-AdTime $_.LastLogonDate
        if (-not $ll) { $ll = Convert-AdTime $_.LastLogonTimestamp }
        $pls = Convert-AdTime $_.PasswordLastSet

        [PSCustomObject]@{
            Name            = $_.Name
            DNSHostName     = $_.DNSHostName
            Enabled         = $_.Enabled
            OperatingSystem = $_.OperatingSystem
            LastLogonDate   = $ll
            PasswordLastSet = $pls
            CanonicalName   = $_.CanonicalName
        }
    }
} catch {
    Write-Error "Failed to query Active Directory (Server=$adServer): $_"
    exit 1
}

if (!$IncludeDisabled) {
    $computers = $allComputers | Where-Object { $_.Enabled -eq $true }
    $computers = $computers | Where-Object {
        ($null -ne $_.LastLogonDate -and $_.LastLogonDate -ge $staleDate) -or
        ($null -eq $_.LastLogonDate -and $null -ne $_.PasswordLastSet -and $_.PasswordLastSet -ge $staleDate)
    }
} else {
    $computers = $allComputers
}

$computers = @($computers)
Write-Verbose "Candidate computers: $($computers.Count)"

$sessionOpt = New-PSSessionOption -OperationTimeout ($OperationTimeoutSec * 1000) -OpenTimeout ($SessionTimeoutSec * 1000)

$sbCheck = {
    $trust = $null
    try { $trust = Test-ComputerSecureChannel -Verbose:$false }
    catch { $trust = $false }

    $serial = $null
    try { $serial = (Get-CimInstance Win32_BIOS -ErrorAction Stop).SerialNumber }
    catch { $serial = $null }

    [pscustomobject]@{
        TrustOk      = [bool]$trust
        SerialNumber = $serial
        UtcNow       = [datetime]::UtcNow
    }
}

$sbRepair = {
    $repaired = $null
    $postOk   = $null
    $msg      = $null

    try {
        $repaired = Test-ComputerSecureChannel -Repair -Verbose:$false
    } catch {
        $repaired = $false
        $msg = $_.Exception.Message
    }

    try {
        $postOk = Test-ComputerSecureChannel -Verbose:$false
    } catch {
        $postOk = $false
        if (-not $msg) { $msg = $_.Exception.Message }
    }

    [pscustomobject]@{
        RepairAttempted = $true
        RepairResult    = [bool]$repaired
        TrustOkAfter    = [bool]$postOk
        Message         = $msg
        UtcNow          = [datetime]::UtcNow
    }
}

$icmCommon = @{
    ErrorAction    = 'Stop'
    SessionOption  = $sessionOpt
    ThrottleLimit  = $ThrottleLimit
}
if ($Credential) { $icmCommon['Credential'] = $Credential }

if ($PingFirst) {
    Write-Verbose "PingFirst enabled: pre-filtering by Test-Connection -Quiet"
    $computers = $computers | Where-Object {
        try { Test-Connection -ComputerName $_.DNSHostName -Count 1 -Quiet -ErrorAction Stop }
        catch { $false }
    }
    $computers = @($computers)
    Write-Verbose "After ping filter: $($computers.Count)"
}

$totalList  = New-Object System.Collections.Generic.List[object]
$failedList = New-Object System.Collections.Generic.List[object]
$fixedList  = New-Object System.Collections.Generic.List[object]

foreach ($comp in $computers) {
    $trustOk = $null
    $serial  = $null
    $status  = $null
    $errText = $null

    try {
        $remote = Invoke-Command -ComputerName $comp.DNSHostName -ScriptBlock $sbCheck @icmCommon
        $trustOk = [bool]$remote.TrustOk
        $serial  = $remote.SerialNumber
        $status  = if ($trustOk) { 'OK' } else { 'Broken' }
    }
    catch {
        $trustOk = $false
        $serial  = $null
        $status  = 'Unreachable'
        $errText = $_.Exception.Message
    }

    if (-not $trustOk) {
        $row = [PSCustomObject]@{
            Name            = $comp.Name
            DNSHostName     = $comp.DNSHostName
            SerialNumber    = if ($serial) { $serial } else { 'Unknown' }
            OperatingSystem = $comp.OperatingSystem
            LastLogonDate   = $comp.LastLogonDate
            PasswordLastSet = $comp.PasswordLastSet
            CanonicalName   = $comp.CanonicalName
            TrustStatus     = $status
            Error           = $errText
            RepairAttempted = $false
            RepairResult    = $null
            TrustOkAfter    = $null
            RepairMessage   = $null
        }

        $totalList.Add($row)

        if ($AutoRepair -and $status -eq 'Broken') {
            try {
                $rep = Invoke-Command -ComputerName $comp.DNSHostName -ScriptBlock $sbRepair @icmCommon
                $row.RepairAttempted = $true
                $row.RepairResult    = [bool]$rep.RepairResult
                $row.TrustOkAfter    = [bool]$rep.TrustOkAfter
                $row.RepairMessage   = $rep.Message

                if ($row.TrustOkAfter) {
                    $fixedList.Add($row)
                } else {
                    $failedList.Add($row)
                }
            }
            catch {
                $row.RepairAttempted = $true
                $row.RepairResult    = $false
                $row.TrustOkAfter    = $false
                $row.RepairMessage   = $_.Exception.Message
                $failedList.Add($row)
            }
        }
        else {
            $failedList.Add($row)
        }
    }
}

if ($OutputFile) {
    $paths = Get-OutputPaths -OutputFile $OutputFile

    $selectCols = @(
        'Name','DNSHostName','SerialNumber','OperatingSystem',
        @{Name='LastLogonDate';Expression={ if ($_.LastLogonDate) { $_.LastLogonDate.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' } }},
        @{Name='PasswordLastSet';Expression={ if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' } }},
        'CanonicalName','TrustStatus','Error','RepairAttempted','RepairResult','TrustOkAfter','RepairMessage'
    )

    $totalList  | Select-Object $selectCols | Export-Csv -Path $paths.Total  -NoTypeInformation -Encoding UTF8
    $failedList | Select-Object $selectCols | Export-Csv -Path $paths.Failed -NoTypeInformation -Encoding UTF8

    Write-Verbose "Exported total failed list to: $($paths.Total)"
    Write-Verbose "Exported failed rebind list to: $($paths.Failed)"
}
else {
    $failedList
}

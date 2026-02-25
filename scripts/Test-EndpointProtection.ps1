<#
.SYNOPSIS
    Validates that endpoint protection is active and healthy.

.DESCRIPTION
    Checks the state of endpoint protection on the local machine:
    - Service running status
    - Real-time protection enabled
    - Definition/signature freshness
    - Security Center registration
    - Tamper protection status (Defender)

    Use this before AND after removing a legacy agent to confirm no protection gap.

.PARAMETER ExpectedProduct
    Name of the product you expect to be active (e.g., "CrowdStrike", "Windows Defender").
    If specified, the check fails unless this product is found and running.

.PARAMETER MaxDefinitionAgeDays
    Maximum acceptable age for virus definitions in days. Default: 7.

.PARAMETER LogPath
    Path to a log file.

.EXAMPLE
    .\Test-EndpointProtection.ps1
    Basic health check of whatever protection is installed.

.EXAMPLE
    .\Test-EndpointProtection.ps1 -ExpectedProduct "Windows Defender" -MaxDefinitionAgeDays 3
    Verifies Defender is active with definitions no older than 3 days.

.NOTES
    Author: Inventive HQ (https://inventivehq.com)
    License: MIT
#>

[CmdletBinding()]
param(
    [string]$ExpectedProduct,
    [int]$MaxDefinitionAgeDays = 7,
    [string]$LogPath
)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Host $entry
    if ($LogPath) {
        $entry | Out-File -FilePath $LogPath -Append -Encoding UTF8
    }
}

function Write-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail = "")
    $icon = if ($Passed) { "PASS" } else { "FAIL" }
    $level = if ($Passed) { "INFO" } else { "WARN" }
    $msg = "[$icon] $Name"
    if ($Detail) { $msg += " - $Detail" }
    Write-Log $msg -Level $level
    return $Passed
}

$results = @()

Write-Log "Endpoint Protection Health Check"
Write-Log "================================="
Write-Log "Computer: $env:COMPUTERNAME"
Write-Log "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
if ($ExpectedProduct) { Write-Log "Expected product: $ExpectedProduct" }
Write-Log ""

# Check 1: Security Center registration
Write-Log "--- Security Center ---"
$securityProducts = @()
try {
    $securityProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    if ($securityProducts.Count -gt 0) {
        foreach ($product in $securityProducts) {
            $enabled = ($product.productState -band 0x1000) -ne 0
            $upToDate = ($product.productState -band 0x10) -eq 0
            Write-Log "  Found: $($product.displayName) | Active: $enabled | Up-to-date: $upToDate"
        }
        $results += Write-Check -Name "Security Center" -Passed $true -Detail "$($securityProducts.Count) product(s) registered"
    } else {
        $results += Write-Check -Name "Security Center" -Passed $false -Detail "No AV products registered"
    }
} catch {
    Write-Log "  SecurityCenter2 not available (expected on Server OS)."
}

# Check 2: Expected product present
if ($ExpectedProduct) {
    Write-Log ""
    Write-Log "--- Expected Product: $ExpectedProduct ---"
    $found = $false

    # Check Security Center
    $scMatch = $securityProducts | Where-Object { $_.displayName -like "*$ExpectedProduct*" }
    if ($scMatch) { $found = $true }

    # Check services for common products
    $serviceMap = @{
        'CrowdStrike'    = 'CSFalconService'
        'SentinelOne'    = 'SentinelAgent'
        'Sophos'         = 'Sophos Endpoint Defense Service'
        'Carbon Black'   = 'CbDefense'
        'Trend Micro'    = 'Ntrtscan'
        'ESET'           = 'ekrn'
        'Symantec'       = 'SepMasterService'
        'Malwarebytes'   = 'MBAMService'
        'Webroot'        = 'WRSVC'
        'Cylance'        = 'CylanceSvc'
        'Defender'       = 'WinDefend'
        'Windows Defender' = 'WinDefend'
    }

    foreach ($key in $serviceMap.Keys) {
        if ($ExpectedProduct -like "*$key*") {
            $svc = Get-Service -Name $serviceMap[$key] -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                $found = $true
                Write-Log "  Service $($serviceMap[$key]) is running."
            }
            break
        }
    }

    $results += Write-Check -Name "Expected product ($ExpectedProduct)" -Passed $found -Detail $(if ($found) { "Found and active" } else { "NOT FOUND — protection gap!" })
}

# Check 3: Windows Defender status (detailed)
Write-Log ""
Write-Log "--- Windows Defender Status ---"
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop

    $rtEnabled = $mpStatus.RealTimeProtectionEnabled
    $results += Write-Check -Name "Real-time protection" -Passed $rtEnabled -Detail $(if ($rtEnabled) { "Enabled" } else { "DISABLED" })

    $tamperEnabled = $mpStatus.IsTamperProtected
    if ($null -ne $tamperEnabled) {
        Write-Log "  Tamper protection: $(if ($tamperEnabled) { 'Enabled' } else { 'Disabled' })"
    }

    # Definition age
    $sigDate = $mpStatus.AntivirusSignatureLastUpdated
    if ($sigDate) {
        $sigAge = (New-TimeSpan -Start $sigDate -End (Get-Date)).Days
        $sigFresh = $sigAge -le $MaxDefinitionAgeDays
        $results += Write-Check -Name "Definition freshness" -Passed $sigFresh -Detail "$sigAge days old (max: $MaxDefinitionAgeDays) — updated $($sigDate.ToString('yyyy-MM-dd'))"
    }

    # Engine version
    Write-Log "  Engine version: $($mpStatus.AMEngineVersion)"
    Write-Log "  Signature version: $($mpStatus.AntivirusSignatureVersion)"

    # Cloud protection
    $cloudEnabled = $mpStatus.MAPSReporting -ne 0
    Write-Log "  Cloud protection: $(if ($cloudEnabled) { 'Enabled' } else { 'Disabled' })"

    # Behavior monitoring
    $behaviorEnabled = $mpStatus.BehaviorMonitorEnabled
    $results += Write-Check -Name "Behavior monitoring" -Passed $behaviorEnabled -Detail $(if ($behaviorEnabled) { "Enabled" } else { "Disabled" })

} catch {
    Write-Log "  Windows Defender cmdlets not available: $($_.Exception.Message)"
    Write-Log "  This is expected if a third-party AV is the primary product."
}

# Check 4: MDE (Defender for Endpoint) SENSE service
Write-Log ""
Write-Log "--- Defender for Endpoint (MDE) ---"
$senseSvc = Get-Service -Name 'SENSE' -ErrorAction SilentlyContinue
if ($senseSvc) {
    $senseRunning = $senseSvc.Status -eq 'Running'
    $results += Write-Check -Name "MDE SENSE service" -Passed $senseRunning -Detail $senseSvc.Status.ToString()
} else {
    Write-Log "  MDE (SENSE) not installed — this is normal for non-MDE environments."
}

# Check 5: No conflicting/orphaned agents
Write-Log ""
Write-Log "--- Agent Conflicts ---"
$runningAgents = @()
$agentServices = @{
    'CSFalconService' = 'CrowdStrike'
    'SentinelAgent'   = 'SentinelOne'
    'SAVService'      = 'Sophos'
    'CbDefense'       = 'Carbon Black'
    'Ntrtscan'        = 'Trend Micro'
    'ekrn'            = 'ESET'
    'SepMasterService' = 'Symantec'
    'MBAMService'     = 'Malwarebytes'
    'WRSVC'           = 'Webroot'
    'CylanceSvc'      = 'Cylance'
    'WinDefend'       = 'Windows Defender'
}

foreach ($svcName in $agentServices.Keys) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        $runningAgents += $agentServices[$svcName]
    }
}

# Exclude Defender from conflict count (it's always there)
$thirdPartyAgents = $runningAgents | Where-Object { $_ -ne 'Windows Defender' }

if ($thirdPartyAgents.Count -gt 1) {
    $results += Write-Check -Name "Agent conflicts" -Passed $false -Detail "Multiple agents running: $($runningAgents -join ', '). This can cause performance issues."
} elseif ($thirdPartyAgents.Count -eq 1) {
    $results += Write-Check -Name "Agent conflicts" -Passed $true -Detail "Single agent: $($thirdPartyAgents[0]) (+ Defender passive mode)"
} else {
    $results += Write-Check -Name "Agent conflicts" -Passed $true -Detail "Only Windows Defender running"
}

# Summary
$passed = ($results | Where-Object { $_ -eq $true }).Count
$failed = ($results | Where-Object { $_ -eq $false }).Count
$total = $results.Count

Write-Log ""
Write-Log "========================================="
Write-Log "Health Check Summary"
Write-Log "========================================="
Write-Log "Passed: $passed / $total"

if ($failed -gt 0) {
    Write-Log "Failed: $failed" -Level "WARN"
    Write-Log ""
    Write-Log "Action required:" -Level "WARN"
    if ($ExpectedProduct -and -not ($results | Select-Object -Last 1)) {
        Write-Log "  - Expected product '$ExpectedProduct' is not active" -Level "WARN"
    }
    Write-Log "  - Review failed checks above and address before proceeding" -Level "WARN"
    exit 1
} else {
    Write-Log ""
    Write-Log "Endpoint protection is healthy."
    exit 0
}

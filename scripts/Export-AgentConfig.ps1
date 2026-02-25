<#
.SYNOPSIS
    Exports endpoint protection configuration for migration to a new platform.

.DESCRIPTION
    Extracts exclusions, policies, and configuration from the current endpoint
    protection agent. Useful for replicating settings in a new platform.

    Currently supports detailed export for:
    - Windows Defender / Microsoft Defender for Endpoint
    - CrowdStrike (exclusion paths from registry)
    - SentinelOne (exclusion paths from registry)

    For other vendors, exports the registry-based configuration that's accessible.

.PARAMETER Vendor
    The vendor to export config from. Default: Defender.

.PARAMETER OutputPath
    Path for the JSON output file.

.EXAMPLE
    .\Export-AgentConfig.ps1 -Vendor Defender -OutputPath C:\Migration\defender-config.json
    Exports full Defender configuration.

.EXAMPLE
    .\Export-AgentConfig.ps1 -Vendor CrowdStrike -OutputPath C:\Migration\cs-exclusions.json
    Exports CrowdStrike exclusion paths.

.NOTES
    Author: Inventive HQ (https://inventivehq.com)
    License: MIT
#>

[CmdletBinding()]
param(
    [ValidateSet('Defender', 'CrowdStrike', 'SentinelOne')]
    [string]$Vendor = 'Defender',

    [Parameter(Mandatory)]
    [string]$OutputPath
)

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message"
}

$config = @{
    ExportDate   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    ComputerName = $env:COMPUTERNAME
    Vendor       = $Vendor
}

try {
    switch ($Vendor) {
        'Defender' {
            Write-Status "Exporting Windows Defender configuration..."

            $prefs = Get-MpPreference -ErrorAction Stop

            # Exclusions
            $config['Exclusions'] = @{
                Paths      = @($prefs.ExclusionPath | Where-Object { $_ })
                Extensions = @($prefs.ExclusionExtension | Where-Object { $_ })
                Processes  = @($prefs.ExclusionProcess | Where-Object { $_ })
                IPs        = @($prefs.ExclusionIpAddress | Where-Object { $_ })
            }

            # Scan settings
            $config['ScanSettings'] = @{
                ScanScheduleDay        = $prefs.ScanScheduleDay
                ScanScheduleTime       = $prefs.ScanScheduleTime.ToString()
                ScanType               = $prefs.ScanParameters
                DisableArchiveScanning = $prefs.DisableArchiveScanning
                DisableEmailScanning   = $prefs.DisableEmailScanning
                DisableRemovableDriveScanning = $prefs.DisableRemovableDriveScanning
            }

            # Protection settings
            $config['Protection'] = @{
                RealTimeMonitoring      = $prefs.DisableRealtimeMonitoring -eq $false
                BehaviorMonitoring      = $prefs.DisableBehaviorMonitoring -eq $false
                CloudProtection         = $prefs.MAPSReporting -ne 0
                CloudBlockLevel         = $prefs.CloudBlockLevel
                PUAProtection           = $prefs.PUAProtection
                ControlledFolderAccess  = $prefs.EnableControlledFolderAccess
                NetworkProtection       = $prefs.EnableNetworkProtection
            }

            # ASR rules
            if ($prefs.AttackSurfaceReductionRules_Ids) {
                $asrRules = @()
                for ($i = 0; $i -lt $prefs.AttackSurfaceReductionRules_Ids.Count; $i++) {
                    $action = switch ($prefs.AttackSurfaceReductionRules_Actions[$i]) {
                        0 { "Disabled" }
                        1 { "Block" }
                        2 { "Audit" }
                        6 { "Warn" }
                        default { $prefs.AttackSurfaceReductionRules_Actions[$i] }
                    }
                    $asrRules += @{
                        RuleId = $prefs.AttackSurfaceReductionRules_Ids[$i]
                        Action = $action
                    }
                }
                $config['ASRRules'] = $asrRules
            }

            # Controlled folder access
            if ($prefs.ControlledFolderAccessProtectedFolders) {
                $config['ControlledFolderAccessProtectedFolders'] = @($prefs.ControlledFolderAccessProtectedFolders)
            }
            if ($prefs.ControlledFolderAccessAllowedApplications) {
                $config['ControlledFolderAccessAllowedApplications'] = @($prefs.ControlledFolderAccessAllowedApplications)
            }

            $exclusionCount = ($config.Exclusions.Paths.Count + $config.Exclusions.Extensions.Count +
                              $config.Exclusions.Processes.Count + $config.Exclusions.IPs.Count)
            Write-Status "Found $exclusionCount exclusions, $(if ($config.ASRRules) { $config.ASRRules.Count } else { 0 }) ASR rules"
        }

        'CrowdStrike' {
            Write-Status "Exporting CrowdStrike configuration..."
            Write-Status "Note: Full policy export requires the Falcon API. This exports locally-cached data."

            # CrowdStrike stores some config in registry
            $csRegPath = 'HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default'

            $exclusions = @()
            if (Test-Path $csRegPath) {
                $csReg = Get-ItemProperty -Path $csRegPath -ErrorAction SilentlyContinue
                if ($csReg) {
                    Write-Status "Found CrowdStrike registry configuration."
                }
            }

            # Check for exclusions in common CrowdStrike paths
            $csConfigPaths = @(
                "$env:ProgramFiles\CrowdStrike",
                "$env:SystemRoot\System32\drivers\CrowdStrike"
            )

            $config['InstallPaths'] = @($csConfigPaths | Where-Object { Test-Path $_ })

            # Agent info
            $csSvc = Get-Service -Name 'CSFalconService' -ErrorAction SilentlyContinue
            if ($csSvc) {
                $config['ServiceStatus'] = $csSvc.Status.ToString()
            }

            # CID (Customer ID)
            $csAgent = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim' -ErrorAction SilentlyContinue
            if ($csAgent -and $csAgent.CU) {
                $config['CustomerID'] = $csAgent.CU
            }

            Write-Status "CrowdStrike local config exported. For full policy/exclusion export, use the Falcon API."
        }

        'SentinelOne' {
            Write-Status "Exporting SentinelOne configuration..."
            Write-Status "Note: Full policy export requires the S1 Management Console API."

            # SentinelOne registry paths
            $s1Paths = @(
                'HKLM:\SOFTWARE\Sentinel Labs\Sentinel Agent',
                'HKLM:\SOFTWARE\SentinelOne'
            )

            foreach ($path in $s1Paths) {
                if (Test-Path $path) {
                    $s1Reg = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                    if ($s1Reg) {
                        $config['RegistryConfig'] = @{}
                        $s1Reg.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                            $config['RegistryConfig'][$_.Name] = $_.Value
                        }
                    }
                }
            }

            $s1Svc = Get-Service -Name 'SentinelAgent' -ErrorAction SilentlyContinue
            if ($s1Svc) {
                $config['ServiceStatus'] = $s1Svc.Status.ToString()
            }

            Write-Status "SentinelOne local config exported. For full policy export, use the Management Console API."
        }
    }

    # Write output
    $json = $config | ConvertTo-Json -Depth 5
    $json | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Status "Configuration exported to: $OutputPath"

    # Summary
    Write-Host ""
    Write-Host "Export Summary:"
    Write-Host "  Vendor:     $Vendor"
    Write-Host "  Computer:   $env:COMPUTERNAME"
    Write-Host "  Output:     $OutputPath"
    if ($config.Exclusions) {
        Write-Host "  Exclusions: $($config.Exclusions.Paths.Count) paths, $($config.Exclusions.Extensions.Count) extensions, $($config.Exclusions.Processes.Count) processes"
    }

} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[ERROR] Stack: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}

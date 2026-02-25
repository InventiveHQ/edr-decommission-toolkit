<#
.SYNOPSIS
    Removes a legacy EDR/AV agent with tamper protection handling.

.DESCRIPTION
    Handles the full removal workflow for common endpoint protection products:
    1. Verifies the vendor is recognized
    2. Checks if another protection agent is active (safety check)
    3. Attempts to disable tamper protection using the provided token
    4. Runs the vendor-specific uninstall command
    5. Cleans up orphaned services and files
    6. Verifies removal

    Requires elevation (Run as Administrator).

    IMPORTANT: Always verify your NEW agent is deployed and active BEFORE
    running this script. Use Test-EndpointProtection.ps1 first.

.PARAMETER Vendor
    The vendor/product to remove. Supported: CrowdStrike, SentinelOne, Sophos,
    CarbonBlack, TrendMicro, ESET, Symantec, Malwarebytes, Webroot, Cylance.

.PARAMETER UninstallToken
    The tamper protection / uninstall token from the vendor console.
    Required for CrowdStrike, SentinelOne, and others with tamper protection.

.PARAMETER Unattended
    Skip confirmation prompts. Use for mass deployment via SCCM/Intune/GPO.

.PARAMETER SkipSafetyCheck
    Skip the check for active replacement protection. Use only in lab environments.

.PARAMETER LogPath
    Path to a log file.

.EXAMPLE
    .\Remove-LegacyAgent.ps1 -Vendor CrowdStrike -UninstallToken "ABCD1234"
    Removes CrowdStrike Falcon with the provided maintenance token.

.EXAMPLE
    .\Remove-LegacyAgent.ps1 -Vendor Sophos -Unattended -LogPath C:\Logs\removal.log
    Unattended Sophos removal with logging.

.NOTES
    Author: Inventive HQ (https://inventivehq.com)
    License: MIT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('CrowdStrike', 'SentinelOne', 'Sophos', 'CarbonBlack', 'TrendMicro',
                 'ESET', 'Symantec', 'Malwarebytes', 'Webroot', 'Cylance')]
    [string]$Vendor,

    [string]$UninstallToken,

    [switch]$Unattended,
    [switch]$SkipSafetyCheck,
    [string]$LogPath
)

#Requires -RunAsAdministrator

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Host $entry
    if ($LogPath) {
        $entry | Out-File -FilePath $LogPath -Append -Encoding UTF8
    }
}

# Vendor-specific configuration
$vendorConfig = @{
    'CrowdStrike' = @{
        ServiceName = 'CSFalconService'
        DisplayName = 'CrowdStrike Falcon Sensor'
        UninstallCmd = {
            param($token)
            $uninstaller = Get-ChildItem "$env:ProgramFiles\CrowdStrike\CsUninstallTool.exe" -ErrorAction SilentlyContinue
            if (-not $uninstaller) {
                # Fallback: use the installer with REMOVE=ALL
                $msiProduct = Get-CimInstance Win32_Product | Where-Object { $_.Name -like "*CrowdStrike*" } | Select-Object -First 1
                if ($msiProduct) {
                    $args = "/x $($msiProduct.IdentifyingNumber) /qn"
                    if ($token) { $args += " MAINTENANCE_TOKEN=$token" }
                    return @{ Exe = 'msiexec.exe'; Args = $args }
                }
                return $null
            }
            $args = "/uninstall"
            if ($token) { $args += " MAINTENANCE_TOKEN=$token" }
            return @{ Exe = $uninstaller.FullName; Args = $args }
        }
        CleanupPaths = @("$env:ProgramFiles\CrowdStrike", "$env:SystemRoot\System32\drivers\CrowdStrike")
    }
    'SentinelOne' = @{
        ServiceName = 'SentinelAgent'
        DisplayName = 'SentinelOne Agent'
        UninstallCmd = {
            param($token)
            $uninstaller = Get-ChildItem "$env:ProgramFiles\SentinelOne\Sentinel Agent*\uninstall.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $uninstaller) {
                # Find via registry
                $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -like "*SentinelOne*" } | Select-Object -First 1
                if ($reg -and $reg.UninstallString) {
                    $cmd = $reg.UninstallString -replace '"', ''
                    $args = "/q"
                    if ($token) { $args += " PASSPHRASE=$token" }
                    return @{ Exe = $cmd; Args = $args }
                }
                return $null
            }
            $args = "/q"
            if ($token) { $args += " PASSPHRASE=$token" }
            return @{ Exe = $uninstaller.FullName; Args = $args }
        }
        CleanupPaths = @("$env:ProgramFiles\SentinelOne")
    }
    'Sophos' = @{
        ServiceName = 'Sophos Endpoint Defense Service'
        DisplayName = 'Sophos Endpoint Protection'
        UninstallCmd = {
            param($token)
            # Sophos uses SophosZap for clean removal
            $zap = Get-ChildItem "$env:ProgramFiles\Sophos\Sophos Endpoint Agent\SophosUninstall.exe" -ErrorAction SilentlyContinue
            if ($zap) {
                return @{ Exe = $zap.FullName; Args = "/quiet" }
            }
            # Fallback to MSI uninstall
            $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*Sophos*" -and $_.UninstallString } | Select-Object -First 1
            if ($reg) {
                $cmd = $reg.UninstallString -replace '"', ''
                return @{ Exe = $cmd; Args = "/qn" }
            }
            return $null
        }
        CleanupPaths = @("$env:ProgramFiles\Sophos", "${env:ProgramFiles(x86)}\Sophos")
    }
    'CarbonBlack' = @{
        ServiceName = 'CbDefense'
        DisplayName = 'VMware Carbon Black'
        UninstallCmd = {
            param($token)
            $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*Carbon Black*" -or $_.DisplayName -like "*Cb Defense*" } | Select-Object -First 1
            if ($reg -and $reg.UninstallString) {
                $cmd = $reg.UninstallString -replace '"', ''
                $args = "/qn"
                if ($token) { $args += " UNINSTALL_CODE=$token" }
                return @{ Exe = 'msiexec.exe'; Args = "/x $($reg.PSChildName) $args" }
            }
            return $null
        }
        CleanupPaths = @("$env:ProgramFiles\Confer", "$env:ProgramFiles\CarbonBlack")
    }
    'TrendMicro' = @{
        ServiceName = 'Ntrtscan'
        DisplayName = 'Trend Micro'
        UninstallCmd = {
            param($token)
            $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*Trend Micro*" } | Select-Object -First 1
            if ($reg -and $reg.UninstallString) {
                return @{ Exe = ($reg.UninstallString -replace '"', ''); Args = "/s" }
            }
            return $null
        }
        CleanupPaths = @("$env:ProgramFiles\Trend Micro")
    }
    'ESET' = @{
        ServiceName = 'ekrn'
        DisplayName = 'ESET Endpoint Security'
        UninstallCmd = {
            param($token)
            $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*ESET*" } | Select-Object -First 1
            if ($reg -and $reg.UninstallString) {
                $cmd = $reg.UninstallString -replace '"', ''
                $args = "/qn"
                if ($token) { $args += " PASSWORD=$token" }
                return @{ Exe = $cmd; Args = $args }
            }
            return $null
        }
        CleanupPaths = @("$env:ProgramFiles\ESET")
    }
    'Symantec' = @{
        ServiceName = 'SepMasterService'
        DisplayName = 'Symantec Endpoint Protection'
        UninstallCmd = {
            param($token)
            # Symantec CleanWipe is the recommended removal tool
            $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*Symantec*Endpoint*" -or $_.DisplayName -like "*Broadcom*Endpoint*" } | Select-Object -First 1
            if ($reg -and $reg.UninstallString) {
                return @{ Exe = ($reg.UninstallString -replace '"', ''); Args = "/qn" }
            }
            return $null
        }
        CleanupPaths = @("$env:ProgramFiles\Symantec", "$env:ProgramFiles\Broadcom")
    }
    'Malwarebytes' = @{
        ServiceName = 'MBAMService'
        DisplayName = 'Malwarebytes'
        UninstallCmd = {
            param($token)
            $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*Malwarebytes*" } | Select-Object -First 1
            if ($reg -and $reg.UninstallString) {
                return @{ Exe = ($reg.UninstallString -replace '"', ''); Args = "/verysilent" }
            }
            return $null
        }
        CleanupPaths = @("$env:ProgramFiles\Malwarebytes")
    }
    'Webroot' = @{
        ServiceName = 'WRSVC'
        DisplayName = 'Webroot SecureAnywhere'
        UninstallCmd = {
            param($token)
            $wrsa = "$env:ProgramFiles\Webroot\WRSA.exe"
            if (Test-Path $wrsa) {
                return @{ Exe = $wrsa; Args = "-uninstall" }
            }
            return $null
        }
        CleanupPaths = @("$env:ProgramFiles\Webroot")
    }
    'Cylance' = @{
        ServiceName = 'CylanceSvc'
        DisplayName = 'Cylance PROTECT'
        UninstallCmd = {
            param($token)
            $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*Cylance*" } | Select-Object -First 1
            if ($reg -and $reg.UninstallString) {
                return @{ Exe = 'msiexec.exe'; Args = "/x $($reg.PSChildName) /qn" }
            }
            return $null
        }
        CleanupPaths = @("$env:ProgramFiles\Cylance")
    }
}

$config = $vendorConfig[$Vendor]

try {
    Write-Log "============================================"
    Write-Log "EDR/AV Agent Removal: $($config.DisplayName)"
    Write-Log "============================================"
    Write-Log ""

    # Step 1: Check if the agent is installed
    Write-Log "Step 1: Checking if $Vendor is installed..."
    $service = Get-Service -Name $config.ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Log "$Vendor service ($($config.ServiceName)) not found. Agent may already be removed."
        Write-Log "Checking for remnant files..."
        $hasRemnants = $false
        foreach ($path in $config.CleanupPaths) {
            if (Test-Path $path) {
                Write-Log "  Found remnant: $path" -Level "WARN"
                $hasRemnants = $true
            }
        }
        if (-not $hasRemnants) {
            Write-Log "$Vendor is not installed. Nothing to do."
            exit 0
        }
        Write-Log "Remnant files found. Continuing with cleanup." -Level "WARN"
    } else {
        Write-Log "Found $Vendor service: $($service.Status)"
    }

    # Step 2: Safety check — is replacement protection active?
    if (-not $SkipSafetyCheck) {
        Write-Log ""
        Write-Log "Step 2: Safety check — verifying replacement protection..."
        $defenderActive = $false
        try {
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop
            $defenderActive = $mpStatus.RealTimeProtectionEnabled
        } catch { }

        $otherAgentActive = $false
        $allAgentServices = @{
            'CSFalconService' = 'CrowdStrike'
            'SentinelAgent'   = 'SentinelOne'
            'SAVService'      = 'Sophos'
            'CbDefense'       = 'Carbon Black'
            'Ntrtscan'        = 'Trend Micro'
            'ekrn'            = 'ESET'
            'SepMasterService' = 'Symantec'
            'WRSVC'           = 'Webroot'
            'CylanceSvc'      = 'Cylance'
        }

        # Remove the vendor we're uninstalling from the check
        $checkServices = $allAgentServices.Clone()
        $checkServices.Remove($config.ServiceName)

        foreach ($svcName in $checkServices.Keys) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                $otherAgentActive = $true
                Write-Log "  Replacement agent detected: $($checkServices[$svcName]) is running."
                break
            }
        }

        if (-not $otherAgentActive -and -not $defenderActive) {
            Write-Log "WARNING: No replacement endpoint protection detected!" -Level "ERROR"
            Write-Log "Removing $Vendor will leave this machine UNPROTECTED." -Level "ERROR"
            if (-not $Unattended) {
                $confirm = Read-Host "Continue anyway? (type YES to confirm)"
                if ($confirm -ne 'YES') {
                    Write-Log "Aborted by user."
                    exit 1
                }
            } else {
                Write-Log "Unattended mode — cannot proceed without active replacement protection." -Level "ERROR"
                Write-Log "Use -SkipSafetyCheck to override (not recommended)." -Level "ERROR"
                exit 1
            }
        } else {
            Write-Log "  Replacement protection confirmed."
        }
    }

    # Step 3: Confirm removal
    if (-not $Unattended) {
        Write-Log ""
        $confirm = Read-Host "Remove $($config.DisplayName)? (Y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Log "Aborted by user."
            exit 0
        }
    }

    # Step 4: Run the uninstall
    Write-Log ""
    Write-Log "Step 3: Running $Vendor uninstaller..."
    $uninstallInfo = & $config.UninstallCmd $UninstallToken

    if (-not $uninstallInfo) {
        Write-Log "Could not find uninstaller for $Vendor." -Level "ERROR"
        Write-Log "Try uninstalling manually from Programs and Features, or use the vendor's removal tool." -Level "ERROR"
        exit 1
    }

    Write-Log "  Executing: $($uninstallInfo.Exe) $($uninstallInfo.Args)"
    $process = Start-Process -FilePath $uninstallInfo.Exe -ArgumentList $uninstallInfo.Args -Wait -PassThru -ErrorAction Stop

    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
        Write-Log "Uninstaller completed (exit code: $($process.ExitCode))."
        if ($process.ExitCode -eq 3010) {
            Write-Log "Reboot required to complete removal." -Level "WARN"
        }
    } else {
        Write-Log "Uninstaller exited with code $($process.ExitCode)." -Level "WARN"
        Write-Log "This may indicate a tamper protection issue. Verify the uninstall token." -Level "WARN"
    }

    # Step 5: Verify removal
    Write-Log ""
    Write-Log "Step 4: Verifying removal..."
    Start-Sleep -Seconds 5  # Give services time to stop

    $serviceStillExists = Get-Service -Name $config.ServiceName -ErrorAction SilentlyContinue
    if ($serviceStillExists -and $serviceStillExists.Status -eq 'Running') {
        Write-Log "$Vendor service is STILL RUNNING. Removal may have failed." -Level "ERROR"
        Write-Log "Check if tamper protection needs to be disabled in the vendor console first." -Level "ERROR"
    } elseif ($serviceStillExists) {
        Write-Log "$Vendor service exists but is $($serviceStillExists.Status). Reboot should complete removal."
    } else {
        Write-Log "$Vendor service removed successfully."
    }

    # Check for remnant files
    $remnantPaths = @()
    foreach ($path in $config.CleanupPaths) {
        if (Test-Path $path) {
            $remnantPaths += $path
        }
    }

    if ($remnantPaths.Count -gt 0) {
        Write-Log ""
        Write-Log "Remnant directories found (may be cleaned up after reboot):" -Level "WARN"
        foreach ($path in $remnantPaths) {
            Write-Log "  $path" -Level "WARN"
        }
    }

    Write-Log ""
    Write-Log "============================================"
    Write-Log "Removal Summary"
    Write-Log "============================================"
    Write-Log "Vendor:  $($config.DisplayName)"
    Write-Log "Service: $(if ($serviceStillExists) { $serviceStillExists.Status } else { 'Removed' })"
    Write-Log "Remnants: $(if ($remnantPaths.Count -gt 0) { "$($remnantPaths.Count) directories" } else { 'None' })"

    if ($process.ExitCode -eq 3010 -or $serviceStillExists) {
        Write-Log ""
        Write-Log "NEXT STEP: Reboot this machine, then run:" -Level "WARN"
        Write-Log "  .\Test-EndpointProtection.ps1" -Level "WARN"
    } else {
        Write-Log ""
        Write-Log "Run .\Test-EndpointProtection.ps1 to verify protection is still active."
    }

} catch {
    Write-Log "Error: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}

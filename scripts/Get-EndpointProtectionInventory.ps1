<#
.SYNOPSIS
    Discovers all installed endpoint protection products on one or more machines.

.DESCRIPTION
    Uses multiple detection methods (WMI Security Center, registry, services, file paths)
    to identify installed EDR/AV products. Detects CrowdStrike, SentinelOne, Sophos,
    Carbon Black, Trend Micro, ESET, Symantec/Broadcom, Malwarebytes, Webroot,
    Cylance, and Windows Defender.

    Works on both workstations (Security Center) and servers (registry/service fallback).

.PARAMETER ComputerName
    One or more computer names to scan. Defaults to the local machine.

.PARAMETER OutputPath
    Optional CSV output path.

.EXAMPLE
    .\Get-EndpointProtectionInventory.ps1
    Lists all protection products on the local machine.

.EXAMPLE
    .\Get-EndpointProtectionInventory.ps1 -ComputerName SERVER01,SERVER02 -OutputPath C:\Reports\inventory.csv
    Scans remote servers and exports to CSV.

.NOTES
    Author: Inventive HQ (https://inventivehq.com)
    License: MIT
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [string]$OutputPath
)

# Known product signatures
$knownProducts = @(
    @{ Name = 'CrowdStrike Falcon';    Services = @('CSFalconService');          Paths = @("$env:ProgramFiles\CrowdStrike\CSFalconService.exe") }
    @{ Name = 'SentinelOne';           Services = @('SentinelAgent', 'SentinelStaticEngine'); Paths = @("$env:ProgramFiles\SentinelOne\Sentinel Agent*") }
    @{ Name = 'Sophos';                Services = @('Sophos Endpoint Defense Service', 'SAVService', 'Sophos MCS Agent'); Paths = @("$env:ProgramFiles\Sophos") }
    @{ Name = 'Carbon Black';          Services = @('CbDefense', 'CarbonBlack', 'cb'); Paths = @("$env:ProgramFiles\Confer", "$env:ProgramFiles\CarbonBlack") }
    @{ Name = 'Trend Micro';           Services = @('Ntrtscan', 'TmListen', 'ds_agent'); Paths = @("$env:ProgramFiles\Trend Micro") }
    @{ Name = 'ESET';                  Services = @('ekrn', 'ERAAgent');         Paths = @("$env:ProgramFiles\ESET") }
    @{ Name = 'Symantec/Broadcom';     Services = @('SepMasterService', 'ccSvcHst', 'SmcService'); Paths = @("$env:ProgramFiles\Symantec", "$env:ProgramFiles\Broadcom") }
    @{ Name = 'Malwarebytes';          Services = @('MBAMService');              Paths = @("$env:ProgramFiles\Malwarebytes") }
    @{ Name = 'Webroot';               Services = @('WRSVC', 'WRCoreService');   Paths = @("$env:ProgramFiles\Webroot") }
    @{ Name = 'Cylance';               Services = @('CylanceSvc');               Paths = @("$env:ProgramFiles\Cylance") }
    @{ Name = 'Windows Defender';       Services = @('WinDefend', 'MsMpSvc');     Paths = @("$env:ProgramFiles\Windows Defender") }
    @{ Name = 'Microsoft Defender for Endpoint'; Services = @('SENSE'); Paths = @("$env:ProgramFiles\Windows Defender Advanced Threat Protection") }
)

function Get-ProtectionInfo {
    param([string]$Computer)

    $results = @()
    $isLocal = ($Computer -eq $env:COMPUTERNAME)

    try {
        # Method 1: WMI Security Center (workstations only)
        $wmiProducts = @()
        try {
            if ($isLocal) {
                $wmiProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
            } else {
                $wmiProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ComputerName $Computer -ErrorAction Stop
            }
        } catch {
            # SecurityCenter2 doesn't exist on Server — that's expected
        }

        foreach ($product in $wmiProducts) {
            # Decode productState to determine if active
            $hex = '0x{0:x}' -f $product.productState
            $enabled = ($product.productState -band 0x1000) -ne 0

            $results += [PSCustomObject]@{
                ComputerName = $Computer
                Product      = $product.displayName
                Vendor       = ($product.displayName -split ' ' | Select-Object -First 1)
                Version      = ''
                Status       = if ($enabled) { 'Active' } else { 'Inactive' }
                Source        = 'SecurityCenter'
            }
        }

        # Method 2: Service-based detection
        foreach ($prod in $knownProducts) {
            foreach ($svcName in $prod.Services) {
                $svc = $null
                try {
                    if ($isLocal) {
                        $svc = Get-Service -Name $svcName -ErrorAction Stop
                    } else {
                        $svc = Get-Service -Name $svcName -ComputerName $Computer -ErrorAction Stop
                    }
                } catch { }

                if ($svc) {
                    # Check if we already found this product via WMI
                    $alreadyFound = $results | Where-Object { $_.Product -like "*$($prod.Name.Split(' ')[0])*" }
                    if (-not $alreadyFound) {
                        $results += [PSCustomObject]@{
                            ComputerName = $Computer
                            Product      = $prod.Name
                            Vendor       = ($prod.Name -split ' ' | Select-Object -First 1)
                            Version      = ''
                            Status       = $svc.Status.ToString()
                            Source        = "Service: $($svc.Name)"
                        }
                    }
                    break  # Found this product, skip remaining service names
                }
            }
        }

        # Method 3: Check uninstall registry for AV/EDR products
        $uninstallPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )

        $avKeywords = @('antivirus', 'endpoint', 'edr', 'falcon', 'sentinel', 'sophos',
                        'carbon black', 'trend micro', 'eset', 'symantec', 'broadcom',
                        'malwarebytes', 'webroot', 'cylance', 'defender')

        $scriptBlock = {
            param($paths, $keywords)
            $found = @()
            foreach ($path in $paths) {
                Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $name = $_.DisplayName
                    if ($name) {
                        foreach ($kw in $keywords) {
                            if ($name -like "*$kw*") {
                                $found += [PSCustomObject]@{
                                    DisplayName    = $name
                                    DisplayVersion = $_.DisplayVersion
                                    Publisher      = $_.Publisher
                                    UninstallString = $_.UninstallString
                                }
                                break
                            }
                        }
                    }
                }
            }
            $found
        }

        $regProducts = @()
        if ($isLocal) {
            $regProducts = & $scriptBlock $uninstallPaths $avKeywords
        } else {
            $regProducts = Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $uninstallPaths, $avKeywords -ErrorAction Stop
        }

        foreach ($rp in $regProducts) {
            # Avoid duplicates
            $alreadyFound = $results | Where-Object { $_.Product -like "*$($rp.DisplayName.Split(' ')[0])*" }
            if (-not $alreadyFound) {
                $results += [PSCustomObject]@{
                    ComputerName = $Computer
                    Product      = $rp.DisplayName
                    Vendor       = if ($rp.Publisher) { $rp.Publisher } else { 'Unknown' }
                    Version      = $rp.DisplayVersion
                    Status       = 'Installed (registry)'
                    Source        = 'Registry'
                }
            }
        }

        if ($results.Count -eq 0) {
            $results += [PSCustomObject]@{
                ComputerName = $Computer
                Product      = 'No endpoint protection detected'
                Vendor       = ''
                Version      = ''
                Status       = 'UNPROTECTED'
                Source        = ''
            }
        }

    } catch {
        $results += [PSCustomObject]@{
            ComputerName = $Computer
            Product      = "ERROR: $($_.Exception.Message)"
            Vendor       = ''
            Version      = ''
            Status       = 'Error'
            Source        = ''
        }
    }

    return $results
}

# Main
Write-Host "Endpoint Protection Inventory"
Write-Host "============================="
Write-Host ""

$allResults = @()
foreach ($computer in $ComputerName) {
    Write-Host "Scanning $computer..."
    $allResults += Get-ProtectionInfo -Computer $computer
}

# Display results
Write-Host ""
$allResults | Format-Table -AutoSize ComputerName, Product, Status, Version, Source

# Export if requested
if ($OutputPath) {
    $allResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Report saved to: $OutputPath"
}

# Warn about unprotected machines
$unprotected = $allResults | Where-Object { $_.Status -eq 'UNPROTECTED' }
if ($unprotected) {
    Write-Host ""
    Write-Warning "The following machines have NO endpoint protection detected:"
    $unprotected | ForEach-Object { Write-Warning "  - $($_.ComputerName)" }
}

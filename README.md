# EDR Decommission Toolkit

**Checklist and PowerShell scripts for safely removing legacy endpoint detection (EDR/AV) agents during a migration.**

Built by [Inventive HQ](https://inventivehq.com) — Cybersecurity & IT services for growing businesses.

---

## Why This Exists

Migrating endpoint protection is one of the riskiest operations in IT. Remove the old agent too early and you have unprotected endpoints. Leave it too long and you have agent conflicts, performance issues, and double-billing.

This toolkit gives you a repeatable, auditable process for decommissioning legacy EDR/AV agents — whether you're moving from CrowdStrike to SentinelOne, Sophos to Defender, or anything in between.

---

## Prerequisites

- PowerShell 5.1 or later
- Run as Administrator
- Windows 10/11 or Windows Server 2016+
- Uninstall token/password from your legacy EDR console (if tamper protection is enabled)

## Quick Start

```powershell
# Clone the toolkit
git clone https://github.com/InventiveHQ/edr-decommission-toolkit.git
cd edr-decommission-toolkit/scripts

# Check what's installed on this machine
.\Get-EndpointProtectionInventory.ps1

# Verify the new agent is running before removing the old one
.\Test-EndpointProtection.ps1 -ExpectedProduct "Windows Defender"

# Remove a legacy agent (interactive prompts for safety)
.\Remove-LegacyAgent.ps1 -Vendor CrowdStrike
```

---

## The Checklist

Use [docs/DECOMMISSION-CHECKLIST.md](docs/DECOMMISSION-CHECKLIST.md) as your migration runbook. It covers:

1. **Pre-migration** — Inventory, exclusion export, uninstall token retrieval
2. **Pilot group** — Test removal on 5-10 machines first
3. **New agent deployment** — Verify enrollment before removing old
4. **Legacy removal** — Scripted removal with tamper protection handling
5. **Post-removal validation** — Confirm no protection gaps
6. **Cleanup** — Console deactivation, license reclamation, documentation

---

## Scripts

### Get-EndpointProtectionInventory.ps1

Discovers all installed endpoint protection products on a machine using WMI, registry, and service checks. Detects CrowdStrike, SentinelOne, Sophos, Carbon Black, Trend Micro, ESET, Symantec/Broadcom, Malwarebytes, Webroot, Cylance, and Windows Defender.

```powershell
# Local machine
.\Get-EndpointProtectionInventory.ps1

# Remote machines (CSV output)
.\Get-EndpointProtectionInventory.ps1 -ComputerName SERVER01,SERVER02 -OutputPath C:\Reports\edr-inventory.csv
```

### Test-EndpointProtection.ps1

Validates that endpoint protection is active and healthy. Checks service status, real-time protection, definition freshness, and Security Center registration. Use this **before** and **after** removing a legacy agent.

```powershell
# Basic check
.\Test-EndpointProtection.ps1

# Verify a specific product is active
.\Test-EndpointProtection.ps1 -ExpectedProduct "CrowdStrike"

# Fail if definitions are older than 3 days
.\Test-EndpointProtection.ps1 -MaxDefinitionAgeDays 3
```

### Remove-LegacyAgent.ps1

Handles uninstallation of common EDR/AV products including tamper protection token handling, service cleanup, and verification. Supports unattended mode for mass deployment.

```powershell
# Interactive removal (prompts for confirmation)
.\Remove-LegacyAgent.ps1 -Vendor CrowdStrike

# With uninstall token (tamper protection)
.\Remove-LegacyAgent.ps1 -Vendor CrowdStrike -UninstallToken "ABC123..."

# Unattended mode for deployment tools
.\Remove-LegacyAgent.ps1 -Vendor Sophos -UninstallToken "XYZ789..." -Unattended

# Log the removal
.\Remove-LegacyAgent.ps1 -Vendor SentinelOne -LogPath C:\Logs\edr-removal.log
```

### Export-AgentConfig.ps1

Exports exclusions, policies, and configuration from legacy agents so you can replicate them in the new platform.

```powershell
# Export current exclusion lists
.\Export-AgentConfig.ps1 -Vendor CrowdStrike -OutputPath C:\Migration\exclusions.json

# Export from Defender
.\Export-AgentConfig.ps1 -Vendor Defender -OutputPath C:\Migration\defender-config.json
```

---

## Supported Vendors

| Vendor | Inventory | Removal | Config Export |
|--------|:---------:|:-------:|:------------:|
| CrowdStrike Falcon | Yes | Yes | Partial |
| SentinelOne | Yes | Yes | Partial |
| Sophos | Yes | Yes | No |
| Carbon Black | Yes | Yes | No |
| Trend Micro | Yes | Yes | No |
| Symantec/Broadcom | Yes | Yes | No |
| ESET | Yes | Yes | No |
| Malwarebytes | Yes | Yes | No |
| Webroot | Yes | Yes | No |
| Cylance | Yes | Yes | No |
| Windows Defender | Yes | N/A | Yes |

---

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues:
- Tamper protection won't disable
- Agent won't uninstall (orphaned services)
- New agent conflicts with remnants of old agent
- Reboot loops after removal
- Security Center still shows old product

---

## Need Help with EDR Migration?

These scripts handle the technical removal — but a full migration includes policy design, exclusion tuning, and 30-day monitoring.

**[Get a seamless EDR migration →](https://inventivehq.com/services/edr-migration)**

Our flat-fee migration package includes legacy agent audit, scripted removal, new agent deployment with tuned policies, and 30-day post-deployment monitoring — starting at $995.

---

## License

MIT — use these scripts however you want. See [LICENSE](LICENSE).

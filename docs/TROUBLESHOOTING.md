# EDR Decommission Troubleshooting Guide

Common issues during endpoint protection migration and how to resolve them.

---

## Quick Decision Tree

```
Problem during EDR migration?
├── Can't uninstall the old agent? → See "Removal Issues" below
├── New agent not working? → See "New Agent Issues" below
├── Performance problems? → See "Performance" below
├── Blue screen / driver conflict? → See "Driver Conflicts" below
└── Agent still showing in old console? → See "Console Cleanup" below
```

---

## Removal Issues

### Tamper Protection Blocks Uninstall

**Symptoms:** Uninstaller exits with error, service can't be stopped, files can't be deleted.

**Resolution:**

1. Get the correct uninstall/maintenance token from the vendor's management console
2. Some vendors use per-device tokens — check the device's page in the console
3. Pass the token: `.\Remove-LegacyAgent.ps1 -Vendor CrowdStrike -UninstallToken "YOUR-TOKEN"`

**CrowdStrike-specific:**
- Falcon console → Host Management → Select host → Actions → Reveal Maintenance Token
- Token expires after use — generate a new one if the first attempt fails

**SentinelOne-specific:**
- Management Console → Sentinels → Select agent → Actions → Show Passphrase
- The passphrase is required even for silent uninstall

### Service Won't Stop

**Symptoms:** `Stop-Service` hangs, service status stuck at "Stopping."

```powershell
# Force-kill the process
$svc = Get-CimInstance Win32_Service | Where-Object { $_.Name -eq 'ServiceName' }
Stop-Process -Id $svc.ProcessId -Force

# If that doesn't work, try Safe Mode:
# 1. Boot into Safe Mode (msconfig → Boot → Safe boot)
# 2. Delete the service: sc delete ServiceName
# 3. Delete the program files
# 4. Boot normally
```

### Uninstaller Not Found

**Symptoms:** `Remove-LegacyAgent.ps1` reports "Could not find uninstaller."

1. Check Programs and Features for the exact product name
2. Find the uninstall string in the registry:
   ```powershell
   Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
       Where-Object { $_.DisplayName -like "*VendorName*" } |
       Select-Object DisplayName, UninstallString
   ```
3. Run the uninstall string manually
4. If no uninstaller exists, use the vendor's dedicated removal tool:
   - CrowdStrike: CsUninstallTool.exe (download from Falcon console)
   - Symantec: CleanWipe (download from Broadcom support)
   - Sophos: SophosZap (download from Sophos community)

### Agent Reinstalls Itself After Removal

**Symptoms:** You uninstall, reboot, and the agent is back.

This usually means a deployment tool (SCCM, Intune, GPO) is reinstalling it:

1. Check SCCM/Intune for deployment assignments — remove or disable them
2. Check GPO for software installation policies: `gpresult /r`
3. Check scheduled tasks: `Get-ScheduledTask | Where-Object { $_.TaskName -like "*VendorName*" }`
4. Remove the deployment assignment BEFORE uninstalling the agent

---

## New Agent Issues

### New Agent Shows "Inactive" or "Offline" in Console

1. **Check the service:**
   ```powershell
   .\Test-EndpointProtection.ps1 -ExpectedProduct "NewProduct"
   ```
2. **Check network:** Can the machine reach the new vendor's cloud? Check proxy/firewall rules.
3. **Check enrollment:** The agent may need a site token or enrollment key.
4. **Reinstall:** Uninstall and reinstall the new agent with the correct enrollment token.

### Real-Time Protection Disabled

1. Check if the legacy agent left behind a WMI registration that's confusing Security Center:
   ```powershell
   Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
   ```
2. If the old product still appears, remove it:
   ```powershell
   # Note the instanceGuid from the query above
   Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
       Where-Object { $_.displayName -like "*OldVendor*" } |
       Remove-CimInstance
   ```
3. Restart the new agent's service.

### New Agent Won't Install (Conflict)

Remnants of the old agent can block installation:

1. Run `Get-EndpointProtectionInventory.ps1` to check what's still detected
2. Check for orphaned services:
   ```powershell
   Get-Service | Where-Object { $_.DisplayName -like "*OldVendor*" }
   # Remove with: sc delete ServiceName
   ```
3. Check for orphaned drivers:
   ```powershell
   driverquery /v | findstr /i "OldVendor"
   # Remove from: C:\Windows\System32\drivers\
   ```
4. Reboot and try installing again.

---

## Performance Issues

### System Slow After Migration

1. **Check for dual scanning:** Both agents running simultaneously doubles the I/O.
   ```powershell
   .\Test-EndpointProtection.ps1  # Check for agent conflicts
   ```
2. **Apply exclusions:** The new agent needs the same exclusions as the old one.
   ```powershell
   .\Export-AgentConfig.ps1 -Vendor Defender -OutputPath exclusions.json
   # Then import those exclusions into the new platform
   ```
3. **SQL Server, Exchange, SharePoint:** These always need specific exclusions — check the vendor's KB article.

### High CPU from New Agent

- First 24-48 hours: Initial scan and baseline building is normal
- If it persists: Check the new console for scan schedule conflicts
- Add high-churn directories to exclusions (build folders, temp, logs)

---

## Driver Conflicts (BSOD)

### Blue Screen After Removal or Installation

1. **Boot Safe Mode:** Hold Shift during restart → Troubleshoot → Advanced → Safe Mode
2. **Remove the problematic driver:**
   ```cmd
   cd C:\Windows\System32\drivers
   ren OldVendorDriver.sys OldVendorDriver.sys.bak
   ```
3. **Boot normally** and verify the issue is resolved
4. **If the new agent causes BSOD:** Uninstall it in Safe Mode and contact the vendor

### Filter Driver Conflicts

EDR products use kernel filter drivers that can conflict:

```powershell
# List filter drivers
fltmc
```

If you see filter drivers from BOTH the old and new vendor, the old one wasn't fully removed. Boot Safe Mode and delete the old driver from `C:\Windows\System32\drivers\`.

---

## Console Cleanup

### Old Agent Still Shows in Legacy Console

After uninstalling from endpoints:
1. Wait 24-48 hours — most consoles auto-detect uninstalled agents
2. Manually decommission/delete the device in the legacy console
3. For CrowdStrike: Host Management → Select host → Actions → Delete Host
4. For SentinelOne: Sentinels → Select agent → Actions → Decommission

### Can't Delete Devices from Legacy Console

Usually a permissions issue — you need admin rights in the console. Contact the vendor if devices are stuck in a "pending uninstall" state.

---

## Still Stuck?

1. Collect logs: `.\Remove-LegacyAgent.ps1 -Vendor {name} -LogPath C:\Logs\removal.log`
2. Run the vendor's dedicated removal tool (most have one for stubborn uninstalls)
3. Check the vendor's support portal for known issues with your specific version

For managed EDR migration support, see our [EDR Migration service](https://inventivehq.com/services/edr-migration).

---

*Built by [Inventive HQ](https://inventivehq.com) — Cybersecurity & IT services for growing businesses.*

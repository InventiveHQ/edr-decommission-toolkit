# EDR/AV Decommission Checklist

A step-by-step runbook for safely removing legacy endpoint protection during a migration.

**Print this, check off each item, keep it for your audit trail.**

---

## Phase 1: Pre-Migration Planning

### Inventory & Documentation
- [ ] Run `Get-EndpointProtectionInventory.ps1` across all endpoints
- [ ] Document the legacy product name, version, and license count
- [ ] Document the new product name, version, and license count
- [ ] Identify the legacy vendor's management console URL and admin credentials
- [ ] Identify machines with non-standard configurations (servers, kiosks, air-gapped)

### Exclusions & Policy Export
- [ ] Export exclusion lists from the legacy console (paths, extensions, processes)
- [ ] Run `Export-AgentConfig.ps1` on a representative machine for local config
- [ ] Document any custom scan schedules or performance tuning
- [ ] Document ASR rules / exploit protection settings (if Defender-managed)
- [ ] Map legacy exclusions to the new product's format

### Tamper Protection
- [ ] Locate the uninstall/maintenance token in the legacy console
- [ ] Test the token on ONE machine before mass deployment
- [ ] Document the token retrieval process (it may change per-device for some vendors)
- [ ] Verify you have console access to generate tokens for all devices

### Communication
- [ ] Notify the security team and get sign-off on the migration window
- [ ] Notify end users about expected behavior (possible reboots, brief AV notification changes)
- [ ] Schedule the migration window (off-hours preferred)

---

## Phase 2: Pilot Group (5-10 Machines)

### New Agent Deployment
- [ ] Deploy the new agent to pilot machines
- [ ] Verify enrollment in the new console for each pilot machine
- [ ] Run `Test-EndpointProtection.ps1 -ExpectedProduct "NewProduct"` on each
- [ ] Confirm real-time protection is active
- [ ] Apply exclusions and policies from Phase 1 export
- [ ] Monitor for 24-48 hours — check for performance issues, false positives

### Legacy Removal (Pilot)
- [ ] Run `Remove-LegacyAgent.ps1 -Vendor {name} -UninstallToken {token}` on each pilot machine
- [ ] Reboot if required
- [ ] Run `Test-EndpointProtection.ps1` post-removal — confirm no protection gap
- [ ] Verify the machine no longer appears in the legacy console (or shows as uninstalled)
- [ ] Monitor pilot machines for 48 hours — any issues, performance changes, alerts

### Pilot Review
- [ ] All pilot machines healthy? (check: no blue screens, no app breakage, no performance degradation)
- [ ] New agent reporting properly to console?
- [ ] Legacy agent fully removed? (no orphaned services, no conflicting drivers)
- [ ] Security team sign-off to proceed to mass rollout?

---

## Phase 3: Mass Rollout

### Pre-Rollout
- [ ] Prepare the deployment script/package (SCCM, Intune, GPO, or manual)
- [ ] Test unattended mode: `Remove-LegacyAgent.ps1 -Vendor {name} -UninstallToken {token} -Unattended`
- [ ] Create a rollback plan (how to reinstall legacy agent if needed)
- [ ] Confirm the new agent is deployed to ALL target machines before removing legacy

### Batch Removal
- [ ] Deploy new agent to batch (verify enrollment before proceeding)
- [ ] Run `Test-EndpointProtection.ps1 -ExpectedProduct "NewProduct"` across batch
- [ ] Remove legacy agent across batch (use `-Unattended -LogPath` for automation)
- [ ] Collect and review removal logs
- [ ] Reboot machines as needed
- [ ] Verify removal across batch

### Monitoring (First 7 Days)
- [ ] Check new console daily for enrollment status, alerts, and health
- [ ] Monitor help desk for user-reported issues
- [ ] Run `Get-EndpointProtectionInventory.ps1` on a sample of machines to verify state
- [ ] Check for orphaned legacy services: `Get-Service | Where-Object { $_.DisplayName -like "*LegacyVendor*" }`

---

## Phase 4: Post-Migration Cleanup

### Console & Licensing
- [ ] Deactivate/remove machines from the legacy vendor console
- [ ] Cancel or downgrade the legacy license (note renewal dates!)
- [ ] Document the license cancellation confirmation
- [ ] Remove legacy vendor's management infrastructure (on-prem console, relay servers)

### Endpoint Cleanup
- [ ] Run a final inventory scan to catch any missed machines
- [ ] Clean up remnant files on machines that had removal issues
- [ ] Remove legacy vendor GPOs or Intune configuration profiles
- [ ] Remove legacy vendor firewall rules (if any)

### Documentation
- [ ] Update your asset management / CMDB with the new agent info
- [ ] Update your incident response runbook with new agent procedures
- [ ] Update your security architecture diagram
- [ ] File the migration report with: machines migrated, issues encountered, timeline, sign-off
- [ ] Archive this checklist with the completion date

---

## Rollback Plan

If the new agent causes critical issues:

1. Reinstall the legacy agent using your existing deployment method
2. Verify the legacy agent is active: `Test-EndpointProtection.ps1 -ExpectedProduct "LegacyProduct"`
3. Investigate the new agent issue with the vendor
4. Retry migration after the issue is resolved

---

## Common Issues

| Issue | Resolution |
|-------|-----------|
| Tamper protection blocks removal | Get the correct uninstall token from the vendor console. Some vendors require per-device tokens. |
| Legacy service won't stop | Boot into Safe Mode and delete the service: `sc delete ServiceName` |
| New agent shows "inactive" in console | Check network connectivity, proxy settings, and enrollment token |
| Performance degradation after migration | Review exclusions — the new agent may need the same exclusions as the old one |
| Driver conflicts (BSOD) | Boot Safe Mode, remove the problematic driver, contact the vendor |

For a full troubleshooting guide, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

*Built by [Inventive HQ](https://inventivehq.com) — [Get a managed EDR migration →](https://inventivehq.com/services/edr-migration)*

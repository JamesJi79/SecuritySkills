# Backup Management Plane Segmentation Gate

## Purpose
Prevents false-positive segmentation alerts when backup system traffic traverses management plane boundaries as part of authorized backup and recovery workflows.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Traffic originates from a known backup server, backup agent, or storage appliance
2. Destination includes management interfaces (iLO, iDRAC, BMC, IPMI) or hypervisor management networks
3. The connection occurs during a documented backup window

### Gate Check: Backup Server Identity

```yaml
check_backup_server_identity:
  - detection_patterns:
      - "backup.*server|backup.*appliance|veeam|netbackup|commvault|rubrik|cohesity"
      - "storage.*array|backup.*storage|tape.*library"
      - "backup.*agent|backup.*proxy|media.*server"
  - pass: "When the source is a recognized backup infrastructure component and the backup schedule confirms the window, downgrade to informational. Rationale: Backup systems require management plane access to snapshot VMs and restore operations by design."
  - fail: "When the source is not in the backup infrastructure inventory, retain original severity. Rationale: Non-backup systems should not have management plane access."
```

### Gate Check: Management Protocol Necessity

```yaml
check_management_protocol_necessity:
  - detection_patterns:
      - "snapshot|vm.?backup|volume.?shadow|vss|hypervisor.?api"
      - "idrac|ilo|ipmi|bmc|mgmt.*network"
      - "restore|recovery|failover|replication"
  - pass: "When the detected management protocol is VMware vSphere API, Hyper-V WMI, or storage array replication that matches the backup tool's documented integration, downgrade severity. Rationale: These protocols are necessary for backup operations and produce no management-plane risk."
  - fail: "When the protocol is interactive management (SSH/RDP to hypervisor, IPMI shell) outside of documented break-glass procedures, retain severity. Rationale: Interactive management plane access from a backup server is anomalous."
```

## Resolution Path
1. Confirm the source IP/hostname is in the backup infrastructure CMDB group
2. Verify the connection timestamp falls within a documented backup or maintenance window
3. Check that the management protocol is on the approved integration list for the backup tool vendor
4. If an exception is warranted, document with a reference to the backup architecture diagram and restore procedure

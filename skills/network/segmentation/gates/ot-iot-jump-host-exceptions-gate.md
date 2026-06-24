# OT IoT Jump-Host Exceptions Gate

## Purpose
Prevents false-positive segmentation violations when OT/IoT jump-host traffic is flagged as unauthorized lateral movement despite operating within approved bastion/air-gap architectures.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Alert involves traffic from a jump host / bastion host to an OT or IoT subnet
2. Destination is a known industrial control system (ICS) or IoT device IP range
3. Source port is ephemeral (49152-65535) and protocol is RDP/SSH/VNC or vendor-specific SCADA protocol

### Gate Check: Jump-Host Authorization

```yaml
check_jump_host_authorization:
  - detection_patterns:
      - "jump.?host|bastion.?host|pam.?server|privileged.?access.?management"
      - "(ot|ics|scada|plc|rtu) (subnet|segment|network|vlan)"
      - "air.?gap|DMZ.?OT|Purdue.?level"
  - pass: "When the jump host is in the authorized bastion inventory and the destination OT segment is in the documented Purdue model (Level 1-2), downgrade to informational. Rationale: Approved OT access via managed bastion is expected behavior in segmented ICS architectures."
  - fail: "When the jump host is unrecognized, unmanaged, or the OT segment is not in the documented segmentation plan, retain original severity. Rationale: Unknown jump host to OT segment traffic is a genuine lateral movement signal."
```

### Gate Check: Protocol Allowlisting

```yaml
check_protocol_allowlisting:
  - detection_patterns:
      - "(ssh|rdp|vnc|https?) (to|toward|from) (ot|ics|plc)"
      - "modbus|profinet|s7|dnp3|bacnet|opc"
  - pass: "When the detected protocol matches the documented allowed protocols for that OT segment's jump-host ACL, downgrade severity. Rationale: Protocol matches authorized access pattern in the OT security policy."
  - fail: "When the protocol is not in the documented allowlist for that jump-host-to-OT-segment pair, retain original severity. Rationale: Unexpected protocol to OT segment is a genuine anomaly regardless of jump host source."
```

## Resolution Path
1. Verify the jump host's FQDN against the bastion inventory (CMDB or PAM system)
2. Confirm the OT subnet is in the approved segmentation plan with documented business justifications
3. Ensure the protocol in use is listed in the OT segment's ingress ACL for that jump host
4. Document the exception with a reference to the approved bastion and OT segment policy documents

# Cloud Snapshot Quarantine Gate

## Purpose
Prevents false-positive containment findings when cloud snapshot quarantine for forensic preservation creates cost or operational concerns, but the quarantine process uses automated lifecycle management, tiered storage, and snapshot budgeting to balance forensic needs with cost control.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A containment procedure requires taking snapshots of cloud volumes for forensic preservation
2. The snapshots are retained beyond the standard backup retention period (quarantine)
3. Snapshot costs or volume concerns are raised as an objection to the quarantine procedure

### Gate Check: Lifecycle Automation

```yaml
check_lifecycle_automation:
  - detection_patterns:
      - "snapshot.*lifecycle|snapshot.*retention|snapshot.*expir|snapshot.*delete"
      - "automated.*snapshot|snapshot.*policy|DLM|data.?lifecycle.?manager"
      - "tier.*snapshot|snapshot.*archive|S3.*glacier|snapshot.*cold"
  - pass: "When snapshots have an automated lifecycle policy that transitions to cost-optimized storage (e.g., AWS EBS Snapshots Archive, snapshot tiering) after 30 days and deletes them after the evidence retention period, downgrade to informational. Rationale: Automated lifecycle management controls costs while preserving forensic evidence for the required retention period."
  - fail: "When snapshots are taken but have no lifecycle policy, resulting in indefinite retention at full cost, retain severity. Rationale: Unmanaged forensic snapshots accumulate costs and may be deleted prematurely without lifecycle automation."
```

### Gate Check: Quarantine Budget

```yaml
check_quarantine_budget:
  - detection_patterns:
      - "forensic.*budget|incident.*cost|IR.*budget|snapshot.*budget"
      - "cloud.*cost|storage.*cost|snapshot.*cost|evidence.*cost"
      - "cost.*center|chargeback|showback|incident.*tag"
  - pass: "When the incident response budget includes a forensic snapshot allocation, and snapshot costs are tagged to the incident for cost tracking, downgrade severity. Rationale: Budgeted forensic costs with incident tagging ensure snapshots can be preserved without financial surprises."
  - fail: "When there is no forensic snapshot budget and costs are charged to general storage, retain severity. Rationale: Unbudgeted forensic costs create pressure to delete evidence prematurely."
```

## Resolution Path
1. Create an automated snapshot lifecycle policy: cold tier after 30 days, delete after 90 days (or match evidence retention policy)
2. Tag all forensic snapshots with the incident ID for cost tracking and automated lifecycle management
3. Include forensic snapshot costs in the IR budget with a defined allocation
4. Document the quarantine procedure with lifecycle stages: Active (days 1-30), Archived (days 31-90), Deleted (day 90+)

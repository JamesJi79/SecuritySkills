# SCIM Deprovisioning Drift Gate

## Purpose
Prevents false-positive access review findings when SCIM-provisioned user accounts persist in downstream applications after deprovisioning in the IdP, but the deprovisioning drift is detected within the SLA and automatically remediated through periodic reconciliation.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A SCIM-provisioned user account remains active in a downstream app after the user was deprovisioned in the IdP
2. The organization has a SCIM reconciliation process that detects and remediates drift
3. Reconciliation runs at least daily and alerts on drift

### Gate Check: Reconciliation Cadence

```yaml
check_reconciliation_cadence:
  - detection_patterns:
      - "SCIM|System.*Cross.*Identity.*Management|provision|deprovision"
      - "reconcil|drift.*detect|sync.*check|identity.*reconcil"
      - "user.*deactiv|account.*deactiv|access.*revok|offboard"
  - pass: "When SCIM reconciliation runs at least every 24 hours and automatically disables drift accounts, downgrade to informational. Rationale: Daily automated reconciliation ensures deprovisioning drift is remediated within 24 hours, meeting most compliance SLAs."
  - fail: "When reconciliation runs less frequently than every 48 hours or is manual, retain severity. Rationale: Manual or infrequent reconciliation leaves a window for orphaned accounts."
```

### Gate Check: Alerting

```yaml
check_alerting:
  - detection_patterns:
      - "alert.*drift|notif.*drift|drift.*report|reconcil.*report"
      - "orphan.*account|stale.*account|zombie.*account|abandon.*account"
      - "reconcil.*fail|provision.*error|SCIM.*error|sync.*error"
  - pass: "When reconciliation failures and drift detections trigger alerts to the identity team with account details within 1 hour of detection, downgrade severity. Rationale: Timely alerting on drift enables investigation before the account can be exploited."
  - fail: "When reconciliation failures are silent or require manual log review to detect, retain severity. Rationale: Unalerted drift may persist indefinitely without detection."
```

## Resolution Path
1. Configure daily SCIM reconciliation for all SCIM-provisioned applications
2. Enable automatic drift remediation (disable orphaned accounts on detection)
3. Set up alerting for reconciliation failures and drift detection
4. Document the maximum deprovisioning latency (reconciliation interval + alert delay) in the access review report

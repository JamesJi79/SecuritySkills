# Cloud Security Group Object Drift Gate

## Purpose
Prevents false-positive firewall review findings when cloud security group rules have drifted from their Infrastructure-as-Code (IaC) source of truth but the drift is intentional and documented.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A cloud security group rule differs from the IaC-managed template (Terraform, CloudFormation, Pulumi)
2. The rule was created outside the IaC pipeline (manual console change, CLI, or API)
3. A drift detection tool (e.g., AWS Config, Azure Policy, Google Cloud Asset Inventory) has flagged the discrepancy

### Gate Check: Drift Authorization

```yaml
check_drift_authorization:
  - detection_patterns:
      - "drift|config.?drift|template.?drift|state.?drift"
      - "terraform|cloudformation|pulumi|cdk|arm.?template"
      - "out.?of.?band|manual.?change|console.?change|break.?glass"
  - pass: "When the drifted rule has an associated change ticket or break-glass record with documented business justification and planned IaC reconciliation date, downgrade to informational. Rationale: Authorized out-of-band changes with a documented reconciliation plan are acceptable temporary deviations."
  - fail: "When no change ticket, break-glass record, or planned reconciliation exists for the drifted rule, retain original severity. Rationale: Unauthorized IaC drift is a configuration compliance violation that increases the attack surface."
```

### Gate Check: Drift Age and Criticality

```yaml
check_drift_age_and_criticality:
  - detection_patterns:
      - "security.?group|sg|nsg|firewall.?rule|acl"
      - "0\\.0\\.0\\.0/0|::/0|wildcard|any.*any|all.*traffic"
      - "expos|internet.?facing|public"
  - pass: "When the drifted rule is less than 72 hours old and does not open 0.0.0.0/0 to non-HTTP(S) ports, downgrade severity. Rationale: Recent drifts within standard change windows are likely intentional and pending IaC reconciliation."
  - fail: "When the drift is older than 72 hours without reconciliation, or opens 0.0.0.0/0 to privileged ports (22, 3389, 3306, 5432, 6379, 27017), retain severity. Rationale: Stale, broad drifts represent unmanaged security posture degradation."
```

## Resolution Path
1. Check the cloud provider's change history or API logs for the user/role that created the security group rule outside IaC
2. Determine if the change references a ticket number in its description tag or was created during an incident
3. If authorized: create a Terraform/CloudFormation PR to reconcile the IaC state within the documented timeline
4. If unauthorized: revert the rule immediately and investigate the source of the unmanaged change

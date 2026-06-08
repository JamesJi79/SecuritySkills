# Suppression Lifecycle Evidence Gate

## Purpose
Prevents false-positive "false positive suppression" findings when suppression records include complete lifecycle metadata (scope, approver, creation date, expiration/revalidation date, revalidation trigger even when the suppression itself appears permanent). The current skill allows suppressions without lifecycle tracking, creating risk that confirmed false positives become permanent global suppressions after scanner updates or environment changes.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "permanent suppression" or "suppression without lifecycle" as Medium/High
2. The suppression record includes creation date, scope, and approver
3. The suppression has an expiration or revalidation trigger configured

### Gate Check: Suppression Metadata

```yaml
check_suppression_metadata:
  - detection_patterns:
      - "false.*positive|suppress.*finding|suppression.*rule|noise.*rule"
      - "suppress.*scope|approv.*suppression|suppression.*date"
  - required_metadata:
      - "Scope (file, directory, rule ID, CVE)"
      - "Approver identity and date"
      - "Creation date"
      - "Expiration or revalidation date"
      - "Revalidation trigger (scanner update, package change, rebuild, network change)"
  - pass: "All required suppression metadata present → Downgrade to Low (Informational). Rationale: Lifecycle-tracked suppressions can be automatically revalidated when conditions change."
  - fail: "Missing any required metadata → Keep severity. Untracked suppressions may silently hide real vulnerabilities after environment changes."
```

### Gate Check: Revalidation Triggers

```yaml
check_revalidation_triggers:
  - detection_patterns:
      - "revalidat|re.*evaluat|re.*assess|trigger.*change"
      - "scanner.*update|plugin.*version|package.*change|asset.*rebuild"
  - pass: "Revalidation triggers are defined AND suppression will be re-checked on trigger events → Accept. Automated revalidation prevents suppression drift."
  - fail: "No revalidation trigger defined → Escalate. Suppressions without revalidation become permanent, even after the underlying cause is resolved."
```

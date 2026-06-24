# Emergency Rule Rollback Expiry Gate

## Purpose
Prevents false-positive severity escalation when temporary emergency firewall rules that have passed their rollback expiry are flagged as violations, even though the change management process formally approved the permanent adoption.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A firewall rule is flagged as expired, temporary, or emergency
2. The rule has an associated change request or emergency change record
3. The rule's documented rollback date/time has passed

### Gate Check: Change Request Status

```yaml
check_change_request_status:
  - detection_patterns:
      - "emergency.*change|urgent.*change|expedited.*change"
      - "rollback.*date|rollback.*time|expir.*time|valid.*until"
      - "RFC|CHG|INC|emergency.*ticket"
  - pass: "When the associated change request has a status of Completed or Closed and the approval documented a permanent adoption decision, downgrade to informational. Rationale: The emergency rule became permanent through documented change management process."
  - fail: "When the change request is still in Pending, In Progress, or the rollback is not documented as canceled, retain original severity. Rationale: An expired emergency rule without formal permanent adoption is a security control gap."
```

### Gate Check: Rule Lifecycle Documentation

```yaml
check_rule_lifecycle_documentation:
  - detection_patterns:
      - "temporary.*rule|emergency.*rule|interim.*rule|hotfix.*rule"
      - "rule.*cleanup|cleanup.*date|review.*date|revert.*date"
      - "expir|rollback|sunset|deprecat"
  - pass: "When the rule has documented evidence of post-emergency review (ticket comment, CAB minutes, rule recertification) that confirms it as intentionally permanent, downgrade severity. Rationale: Formal adoption documentation satisfies audit requirements for the rule's ongoing existence."
  - fail: "When no post-emergency review evidence exists and the rule exceeds its documented rollback expiry, retain severity. Rationale: An undocumented permanent emergency rule violates the principle of least privilege and change control policy."
```

## Resolution Path
1. Locate the change request or emergency ticket associated with the firewall rule
2. Verify the ticket status and check for a documented permanent adoption decision or rule recertification
3. If the rule is intended to be permanent, create a standard change request to formalize the rule outside the emergency process
4. If no permanent adoption decision exists, schedule the rule for removal within the next maintenance window

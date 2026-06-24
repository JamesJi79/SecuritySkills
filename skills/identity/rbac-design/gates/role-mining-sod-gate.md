# Role Mining Separation-of-Duties Gate

## Purpose
Prevents false-positive RBAC findings when role mining identifies role combinations that appear to violate separation of duties (SoD), but the organization implements compensating controls (approval workflows, audit logging, time-bound elevation) that prevent SoD abuse.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Role mining identifies a role or role combination that violates SoD rules
2. The role is used only with approval workflows or time-bound elevation
3. All role activations are logged and audited

### Gate Check: Approval Workflow

```yaml
check_approval_workflow:
  - detection_patterns:
      - "separation.*duties|SoD|conflict.*role|conflict.*interest"
      - "approval.*workflow|manager.*approv|peer.*review|two.?person.*rule"
      - "role.*mining|role.*discover|entitlement.*analytics|access.*certification"
  - pass: "When SoD-violating role combinations require documented approval from a manager or security team before activation, downgrade to informational. Rationale: Approval workflows provide human oversight that compensates for SoD violations."
  - fail: "When SoD-violating roles can be self-assigned or activated without approval, retain severity. Rationale: Unapproved SoD violations enable fraud or abuse."
```

### Gate Check: Audit Trail

```yaml
check_audit_trail:
  - detection_patterns:
      - "audit.*log|activit.*log|role.*activ|privilege.*use|session.*log"
      - "certification|access.*review|entitlement.*review|quarterly.*review"
      - "user.*activit|anomaly.*detect|UEBA|user.*behavior"
  - pass: "When all role activations are logged with actor, timestamp, duration, and actions performed, AND logs are reviewed quarterly for SoD violations, downgrade severity. Rationale: Audited role activations with periodic review detect SoD abuse after the fact."
  - fail: "When role activations are not logged or are retained for less than 90 days, retain severity. Rationale: Unlogged SoD-violating role activations leave no audit trail for misuse detection."
```

## Resolution Path
1. Identify all SoD-violating role combinations through role mining
2. Implement approval workflows for all conflict role assignments
3. Enable audit logging for all role activations with 90+ day retention
4. Schedule quarterly SoD violation reviews using access certification tools

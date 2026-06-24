# Recurrence Test Control Validation Gate

## Purpose
Prevents false-positive findings when post-incident review (PIR) recommendations lack formal recurrence test controls, but compensating detective/preventive controls are already in place through existing monitoring, alerting, or change management processes.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A PIR recommendation to add recurrence testing controls is flagged as unimplemented
2. The incident root cause has compensating detective controls (monitoring, alerting, scheduled scans)
3. The team's existing change management process requires peer review and testing before production changes

### Gate Check: Compensating Detective Controls

```yaml
check_compensating_detective_controls:
  - detection_patterns:
      - "recurrence|re-occur|re.?occur|repeat.*incident"
      - "regression.*test|recurrence.*test|control.*test"
      - "monitor|alert|detect|scan|health.?check"
  - pass: "When the incident type is already covered by a monitoring alert, scheduled vulnerability scan, or health check that would detect a recurrence, downgrade to informational. Rationale: Existing detective controls provide recurrence detection without formal test automation."
  - fail: "When no compensating detective control exists and recurrence would only be detected through manual observation or user report, retain severity. Rationale: Silent recurrence of an incident without detection is a genuine control gap."
```

### Gate Check: Change Management Coverage

```yaml
check_change_management_coverage:
  - detection_patterns:
      - "change.*review|peer.*review|code.*review|PR.*review"
      - "CAB|change.*board|technical.*review|design.*review"
      - "staging|test.*environment|canary|blue.?green|feature.*flag"
  - pass: "When the fix was deployed through a change management process that requires peer review, staging validation, and rollback planning, downgrade severity. Rationale: Formal change management with testing gates reduces recurrence risk similarly to dedicated regression tests."
  - fail: "When the fix was deployed directly to production without peer review or staging validation, retain severity. Rationale: Direct-to-production fixes without review bypass the primary recurrence prevention mechanism."
```

## Resolution Path
1. Identify any existing monitoring alerts, scheduled scans, or health checks that would detect the same incident pattern
2. If compensating controls exist, document them in the PIR action tracker as the recurrence prevention strategy
3. If no compensating controls exist, file a feature request for a recurrence detection control (alert, scan, or test)
4. Ensure the incident fix was deployed through documented change management with peer review and a rollback plan
5. Set a 90-day calendar reminder to verify the compensating control is still effective

# API Key Unused-Age Gates

## Purpose
Prevents false-positive IAM findings when API keys that exceed the standard unused-age threshold are flagged as stale, but the keys are intentionally long-lived for specific use cases (CI/CD pipelines, legacy system integration, disaster recovery credentials) with compensating monitoring controls.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. An API key exceeds the standard unused-age threshold (>90 days since last use)
2. The key is documented for a specific use case that requires periodic manual use (DR credentials, break-glass keys, legacy system integration)
3. Key usage is monitored and alerts trigger on anomalous activity

### Gate Check: Documented Use Case

```yaml
check_documented_use_case:
  - detection_patterns:
      - "break.?glass|emergency.*access|disaster.*recovery|DR.*key"
      - "legacy.*integration|legacy.*system|vendor.*integration|legacy.*API"
      - "CI.*pipeline|deploy.*key|release.*key|artifact.*key"
  - pass: "When the key has a documented business justification in the key description or metadata, AND the justification requires the key to remain active beyond the standard rotation period, downgrade to informational. Rationale: Documented exception keys with business justification meet audit requirements for controlled exceptions."
  - fail: "When the key has no description, no metadata, or no documented justification for exceeding the unused-age threshold, retain severity. Rationale: Undocumented keys exceeding the unused-age threshold may indicate forgotten or orphaned credentials."
```

### Gate Check: Monitoring Coverage

```yaml
check_monitoring_coverage:
  - detection_patterns:
      - "last.*used|last.*access|last.*activity|last.*rotated"
      - "cloud.*trail|audit.*log|access.*log|key.*usage|credential.*report"
      - "alert|notif|anomaly|unusual.*activity|unexpected.*use"
  - pass: "When the key's usage is logged to a SIEM or audit system with alerts configured for anomalous use (new location, new service, out-of-hours), downgrade severity. Rationale: Monitored keys with alerting provide detective control that compensates for the reduced rotational hygiene."
  - fail: "When no usage monitoring or alerting exists for the key, retain severity. Rationale: Unmonitored keys beyond the unused-age threshold cannot detect misuse and must be rotated."
```

## Resolution Path
1. Add a meaningful description to the key documenting its purpose, owner, and expected use frequency
2. Set up CloudTrail/key usage logging and configure alerts for anomalous activity
3. Schedule the key for rotation at the next major release or DR test cycle
4. Document the exception in the IAM review report with the business justification and monitoring evidence

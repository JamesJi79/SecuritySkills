---
name: benign-sigma-rule-with-mapped-field
expected: pass
---

# Benign SIEM rule with platform data-model mapping

## Rule configuration

```
Sigma field: CommandLine
Platform field: DeviceProcessEvents.ProcessCommandLine
mapping_version: 2026-06
last_sample_count: 18422
unit_test_fixture: pass
```

## Evidence

| Field | Value |
|---|---|
| Data-model version | 2026-06 (current) |
| Field mapping verified | Yes — CommandLine maps to DeviceProcessEvents.ProcessCommandLine |
| Schema compatibility test | Pass — all 18,422 samples resolve |
| Negative test | Pass — null CommandLine returns expected no-match |

## Expected review result

Pass the schema-drift gates. The rule correctly references a mapped field, specifies the data-model version, and has verified fixture coverage.

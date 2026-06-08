---
name: vulnerable-sigma-rule-stale-mapping
expected: fail
---

# Vulnerable SIEM rule with stale data-model mapping

## Rule configuration

```
Sigma field: EventID
Platform field: WindowsEventLog.EventID
mapping_version: 2024-03
last_sample_count: 0
unit_test_fixture: none
```

## Evidence

| Field | Value |
|---|---|
| Data-model version | 2024-03 (stale — current is 2026-06) |
| Field mapping | EventID deprecated in v2025-12, replaced by EventIdentifier |
| Schema compatibility test | None — no test since migration |
| Fixture coverage | None — no sample events |

## Expected review result

Fail the review. The rule references a deprecated field through a stale mapping version, has no fixture coverage, and would silently fail to match events under the current data model.

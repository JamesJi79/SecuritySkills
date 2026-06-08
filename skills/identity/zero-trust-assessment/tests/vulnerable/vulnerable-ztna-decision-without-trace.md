---
name: vulnerable-ztna-decision-without-trace
expected: fail
---

# Vulnerable ZTNA access with missing policy trace and stale posture

## Access decision

```
ZTNA allow admin-panel
subject=any authenticated
device=not checked
device_posture_checked_at=2026-03-01T00:00Z
policy_decision_id=none
resource=admin-panel
```

## Evidence

| Field | Value |
|---|---|
| Policy decision trace | None — no decision ID recorded |
| Posture freshness | 3+ months stale — far exceeds typical 24h policy |
| Subject binding | "any authenticated" — no specific identity scope |
| Device binding | Not checked — any device accepted |
| Resource binding | admin-panel — broad scope, no sub-resource restriction |

## Expected review result

Fail the review. No policy decision tracing, stale device posture (3+ months), no device verification, and overly broad subject/resource binding create critical ZT gaps.

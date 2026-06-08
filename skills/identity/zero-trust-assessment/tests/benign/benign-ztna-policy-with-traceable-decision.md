---
name: benign-ztna-policy-with-traceable-decision
expected: pass
---

# Benign ZTNA policy with traceable decisions and fresh posture

## Access decision

```
ZTNA allow finance-app
subject=user:alice
device=compliant
device_posture_checked_at=2026-06-08T08:57Z
policy_decision_id=pdp-44af
resource=finance-app/invoices
```

## Evidence

| Field | Value |
|---|---|
| Policy decision trace | Yes — pdp-44af maps to policy version 2.3.1 |
| Posture freshness | 15 minutes ago — within 24h policy limit |
| Subject binding | user:alice — specific identity |
| Device binding | compliant device attestation |
| Resource binding | finance-app/invoices — scoped resource path |

## Expected review result

Pass the policy-decision trace gates. The decision is traceable, posture is fresh, and all three binding dimensions are enforced.

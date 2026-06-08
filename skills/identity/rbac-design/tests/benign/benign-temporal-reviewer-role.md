---
name: benign-temporal-reviewer-role
expected: pass
---

# Benign temporal role assignment

## Role configuration

```
role=quarter-end-finance-reviewer
assigned_until=2026-07-05
approver=finance-controller
reapproval_required=true
attribute_source=HRIS
project=fin-close-2026
```

## Evidence

| Field | Value |
|---|---|
| Expiry timestamp | Explicit (2026-07-05) |
| Enforced by system | Yes — API checks assigned_until before granting access |
| Re-approval workflow | Quarterly recertification with manager approval |
| Attribute source | HRIS — auto-revoked on termination |

## Expected review result

Pass the role expiry gates. The role has a defined scope, explicit expiry, enforcement mechanism, and re-approval cadence.

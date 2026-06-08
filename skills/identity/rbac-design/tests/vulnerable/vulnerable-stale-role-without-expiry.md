---
name: vulnerable-stale-role-without-expiry
expected: fail
---

# Vulnerable stale role assignment

## Role configuration

```
role=legacy-db-admin
assigned_until=none
attribute_source=manual_group
last_reviewed=2024-03-15
user_status=terminated_2025-01-20
```

## Evidence

| Field | Value |
|---|---|
| Expiry timestamp | None — permanent grant |
| User status | Terminated (15+ months ago) |
| Attribute source | Manual group — no HRIS sync |
| Last reviewed | 2024-03-15 (27+ months ago) |

## Expected review result

Fail the review. The role has no expiry, was assigned to a terminated user, uses manual attribute source without HRIS reconciliation, and has not been reviewed in over 2 years.

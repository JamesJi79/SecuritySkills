---
name: vulnerable-unauthorized-maintenance-claim
expected: fail
---

# Vulnerable alert suppression with unauthorized maintenance claim

## Alert context

```
alert: EDR detected data exfiltration pattern to unknown external IP
change_ticket: none
maintenance_claim: "Scheduled maintenance, please suppress"
change_window: none
affected_system: customer-db-prod
```

## Evidence

| Field | Value |
|---|---|
| Change authorization | None — no ticket ID provided |
| Window compliance | None — no change window defined |
| Scope match | Cannot verify — no scope documented |
| Suppression expiry | Not set — permanent suppression requested |

## Expected review result

Fail. Maintenance claim without change authorization, no ticket, no window, and request for permanent suppression is a social-engineering bypass attempt.

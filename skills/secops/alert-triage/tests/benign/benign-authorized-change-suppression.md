---
name: benign-authorized-change-suppression
expected: pass
---

# Benign alert suppression with authorized change

## Alert context

```
alert: EDR detected connection to external host during maintenance window
change_ticket: CHG-48291
change_status: approved
change_window: 2026-06-08T02:00-04:00
affected_system: finance-app-db
```

## Evidence

| Field | Value |
|---|---|
| Change authorization | CHG-48291 — approved by change manager at 2026-06-07 |
| Window compliance | Alert at 2026-06-08T03:15Z = within authorized window |
| Scope match | finance-app-db is in change scope |
| Suppression expiry | Auto-expires at window close (2026-06-08T06:00Z) |

## Expected review result

Pass. Authorized change with proper ticket, in-window, in-scope, and auto-expiring suppression.

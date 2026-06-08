---
name: vulnerable-dangling-cname-with-stale-check
expected: fail
---

# Vulnerable dangling CNAME record with stale verification

## DNS record

```
CNAME app.example.com -> old-cdn.example-cdn.com
vendor_reservation: unknown
http_status: 200 (generic landing page)
last_verified: 2025-01-15
```

## Evidence

| Field | Value |
|---|---|
| Vendor reservation | Unknown — no active account found for example-cdn.com |
| Claimable status | Claimable — generic 200 response, domain registration expired |
| Verification freshness | 18+ months — far exceeds typical policy limit |
| Reservation history | CDN contract ended 2024-12 |

## Expected review result

Fail the review. The CNAME points to a domain whose registration has expired, the target returns a generic response, and no verification has been performed in over 18 months.

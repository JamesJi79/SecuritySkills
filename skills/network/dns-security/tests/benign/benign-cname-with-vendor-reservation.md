---
name: benign-cname-with-vendor-reservation
expected: pass
---

# Benign CNAME record with confirmed vendor reservation

## DNS record

```
CNAME docs.example.com -> vendor.example-host.com
vendor_reservation: active
http_status: 404 (custom domain not claimable)
last_verified: 2026-06-08
```

## Evidence

| Field | Value |
|---|---|
| Vendor reservation | Active — account confirms domain binding |
| Claimable status | Not claimable — provider returns unclaimable 404 |
| Verification freshness | 0 days — verified today |
| Reservation history | Same provider since 2024 |

## Expected review result

Pass the dangling-record gates. The vendor reservation is active, the target is documented as unclaimable, and the verification is recent.

---
name: vulnerable-evidence-transfer-without-custody
expected: fail
---

# Vulnerable evidence transfer missing custody chain and authorization

## Incident evidence

```
containment_action: quarantine server
legal_hold_ticket: none
evidence_package: disk_image.dd (no hash)
external_ir_transfer: email attachment
```

## Evidence

| Field | Value |
|---|---|
| Legal hold authorization | None — no hold ticket referenced |
| Hold vs collection timing | No hold — evidence collected without legal authorization |
| Custody hash chain | None — no hash, no signatures, no chain |
| Recipient acknowledgment | None — emailed as attachment without receipt tracking |

## Expected review result

Fail the review. No legal hold authorization, no evidence hash or custody chain, and email-based transfer without recipient tracking create significant evidentiary risk.

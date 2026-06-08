---
name: benign-legal-hold-with-custody-chain
expected: pass
---

# Benign incident response with proper legal hold and custody chain

## Incident evidence

```
containment_action: isolate host after memory capture
legal_hold_ticket: LH-2026-184
evidence_package: disk.img.sha256 + chain_of_custody.pdf
external_ir_transfer: encrypted archive with recipient receipt
```

## Evidence

| Field | Value |
|---|---|
| Legal hold authorization | LH-2026-184 — issued by legal@company.com at 2026-06-08T09:00Z |
| Hold vs collection timing | Hold issued before evidence collection (09:00 vs 09:15) |
| Custody hash chain | disk.img.sha256 → custodian sig → encrypted transfer → recipient sig |
| Recipient acknowledgment | Signed receipt from external IR provider at 2026-06-08T11:30Z |

## Expected review result

Pass the legal-hold gates. Proper authorization, chain-of-custody, and recipient acknowledgment are all documented.

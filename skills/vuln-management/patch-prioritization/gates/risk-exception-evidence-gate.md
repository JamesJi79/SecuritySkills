# Risk Exception Evidence Matrix Gate

## Purpose
Prevents false-positive "risk exception approved" findings when patch exceptions capture comprehensive evidence (business justification, compensating controls, residual risk, approval date, expiration/review date, policy limit checks) even when the exception ID and CVE fields alone appear sufficient. The current skill's output table omits the revalidation evidence needed to prevent expired exceptions from hiding SLA breaches.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "risk exception inadequate" or "exception missing revalidation" as Medium/High
2. The exception record includes evidence fields beyond ID/CVE/SLA/deadline/approver/status
3. The evidence includes business justification, compensating controls, residual risk assessment, and expiration date

### Gate Check: Exception Completeness

```yaml
check_exception_completeness:
  - detection_patterns:
      - "risk.*exception|patch.*exception|SLA.*waiver|deadline.*extend"
      - "exception.*ID|CVE.*exception|approver|exception.*status"
  - additional_evidence_required:
      - "Business justification for the exception"
      - "Compensating controls in place"
      - "Residual risk after exception"
      - "Approval date and approver identity"
      - "Expiration or re-review date"
      - "Policy limit exceeded? (yes/no with justification)"
  - pass: "Exception record includes ALL six evidence fields → Downgrade to Low (Informational). Rationale: Comprehensive exception evidence enables proper governance and prevents exception creep."
  - fail: "Exception record missing any of the six evidence fields → Keep severity. Incomplete exceptions create SLA breach hiding risk."
```

### Gate Check: Expiration Monitoring

```yaml
check_expiration_monitoring:
  - detection_patterns:
      - "expir.*date|re.*review.*date|exception.*age|stale.*exception"
      - "auto.*revoke|exception.*expir|review.*cycle"
  - pass: "Exceptions have expiration dates AND automated revalidation triggers → Accept. Expired exceptions will be identified and re-reviewed."
  - fail: "No expiration date OR no revalidation process → Escalate to High. Without expiration, exceptions can persist indefinitely after the justification expires."
```

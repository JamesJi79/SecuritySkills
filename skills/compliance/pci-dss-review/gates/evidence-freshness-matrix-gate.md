# PCI DSS Evidence Freshness Matrix Gate

## Purpose
Prevents false-positive "evidence sufficient" findings when PCI DSS assessment evidence includes date, owner, testing procedure, sample scope, period covered, and freshness status—even when the evidence field alone appears populated. The current skill accepts any evidence without requiring provenance metadata.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "evidence insufficient" or "stale evidence" as High
2. Evidence records include date, owner, and testing procedure
3. Sample scope and period covered are documented

### Gate Check: Evidence Provenance

```yaml
check_evidence_provenance:
  - detection_patterns:
      - "evidence.*date|evidence.*owner|testing.*procedure|sample.*scope"
      - "evidence.*freshness|assessment.*evidence|PCI.*evidence"
      - "examine|observe|interview|test.*procedure"
  - required_fields:
      - "Evidence date (when was it collected?)"
      - "Evidence owner (who collected it?)"
      - "Testing procedure (examine/observe/interview/test)"
      - "Sample scope (which systems, users, transactions?)"
      - "Period covered (what time range does it represent?)"
      - "Freshness status (current/stale/expired)"
  - pass: "Evidence includes ALL six provenance fields → Downgrade to Low (Informational). Rationale: Complete provenance enables assessor verification and evidence re-use across assessment cycles."
  - fail: "Evidence missing any provenance field → Keep severity. Incomplete provenance creates PCI assessment readiness gaps."
```

### Gate Check: Evidence Rotation

```yaml
check_evidence_rotation:
  - detection_patterns:
      - "evidence.*expir|evidence.*rotat|re.*collect|refresh.*evidence"
      - "annual.*review|quarterly.*evidence|evidence.*age"
  - pass: "Evidence has defined rotation schedule OR freshness status is actively tracked → Accept. Evidence rotation ensures assessment evidence remains current."
  - fail: "No evidence rotation or freshness tracking → Escalate. Stale evidence can pass a requirement that no longer holds."
```

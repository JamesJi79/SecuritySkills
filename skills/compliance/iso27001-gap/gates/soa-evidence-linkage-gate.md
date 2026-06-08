# Statement of Applicability Evidence Linkage Gate

## Purpose
Prevents false-positive "SoA complete" findings when each SoA control decision is linked to a specific risk, legal/contractual requirement, treatment decision, evidence owner, evidence artifact, and evidence date. The current skill does not require auditor-verifiable linkage from SoA entries to Clause 6.1.3 risk treatment evidence.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "SoA control missing evidence linkage" as High
2. Each SoA entry links to at least one risk or legal requirement
3. Evidence artifacts exist and are dated for each included control

### Gate Check: SoA-Risk Linkage

```yaml
check_soa_risk_linkage:
  - detection_patterns:
      - "SoA.*evidence|Statement.*Applicability|Annex.*A.*control"
      - "risk.*treatment|Clause.*6\.1\.3|control.*selection"
      - "included|excluded|applicability|justification.*control"
  - required_linking:
      - "Risk ID or legal/contractual requirement reference"
      - "Treatment decision (accept, mitigate, transfer, avoid)"
      - "Evidence owner"
      - "Evidence artifact (policy, procedure, screenshot, report, log)"
      - "Evidence date"
  - pass: "Each SoA entry links to ALL five evidence fields → Downgrade to Low (Informational). Rationale: Auditor-verifiable linkage demonstrates ISO 27001 Clause 6.1.3 compliance."
  - fail: "SoA entry missing any linkage field → Keep severity. Unlinked SoA entries cannot be auditor-verified."
```

### Gate Check: Exclusion Justification

```yaml
check_exclusion_justification:
  - detection_patterns:
      - "excluded|not.*applicable|N/A|out.*of.*scope"
      - "justification.*exclusion|reason.*not.*included"
  - pass: "Excluded controls have documented justification referencing risk assessment or scope boundary → Accept. ISO 27001 requires exclusion justification."
  - fail: "Excluded control without documented justification → Escalate. Unexplained exclusions fail ISO 27001 Clause 6.1.3 requirements."
```

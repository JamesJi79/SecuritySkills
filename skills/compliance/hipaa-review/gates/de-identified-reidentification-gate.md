# De-Identified Dataset Reidentification Risk Gate

## Purpose
Prevents false-positive findings when de-identification methods document expert determination or safe-harbor field removal, by requiring the reviewer to verify that the dataset cannot be reidentified through linkage analysis before classifying the pattern as compliant.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Code documents a de-identification method (expert determination determination or safe-harbor under 45 CFR 164.514(b))
2. ePHI fields are flagged as removed or masked in the system design
3. No linkage analysis or reidentification risk assessment has been performed

### Gate Check: Reidentification Linkage Analysis

```yaml
check_reidentification_linkage:
  - detection_patterns:
      - "de.?identif(y|ied|ication)"
      - "safe.?harbor"
      - "expert determination"
      - "PHI removed|ePHI masked"
      - "anonymized data set"
  - pass: >
      "Reidentification risk assessment performed confirming residual
      reidentification risk below acceptable threshold ($\leq 0.05$ confidence).
      Rare ZIP/date/device combinations and joinable support-ticket identifiers
      have been explicitly excluded or suppressed."
    Rationale: "Safe-harbor and expert determination are valid de-identification
      methods under HIPAA, but only when the effective risk of reidentification
      has been measured and documented. A static field redaction without linkage
      analysis is not sufficient."
  - fail: >
      "No reidentification risk assessment found, or assessment does not cover
      rare-ZIP/date/device combinations and cross-system join paths (e.g.,
      support tickets containing identifiers). Recommend performing a formal
      reidentification risk assessment before accepting de-identified status."
```

### Gate Check: Residual Identifiability Audit

```yaml
check_residual_identifiability:
  - detection_patterns:
      - "(ZIP|zip|postal) code"
      - "date of birth|admission date|discharge date"
      - "device ID|device identifier"
      - "support ticket|ticket ID"
  - pass: >
      "All residual quasi-identifiers (rare ZIP/date/device combinations,
      support-ticket cross-references) have been audited and eliminated or
      generalized below reidentification threshold."
    Rationale: "HIPAA safe-harbor requires removal of 18 specific identifiers,
      but rare combinations of remaining quasi-identifiers can still uniquely
      identify patients. Linkage with operational data (support tickets,
      billing records) is a common reidentification vector."
  - fail: >
      "Residual quasi-identifiers present without documented generalization or
      suppression. Reidentification via rare-ZIP/date/device combination or
      support-ticket join is possible. Require further de-identification or
      explicit risk acceptance."
```

## Resolution Path
1. Perform a reidentification risk assessment using a statistical linkage method (e.g., k-anonymity, l-diversity)
2. Document the residual reidentification risk level and acceptable threshold
3. Remove or generalize any quasi-identifiers that fall below the threshold
4. If de-identification cannot achieve acceptable risk, implement a Limited Data Set with a data use agreement under 45 CFR 164.514(e)

# Legal Privilege Boundary Gate

## Purpose
Prevents false-positive post-incident review findings when legal privilege boundaries in incident documentation could expose sensitive communications, but the organization has a documented legal hold procedure and privilege review process for incident artifacts.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A PIR finding flags that incident documentation may contain legally privileged information
2. The organization has a legal hold procedure for incident artifacts
3. Legal counsel reviews privileged materials before inclusion in the PIR report

### Gate Check: Privilege Review Process

```yaml
check_privilege_review_process:
  - detection_patterns:
      - "legal.*privilege|attorney.*client|privileged.*communicat|work.*product"
      - "legal.*hold|litigation.*hold|preservation.*notice"
      - "general.*counsel|legal.*review|outside.*counsel|breach.*coach"
  - pass: "When the PIR process requires legal counsel to review and redact privileged materials before inclusion in the report, downgrade to informational. Rationale: A documented privilege review process ensures sensitive legal communications are protected while allowing the PIR to proceed."
  - fail: "When incident documentation is published without legal review for privilege-protected content, retain severity. Rationale: Unreviewed incident documentation may waive attorney-client privilege."
```

## Resolution Path
1. Engage legal counsel at the start of the PIR process to identify privileged communications
2. Create a separate privileged appendix for legally sensitive findings (not included in the distributed PIR)
3. Document the privilege review step in the PIR procedure

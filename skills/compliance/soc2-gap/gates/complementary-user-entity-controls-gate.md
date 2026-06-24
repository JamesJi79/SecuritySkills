# Complementary User Entity Controls Evaluation Gate

## Purpose
Prevents false-positive SOC 2 gap findings when user entity controls are not formally documented in the service organization's control matrix, but compensating controls at the user entity level are addressed through contractual terms, shared responsibility matrices, and user entity responsibilities documentation.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A SOC 2 gap assessment flags missing complementary user entity controls (CUEC) in the service organization's control matrix
2. The organization has a published shared responsibility matrix or user responsibilities document
3. Customer contracts include security requirements and user entity obligations

### Gate Check: Shared Responsibility Documentation

```yaml
check_shared_responsibility_documentation:
  - detection_patterns:
      - "complementary.*user.*entity.*control|CUEC|user.*entity.*responsib"
      - "shared.*responsib|responsibility.*matrix|shared.*security.*model"
      - "customer.*responsib|client.*responsib|tenant.*responsib"
  - pass: "When the organization publishes a shared responsibility matrix that explicitly states user entity obligations for the in-scope controls (access management, encryption configuration, incident notification), downgrade to informational. Rationale: A published shared responsibility model satisfies the intent of CUEC documentation even when not in the formal control matrix."
  - fail: "When no shared responsibility documentation exists and user entity obligations are not communicated to customers, retain severity. Rationale: Undocumented user entity responsibilities create control gaps that may lead to audit findings for both the service organization and its customers."
```

### Gate Check: Contractual Security Requirements

```yaml
check_contractual_security_requirements:
  - detection_patterns:
      - "SLA|service.*level.*agreement|terms.*of.*service|customer.*agreement"
      - "security.*appendix|data.*protection.*addendum|DPA|SOW"
      - "penetration.*test|audit.*right|security.*review|compliance.*cert"
  - pass: "When customer contracts or data protection addenda include user entity security obligations (maintain access controls, encrypt data, report incidents), downgrade severity. Rationale: Contractually binding security obligations provide equivalent control coverage to formally documented CUECs."
  - fail: "When contracts do not address user entity security obligations or data protection requirements, retain severity. Rationale: Without contractual security requirements, user entity controls exist only informally and are not auditable."
```

## Resolution Path
1. Map each in-scope SOC 2 control to the corresponding user entity responsibility in the shared responsibility matrix
2. Ensure the shared responsibility matrix is published in the customer portal and referenced in contracts
3. Add a CUEC section to the SOC 2 control matrix that cross-references the shared responsibility documentation
4. Review customer contracts to confirm security obligations are included and enforceable

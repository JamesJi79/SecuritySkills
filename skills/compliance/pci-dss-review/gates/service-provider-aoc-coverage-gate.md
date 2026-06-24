# Service Provider AOC Coverage Gate

## Purpose
Prevents false-positive PCI DSS findings when a service provider's Attestation of Compliance (AOC) does not explicitly list the customer's in-scope services, but the provider's SOC 2 Type II or PCI DSS ROC covers the relevant service infrastructure and compensating controls are in place.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A PCI DSS assessment flags that a service provider's AOC does not explicitly cover the cardholder data environment (CDE) services used
2. The service provider has a SOC 2 Type II report or PCI DSS ROC that covers the relevant service infrastructure
3. The customer has contractual assurances that the provider's CDE infrastructure is in scope of their PCI assessment

### Gate Check: Provider Assessment Coverage

```yaml
check_provider_assessment_coverage:
  - detection_patterns:
      - "AOC|attestation.*of.*compliance|ROC|report.*on.*compliance"
      - "SOC.*2|SOC.*3|Type.*II|service.*organization.*control"
      - "PCI.*scope|CDE.*infrastructure|cardholder.*data.*environment"
  - pass: "When the provider's SOC 2 Type II report or PCI ROC includes the specific service types being used (cloud hosting, payment processing, SaaS) and the report was issued within the last 12 months, downgrade to informational. Rationale: A current SOC 2 or PCI assessment covering the service type provides equivalent assurance to a service-specific AOC."
  - fail: "When the provider has no current (<12 month) SOC 2 or PCI assessment, or the assessment explicitly excludes the service type being used, retain severity. Rationale: Without current third-party assessment coverage, the provider's CDE controls are unverified."
```

### Gate Check: Contractual Control Assurance

```yaml
check_contractual_control_assurance:
  - detection_patterns:
      - "service.*provider|vendor|third.?party|sub.?processor|sub.?service"
      - "contract.*section|security.*appendix|responsibility.*matrix"
      - "right.*to.*audit|audit.*report|security.*certification"
  - pass: "When the customer contract includes the provider's commitment to maintain PCI DSS compliance or equivalent security framework for the service infrastructure, AND grants the customer right-to-audit or report access, downgrade severity. Rationale: Contractual compliance commitments with audit rights provide formal assurance even without an explicit AOC."
  - fail: "When the contract does not include compliance commitments, security framework requirements, or audit rights for the service, retain severity. Rationale: Without contractual security assurances, the customer cannot verify provider CDE controls."
```

## Resolution Path
1. Request the provider's most recent SOC 2 Type II report or PCI ROC and verify it covers the relevant service infrastructure
2. Map the in-scope CDE services to the provider's assessed control framework
3. If the AOC gap persists, request a service-specific AOC letter from the provider's compliance team
4. Document the compensating controls (SOC 2 coverage + contractual assurances) in the PCI DSS responsibility matrix

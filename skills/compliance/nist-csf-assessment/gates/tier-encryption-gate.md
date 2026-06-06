# Tier-Based Encryption Assessment Gate

## Purpose
Prevents false-positive "Tier 1" maturity gaps for small organizations flagged for the absence of enterprise-managed encryption keys (CMEK) by providing size-appropriate encryption assessment criteria aligned with organizational maturity.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags PR.DS-01 (Data-at-Rest protection) as "Tier 1" or "significant gap"
2. The primary evidence is absence of customer-managed encryption keys (CMEK), hardware security modules (HSM), or external key management system (KMS)
3. The organization size or maturity context indicates it is small-to-medium (SME) or early-stage (Tier 1-2 overall)

### Gate Check: Organization Size Classification

```yaml
check_organization_size:
  - description: "Determine the appropriate encryption assessment tier based on org size"
  - criteria:
      small_business:
        indicators:
          - "Fewer than 100 employees"
          - "No dedicated security team"
          - "Annual revenue under $50M"
          - "Cloud-native with managed services (no self-managed infrastructure)"
        assessment: "Use SME Assessment Path below"
      medium_business:
        indicators:
          - "100-1000 employees"
          - "Has security team (1-5 people)"
          - "Annual revenue $50M-$500M"
          - "Mix of managed and self-managed infrastructure"
        assessment: "Use Standard Assessment Path"
      enterprise:
        indicators:
          - "1000+ employees"
          - "Dedicated security team (10+ people)"
          - "Annual revenue $500M+"
          - "Self-managed infrastructure with dedicated compliance team"
        assessment: "Use Enterprise Assessment Path (CMEK required)"
```

### Gate Check: SME Encryption Assessment (Size-Appropriate)

```yaml
check_sme_encryption:
  - description: "For small organizations, evaluate encryption controls proportional to resources"
  - acceptance_criteria:
      - "Cloud-managed encryption keys (AWS EBS/SSE-S3, Azure SSE, GCP CMEK with Google-managed keys) → Accept. Rationale: AWS/Azure/GCP-managed keys meet ISO 27001 and SOC 2 encryption requirements. Customer-managed keys add operational complexity without proportional security benefit for small orgs."
      - "Encryption at rest enabled on all data stores (RDS, S3, EBS, DynamoDB, Cosmos DB, Cloud Storage) → Accept. The key management layer (service-managed vs. customer-managed) does not affect the confidentiality of data-at-rest."
      - "TLS 1.2+ for data-in-transit with valid certificates → Accept"
      - "Secret management via cloud-native secret store (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) → Accept. These services handle key rotation and access auditing without requiring a dedicated HSM."
  - sme_tier_mapping:
      - "All cloud-managed encryption controls in place → Tier 3 (Repeatable) for PR.DS-01"
      - "Partial encryption (some services not encrypted) → Tier 2 (Risk Informed)"
      - "No encryption at rest enabled → Tier 1 (Partial) — this IS a genuine gap"
```

### Gate Check: Enterprise Encryption Assessment (CMEK Required)

```yaml
check_enterprise_encryption:
  - description: "For enterprise organizations, customer-managed keys are the expected baseline"
  - requirements:
      - "Customer-managed encryption keys (CMEK) with automatic rotation (90-day max)"
      - "HSM-backed key storage (AWS CloudHSM, Azure Dedicated HSM, GCP Cloud HSM)"
      - "Key access audit logging with separation of duties"
      - "Key revocation and disaster recovery procedures documented and tested"
      - "Compliance with applicable regulatory frameworks (PCI DSS, HIPAA, FedRAMP)"
  - enterprise_tier_mapping:
      - "All CMEK requirements met → Tier 4 (Adaptive)"
      - "CMEK in place but missing audit/rotation → Tier 3 (Repeatable)"
      - "No CMEK, using service-managed keys → Tier 2 (Risk Informed) — flag as improvement opportunity"
      - "No encryption at rest → Tier 1 (Partial)"
```

## Remediation Steps

When this gate adjusts a PR.DS-01 assessment:

1. **Document the tier adjustment** — "PR.DS-01 assessment adjusted from Tier 1 to Tier [X]. Rationale: Organization is [small/medium/enterprise]. For SMEs, cloud-managed encryption keys satisfy data-at-rest protection requirements. Customer-managed keys are not cost-justified at this scale."
2. **Provide the appropriate recommendation** — For SMEs, recommend: "Continue using cloud-managed encryption keys. Enable encryption on any unencrypted resources. Re-evaluate CMEK adoption when the organization grows to [medium/enterprise] scale or compliance requirements change."
3. **Flag genuine gaps** — If the organization has NO encryption at rest on any data store, this IS a Tier 1 gap regardless of size.
4. **Add roadmap item** — "Consider CMEK evaluation in [12-24 months] as part of maturity growth planning."

## False Positive Prevention

- Do NOT apply SME assessment to organizations handling regulated data (PCI DSS, HIPAA, FedRAMP, GDPR Article 32) — regulatory requirements may mandate CMEK regardless of organization size.
- Do NOT apply SME assessment to enterprises that are divisions of larger organizations — assess at the parent organization's maturity level.
- Do NOT downgrade findings related to data-in-transit encryption (PR.DS-02) — TLS is mandatory for all organizations regardless of size.

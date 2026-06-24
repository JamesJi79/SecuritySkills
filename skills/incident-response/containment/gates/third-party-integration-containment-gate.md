# Third-Party Integration Containment Gate

## Purpose
Prevents false-positive containment findings when third-party integrations (SaaS APIs, webhooks, OAuth apps) cannot be immediately disabled during incident response, but the organization has compensating controls (API key rotation, OAuth token revocation, integration deactivation) that can be executed within the containment SLA.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A containment review flags that third-party integrations cannot be rapidly disabled during an incident
2. The integrations are cataloged with API key IDs, OAuth app IDs, or webhook URLs
3. Deactivation procedures are documented and tested for each critical integration

### Gate Check: Integration Catalog

```yaml
check_integration_catalog:
  - detection_patterns:
      - "third.?party.*integrat|SaaS.*integrat|API.*integrat|OAuth.*app|webhook"
      - "integrat.*catalog|integrat.*inventory|connected.*app|app.*director"
      - "API.*key.*rotat|token.*revocat|integrat.*deactivat|app.*remov"
  - pass: "When all third-party integrations are cataloged in an inventory with API key IDs or OAuth app IDs, and deactivation procedures are documented, downgrade to informational. Rationale: A documented integration inventory with deactivation procedures enables containment within the SLA."
  - fail: "When no integration catalog exists, or deactivation procedures are undocumented, retain severity. Rationale: Undocumented integrations cannot be rapidly disabled during an incident."
```

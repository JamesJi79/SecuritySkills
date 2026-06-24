# Keyless Workload Identity Gate

## Purpose
Prevents false-positive IAM findings when cloud workloads use keyless identity (OIDC, workload identity federation, instance metadata credentials) instead of long-lived service account keys, but the keyless approach is the more secure alternative.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags the absence of a service account key or access key for a workload
2. The workload uses OIDC-based identity federation (Workload Identity Federation, OIDC provider, IMDS credentials)
3. The cloud provider supports keyless authentication for the workload's runtime environment

### Gate Check: OIDC Federation

```yaml
check_oidc_federation:
  - detection_patterns:
      - "workload.*identity|OIDC|OpenID.*Connect|identity.*federation"
      - "IMDS|instance.*metadata|metadata.*credentials|STS.*AssumeRoleWithWebIdentity"
      - "keyless|no.?key|key.?free|token.*exchange"
  - pass: "When the workload authenticates via OIDC identity federation (GCP Workload Identity Federation, AWS IAM Roles Anywhere, Azure Workload Identity, GitHub Actions OIDC), downgrade to informational. Rationale: Keyless OIDC identity is more secure than long-lived keys - shorter credential lifetime, automatic rotation, no secret management burden."
  - fail: "When the workload uses static credentials (file-based, environment variable) without any identity federation mechanism, retain severity. Rationale: Static workload credentials without keyless alternatives are a genuine credential management risk."
```

### Gate Check: Credential Lifetime

```yaml
check_credential_lifetime:
  - detection_patterns:
      - "access.*key|secret.*key|service.*account.*key|API.*key"
      - "credential.*rotation|key.*rotation|secret.*rotat"
      - "token.*expir|session.*duration|credential.*lifetime"
  - pass: "When any static credential used has automatic rotation (<90 days) and the workload is actively migrating to keyless identity with a documented plan, downgrade severity. Rationale: Short-lived rotating credentials with a migration plan represent acceptable interim risk."
  - fail: "When static credentials are older than 90 days without rotation and there is no keyless migration plan, retain severity. Rationale: Long-lived unrotated workload credentials are a standing vulnerability."
```

## Resolution Path
1. Identify the workload's runtime environment (GKE, ECS, Azure, GitHub Actions, on-prem) and map available OIDC identity options
2. If using GCP, enable Workload Identity Federation for the workload's service account
3. If using AWS, configure IAM Roles Anywhere or ECS task IAM roles
4. If using Azure, enable Workload Identity Federation with OIDC token exchange
5. Document the migration timeline and set credential rotation to <30 days as interim control

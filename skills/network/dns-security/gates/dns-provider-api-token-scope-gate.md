# DNS Provider API Token Scope Gate

## Purpose
Prevents false-positive findings when DNS provider API tokens with broader-than-necessary scopes are flagged as over-privileged, but the token's effective permissions are constrained by the provider's resource-level IAM or organization-level policies.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A DNS provider API token (Cloudflare API token, AWS IAM access key, Azure service principal, GCP service account key) has broader scopes than the minimum required for its function
2. The token is used for DNS record management (DDNS, Let's Encrypt DNS-01, Terraform DNS provider)
3. The provider supports resource-level or condition-based policy constraints

### Gate Check: Resource-Level Constraint

```yaml
check_resource_level_constraint:
  - detection_patterns:
      - "cloudflare.*api.*token|dns.*api.*key|route53.*key"
      - "iam.*access.*key|service.*principal|service.*account"
      - "dns.*zone|managed.*dns|record.*set"
  - pass: "When the token is scoped to specific DNS zones or resources via provider-native IAM (Cloudflare Zone API token, AWS IAM condition keys, GCP service account IAM binding), downgrade to informational. Rationale: Resource-level policies effectively limit the token's blast radius despite broad API scope."
  - fail: "When the token has account-level or organization-level scope AND no resource-level policy binds it to specific zones, retain severity. Rationale: Unconstrained DNS API tokens with broad scope can modify any DNS record in the account."
```

### Gate Check: Token Rotation and Monitoring

```yaml
check_token_rotation_and_monitoring:
  - detection_patterns:
      - "access.*key|api.*key|secret.*key|token"
      - "rotation|rotat|renew|refresh"
      - "cloudtrail|audit.*log|access.*log|activity.*log"
  - pass: "When the token is rotated within 90 days and its usage is monitored via provider audit logs with alerts for anomalous activity, downgrade severity. Rationale: Short-lived tokens with audit coverage limit the window and detectability of misuse."
  - fail: "When the token is older than 90 days without rotation, or audit logging is not enabled for the token's actions, retain severity. Rationale: Long-lived unmonitored tokens present an unacceptable risk of undetected credential misuse."
```

## Resolution Path
1. Identify the specific DNS zones or resources the token needs to manage for its documented function
2. Create a provider-scoped token or IAM policy that restricts the token to only those zones/resources
3. Set a 90-day rotation reminder using the provider's token expiration feature or a calendar reminder
4. Enable CloudTrail/Audit Logs for the token's API actions and set up alerts for zone deletions and record modifications

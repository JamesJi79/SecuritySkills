# Vault Checkout Recording Gate

## Purpose
Prevents false-positive privileged access findings when vault credential checkouts are not individually recorded or approved, but the vault system provides post-checkout auditing, automatic credential rotation, and session recording that compensate for pre-checkout approval gaps.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A privileged access vault (CyberArk, HashiCorp Vault, AWS Secrets Manager) allows credential checkouts without per-request approval
2. Post-checkout auditing captures who checked out which credential at what time
3. Credentials are automatically rotated after each checkout

### Gate Check: Post-Checkout Audit

```yaml
check_post_checkout_audit:
  - detection_patterns:
      - "vault.*checkout|credential.*checkout|secret.*retriev|password.*checkout"
      - "CyberArk|HashiCorp.*Vault|AWS.*Secrets.*Manager|Azure.*Key.*Vault"
      - "audit.*log|checkout.*log|retrieval.*log|secret.*access.*log"
  - pass: "When every credential checkout is logged to an immutable audit trail that includes: who, which credential, timestamp, source IP, and purpose. Logs retained 1+ year. Downgrade to informational. Rationale: Post-checkout audit trails provide forensic accountability equivalent to pre-approval."
  - fail: "When checkout audit logs do not capture source identity or purpose, or logs are retained less than 90 days, retain severity. Rationale: Insufficient checkout audit trails prevent attribution of credential use."
```

### Gate Check: Auto-Rotation

```yaml
check_auto_rotation:
  - detection_patterns:
      - "automatic.*rotat|post.?checkout.*rotat|per.?use.*rotat|one.?time.*password"
      - "credential.*rotat|password.*rotat|secret.*rotat|key.*rotat"
      - "ephemeral.*credential|dynamic.*secret|lease.*duration|TTL.*credential"
  - pass: "When credentials are automatically rotated immediately after each checkout (per-use rotation), OR credentials are ephemeral/dynamic with a TTL, downgrade severity. Rationale: Per-use credential rotation or ephemeral credentials prevent credential reuse even without per-request approval."
  - fail: "When credentials are not rotated after checkout or are rotated on a fixed schedule (weekly/monthly), retain severity. Rationale: Fixed-schedule rotation leaves a window for credential reuse after legitimate checkout."
```

## Resolution Path
1. Enable immutable audit logging for all vault credential checkouts
2. Configure automatic credential rotation on check-in (per-use rotation) for all privileged accounts
3. For vaults supporting dynamic secrets (HashiCorp Vault), migrate static credentials to dynamic/TTL-based secrets
4. Review vault audit logs monthly for anomalous checkout patterns

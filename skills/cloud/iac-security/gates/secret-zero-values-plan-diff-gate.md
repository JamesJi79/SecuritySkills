# Secret Zero-Values in Plan Diffs Gate

## Purpose
Prevents false-positive findings when plan review treats unknown/sensitive/zero values as risk until source verified, by requiring the reviewer to verify that redacted or sensitive values in IaC plan diffs are not silently masking dangerous drift.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. IaC plan diff contains sensitive-computed- or unknown-values that are redacted
2. Reviewer treats (sensitive) or (known after apply) values as acceptable without verification
3. Provider default changes could set a secret field to an empty string or other insecure value

### Gate Check: Sensitive Value Source Verification

```yaml
check_sensitive_value_source:
  - detection_patterns:
      - "\(sensitive\)|sensitive value|redacted"
      - "known after apply|computed"
      - "secret|password|token|key|credential"
      - "(empty|"")|null|0|false"
  - pass: >
      "Every (sensitive) value in the plan diff has been verified against its
      authoritative source (vault, parameter store, secrets manager, or
      encrypted variable file). Changes from a known value to (sensitive) or
      (known after apply) are treated as high-signal events requiring explicit
      confirmation that the value was not replaced with an empty or default
      value."
    Rationale: "Sensitive value redaction in plan diffs is necessary for
      security but creates a visibility gap. A secret changed to an empty
      string, or a provider default that zeroes out a credential field, is
      invisible in the diff. Provider behavioral changes (e.g., switching from
      required to optional) can silently disable authentication."
  - fail: >
      "One or more (sensitive) values could not be verified against an
      authoritative source. The change from a known value to (sensitive) or
      (known after apply) may indicate a secret was inadvertently replaced with
      an empty or default value. Recommend checking the authoritative secret
      source and verifying the value was preserved."
```

### Gate Check: Provider Default Drift Detection

```yaml
check_provider_default_drift:
  - detection_patterns:
      - "provider|resource|data source"
      - "optional|default|deprecated"
      - "version|upgrade|migration"
  - pass: >
      "Provider/resource version changes have been reviewed for behavioral
      changes that could alter default values for security-sensitive fields.
      Upcoming provider versions are checked against changelogs for security-
      relevant default changes."
    Rationale: "Provider upgrades (especially major versions) can change field
      defaults. A field that was required becoming optional with a zero-value
      default (empty string, 0, false) can silently disable authentication,
      encryption, or access controls. This is invisible in the plan diff."
  - fail: >
      "Provider or resource version changes present in the plan, but no review
      of behavioral default changes has been performed. Recommend reviewing
      provider changelogs for security-relevant default modifications."
```

## Resolution Path
1. Maintain an authoritative secret source (vault/parameter store) and verify (sensitive) plan values against it
2. Treat any change from known value to (sensitive)/(known after apply) as a high-signal review event
3. Review provider/resource version changelogs for security-relevant default changes before upgrading

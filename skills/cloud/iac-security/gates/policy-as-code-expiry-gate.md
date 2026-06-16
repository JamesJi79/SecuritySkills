# Policy-as-Code Exception Expiry Gate

## Purpose
Prevents false-positive findings when IaC policy exceptions require owner, reason, scope, and expiry enforced in CI, by requiring the reviewer to verify that exceptions cannot persist indefinitely or suppress unrelated resources without periodic revalidation.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. IaC policy scanner exceptions (Checkov skip, tfsec ignore, OPA exception) are defined
2. Exceptions document owner, reason, scope, and expiry
3. Exception TTL is not enforced or exception silently persists after mitigation

### Gate Check: Exception Lifecycle Governance

```yaml
check_exception_lifecycle:
  - detection_patterns:
      - "checkov:skip|tfsec:ignore|#nosec"
      - "exception|suppress|skip"
      - "expir(y|ation|es)|TTL"
      - "owner|reason|scope"
      - "OPA exception|policy exclusion"
  - pass: >
      "Every exception has an explicit TTL (maximum 90 days recommended), is
      reviewed by a second party at creation time, is associated with a
      documented remediation ticket or issue, and CI enforces mandatory
      revalidation on expiry. Exceptions without TTL are automatically expired
      by CI pipeline after the maximum period."
    Rationale: "Policy exceptions with documented owner/reason/scope/expiry are
      a legitimate governance mechanism when properly lifecycle-managed. The
      risk is silent persistence — an exception that outlives the condition that
      justified it becomes a permanent security gap."
  - fail: >
      "One or more exceptions lack a TTL, are not enforced by CI revalidation,
      or are not associated with a remediation ticket. Exceptions with broad
      scope (matching unrelated resource types) present additional risk of
      suppressing valid findings. Recommend adding enforced TTL with CI
      mandatory revalidation and scoping exceptions to the minimal resource
      pattern."
```

### Gate Check: Exception Scope Narrowing

```yaml
check_exception_scope:
  - detection_patterns:
      - "resource:.*\*|resource:.*all|path:.*\*"
      - "broad exception|wildcard|all resources"
      - "skip_all|ignore_all|suppress all"
  - pass: >
      "Each exception is scoped to the specific resource, rule, or path that
      produced the finding. Wildcard or resource-group-level exceptions are
      not used. The exception path matches exactly the resource needing the
      exception."
    Rationale: "A broad exception scope (matching unrelated resources or
      entire directories) can suppress future valid findings. Narrow scoping
      ensures that only the known, documented exception is suppressed, and any
      new resources or patterns are still subject to full policy enforcement."
  - fail: >
      "Exception scope is broader than necessary (wildcard, resource-group, or
      directory-level). Recommend narrowing to the specific resource, rule, or
      path to avoid suppressing unrelated findings."
```

## Resolution Path
1. Add explicit TTL to every policy exception (maximum 90 days)
2. Configure CI pipeline to expire exceptions after TTL and require revalidation
3. Scope each exception to the minimal resource/rule/path combination
4. Link each exception to a remediation ticket or issue for tracking

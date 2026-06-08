# Azure Functions HTTP Key and Admin Endpoint Gate

## Purpose
Prevents false-positive "unsecured Azure Function endpoint" findings when HTTP-triggered functions use function-level or admin-level authorization keys, even when the authentication header is not explicitly validated in the function code. The Azure Functions runtime validates authorization keys before the function code executes, so code-level validation is often unnecessary.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "Azure Function HTTP endpoint without auth" as High
2. The function's `function.json` or `authLevel` setting specifies `function` or `admin` (not `anonymous`)
3. The function is accessed via the Azure Functions host URL (not via APIM or other gateway)

### Gate Check: Auth Level Assessment

```yaml
check_auth_level:
  - detection_patterns:
      - "Azure.*Function|httpTrigger|function\.json|authLevel"
      - "function.*key|host.*key|_master.*key|x-functions-key"
      - "anonymous.*access|unsecured.*endpoint|no.*auth.*function"
  - pass: "authLevel is set to 'function' or 'admin' in function.json → Downgrade to Low (Informational). Rationale: Azure Functions runtime validates authorization keys before invoking the function code. Code-level key validation is redundant when runtime-level auth is enabled."
  - fail: "authLevel is set to 'anonymous' → Keep severity. Anonymous functions accept all HTTP requests without authentication."
```

### Gate Check: Additional Protection

```yaml
check_additional_protection:
  - detection_patterns:
      - "APIM|API.*Management|Front.*Door|WAF|App.*Gateway"
      - "VNet.*integration|service.*endpoint|private.*endpoint"
      - "IP.*restrict|access.*restrict|network.*ACL"
  - pass: "Function protected by API Management, WAF, VNet integration, or network restrictions in addition to runtime auth → Accept. Defense-in-depth beyond runtime keys is recommended for production."
  - fail: "No additional protection beyond authLevel AND function is internet-facing → Escalate to Medium. Runtime keys provide basic protection but are vulnerable to key leakage."
```

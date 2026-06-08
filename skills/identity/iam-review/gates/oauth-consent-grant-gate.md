# OAuth Consent and Application Permission Grant Gate

## Purpose
Prevents false-positive "over-permissioned OAuth app" findings when an application's requested OAuth scopes are appropriate for its documented function, even when the scope set appears broad. The gate evaluates whether the scope request is proportionate to the application's purpose, not just the raw scope list.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "excessive OAuth scopes" or "over-permissioned application" as Medium/High
2. The requested scopes are documented in the application manifest or consent screen
3. The application's purpose (documented in README, app description, or security documentation) justifies each requested scope

### Gate Check: Scope Proportionality

```yaml
check_scope_proportionality:
  - detection_patterns:
      - "OAuth.*scope|permission.*grant|consent.*screen|app.*permission"
      - "over.?permission|excessive.*scope|broad.*scope|least.*privilege"
      - "openid|profile|email|offline_access|api://.*scope"
  - pass: "Each requested scope maps to a documented feature in the application → Downgrade to Medium (Observation). Rationale: Broad scopes may be necessary for the application's function (e.g., email client needs mail.* scopes). Verify during functional testing."
  - fail: "Scopes requested without corresponding feature OR scopes include sensitive permissions (mail.send, files.readwrite.all, directory.*) → Keep severity. Sensitive scopes without clear justification are an OAuth consent phishing risk."
```

### Gate Check: Admin Consent Assessment

```yaml
check_admin_consent:
  - detection_patterns:
      - "admin.*consent|tenant.*admin|organization.*consent|admin.*grant"
      - "delegated.*permission|application.*permission|app.?only"
  - pass: "Application uses delegated permissions (user-consented) rather than application permissions (admin-consented) where possible → Accept. Delegated permissions are scoped to the user's access level."
  - fail: "Application uses application permissions (admin-consented, app-only) without documented justification → Escalate. Application permissions grant the app access to ALL data without a signed-in user."
```

# Cookie and Session Storage Gate

## Purpose
Prevents false-positive cookie/session storage flags when the code uses `__Host-` prefix cookies with Secure+HttpOnly+SameSite attributes, sessionStorage for short-lived CSRF nonces only, or framework-managed session abstractions that handle cookie security automatically (Passport.js, Django session, Spring Security, Devise).

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "insecure cookie configuration" or "session storage vulnerability" as High
2. The code sets cookies with `__Host-` or `__Secure-` prefix AND Secure+HttpOnly+SameSite=Lax/Strict flags
3. OR the session token is managed entirely by a framework session abstraction

### Gate Check: Secure Cookie Attributes

```yaml
check_secure_cookies:
  - detection_patterns:
      - "Set-Cookie|set-cookie|cookie\.set|cookies\.set|response\.cookie"
      - "__Host-|__Secure-|Secure;|HttpOnly;|SameSite"
  - checks:
      - "Prefix: __Host- (strongest) or __Secure- (strong) must be present for session cookies"
      - "Flags: Secure AND HttpRequired AND SameSite=Lax|Strict all present"
      - "Path: Set to / for __Host- prefix cookies"
      - "Max-Age: Finite for session cookies (no persistent session tokens)"
  - pass: "All secure cookie attributes present AND no sensitive data in cookie value → Downgrade to Low (Observation). Rationale: __Host- prefix cookies with Secure+HttpOnly+SameSite=Lax follow OWASP best practices for session cookies."
  - fail: "Missing secure attributes → Keep original severity. Flag specific missing attributes."
```

### Gate Check: Storage Context

```yaml
check_storage_context:
  - detection_patterns:
      - "localStorage|sessionStorage|IndexedDB|cookie.*store"
      - "CSRF.*nonce|csrf.*token|XSRF-TOKEN|X-CSRF-Token"
  - pass: "Data in sessionStorage is a short-lived CSRF nonce ONLY (not auth tokens, not PII) → No finding. Rationale: SessionStorage is cleared on tab close and is not accessible cross-tab. CSRF nonces are intentionally ephemeral."
  - fail: "Auth tokens or PII in localStorage/sessionStorage → Keep severity. Recommend migration to secure cookie or in-memory storage."
```

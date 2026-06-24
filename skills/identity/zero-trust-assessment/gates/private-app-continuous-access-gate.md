# Private App Continuous Access Gate

## Purpose
Prevents false-positive zero-trust findings when private applications are accessible without continuous verification, but the access proxy enforces session timeout, device posture checks, or IdP re-authentication at configurable intervals.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A private application is accessible without per-request re-authorization
2. An access proxy (Cloudflare Access, Zscaler, Tailscale, Pomerium, OAuth2 Proxy) enforces access policy
3. The proxy is configured with session timeouts, device posture checks, or IdP re-authentication

### Gate Check: Proxy Enforcement

```yaml
check_proxy_enforcement:
  - detection_patterns:
      - "access.*proxy|reverse.*proxy|auth.*proxy|cloudflare.*access|Zscaler|Tailscale|Pomerium"
      - "session.*timeout|session.*duration|re.?auth|re.?authenticat"
      - "device.*posture|device.*check|device.*trust|crowdstrike|sentinelone|mdm"
  - pass: "When the access proxy enforces session timeouts of 8 hours or less AND device posture checks on each session start, downgrade to informational. Rationale: Proxy-enforced session timeouts with device posture checks at session start provide continuous verification for private applications."
  - fail: "When sessions are long-lived (24+ hours) without device posture checks, or there is no access proxy limiting access, retain severity. Rationale: Long-lived sessions without device verification create a standing access risk."
```

### Gate Check: IdP Session Policy

```yaml
check_idp_session_policy:
  - detection_patterns:
      - "IdP|identity.?provider|Okta|Azure.*AD|Google.*Workspace|OneLogin"
      - "session.*polic|conditional.*access|risk.*based|adaptive.*auth"
      - "re.?authenticat|step.?up|MFA.*re.?prompt|factor.*sequenc"
  - pass: "When the IdP enforces session policies that require re-authentication for sensitive applications (MFA re-prompt, step-up auth) even when the access proxy session is still valid, downgrade severity. Rationale: IdP-level session policies provide defense-in-depth for private application access."
  - fail: "When the IdP session outlives the access proxy session, or no step-up authentication exists for sensitive applications, retain severity. Rationale: Stale IdP sessions can be used to re-authenticate to private apps after the proxy session expires."
```

## Resolution Path
1. Deploy an access proxy (Cloudflare Access or Tailscale) in front of all private applications
2. Configure session timeouts of 4-8 hours with device posture checks on each session
3. Configure IdP conditional access policies to require MFA re-prompt for sensitive applications
4. Audit private application access logs for anomalous session patterns

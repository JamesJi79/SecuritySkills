# IdP Session Revoke Propagation Gate

## Purpose
Prevents false-positive containment findings when IdP session revocation does not immediately propagate to all downstream services, but the IdP and services use token expiration, forced re-authentication, or token revocation lists to bound the propagation delay.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A containment review flags that IdP session revocation does not immediately terminate all active sessions across downstream services
2. The IdP supports token revocation or short session lifetimes
3. Downstream services validate tokens on each request or at frequent intervals

### Gate Check: Token Expiration Bounds

```yaml
check_token_expiration_bounds:
  - detection_patterns:
      - "session.*expir|token.*lifetime|access.*token.*TTL|refresh.*token.*TTL"
      - "JWT.*exp|session.*timeout|inactivity.*timeout|absolute.*timeout"
      - "OAuth.*revocation|token.*revocation|session.*revocation"
  - pass: "When access tokens have a TTL of 15 minutes or less, and refresh tokens require re-authentication within 24 hours, downgrade to informational. Rationale: Short token lifetimes bound the propagation delay, ensuring revoked sessions are effectively terminated within minutes."
  - fail: "When access tokens have a TTL exceeding 1 hour or refresh tokens persist beyond 7 days without re-authentication, retain severity. Rationale: Long-lived sessions create an unacceptable window between revocation and effective session termination."
```

### Gate Check: Downstream Validation

```yaml
check_downstream_validation:
  - detection_patterns:
      - "token.*validat|JWT.*verify|introspect|token.*check"
      - "OAuth.*introspect|opaque.*token|session.*validat|auth.*check"
      - "API.*gateway|reverse.*proxy|auth.*proxy|sidecar.*auth"
  - pass: "When all downstream services validate tokens on every request (via API gateway, sidecar proxy, or per-service introspection), downgrade severity. Rationale: Per-request token validation ensures revocation is effective within one TTL, regardless of propagation mechanism."
  - fail: "When downstream services cache authentication decisions for longer than the token TTL, or validate only at session start, retain severity. Rationale: Cached authentication decisions extend the revocation propagation window beyond the designed token lifetime."
```

## Resolution Path
1. Configure OAuth/OIDC provider to issue short-lived access tokens (15 min TTL) and enforce re-authentication for refresh tokens within 24 hours
2. Implement token introspection at the API gateway or reverse proxy for all downstream services
3. Deploy a sidecar auth proxy (Istio, Envoy, OAuth2 Proxy) for services that cannot implement token validation natively
4. Document the maximum theoretical propagation delay (token TTL + network latency) and verify it meets the incident response SLA

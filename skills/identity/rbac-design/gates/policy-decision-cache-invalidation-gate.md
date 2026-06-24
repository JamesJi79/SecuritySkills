# Policy Decision Cache Invalidation Gate

## Purpose
Prevents false-positive RBAC findings when access policies rely on cached authorization decisions that may not reflect recent role changes, but the cache invalidation strategy (TTL-based, event-driven, or periodic refresh) ensures stale decisions are bounded.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. An RBAC review identifies that cached policy decisions could serve stale authorization results
2. The authorization system has implemented a cache invalidation strategy
3. The maximum cache lifetime is documented and aligned with the organization's access risk tolerance

### Gate Check: Cache Invalidation Strategy

```yaml
check_cache_invalidation_strategy:
  - detection_patterns:
      - "cache.*invalidate|cache.*TTL|cache.*refresh|cache.*expir"
      - "policy.*cache|decision.*cache|auth.*cache|PDP.*cache|PEP.*cache"
      - "event.*driven|webhook.*invalidate|reactive.*invalidate|push.*invalidate"
  - pass: "When the cache invalidation uses event-driven mechanisms (webhook on role change, Pub/Sub on policy update) with a fallback TTL of <5 minutes, downgrade to informational. Rationale: Event-driven invalidation ensures changes are reflected within seconds, with TTL as a safety net."
  - fail: "When only passive TTL-based invalidation is used with a TTL >15 minutes, or there is no documented invalidation strategy, retain severity. Rationale: TTL-only invalidation with long windows can allow unauthorized access to persist for extended periods after role revocation."
```

### Gate Check: Critical Change Immediate Invalidation

```yaml
check_critical_change_invalidation:
  - detection_patterns:
      - "role.*revoke|access.*revoke|permission.*remove|user.*terminat|employee.*offboard"
      - "privilege.*escal|role.*elevat|admin.*grant|sensitive.*role"
      - "termination|suspension|offboarding|deactivation"
  - pass: "When critical access changes (termination, role revocation, privilege escalation) trigger immediate cache invalidation for the affected user, bypassing the normal TTL, downgrade severity. Rationale: Immediate invalidation for critical changes ensures the access control plane responds instantly to high-impact events."
  - fail: "When all cache invalidation follows the same TTL regardless of change criticality, retain severity. Rationale: Equal treatment of routine and critical changes leaves a window for unauthorized access after high-impact events."
```

## Resolution Path
1. Implement event-driven cache invalidation for policy and role changes (webhook, Pub/Sub, or database CDC)
2. Set the passive TTL to 5 minutes or less as a fallback
3. Categorize access changes into critical (termination, role revocation) and routine (new role, attribute update)
4. Configure critical changes to bypass TTL and trigger immediate invalidation
5. Document the cache invalidation architecture and test quarterly with fire drills

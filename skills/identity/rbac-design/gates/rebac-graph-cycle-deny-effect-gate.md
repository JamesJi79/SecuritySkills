# ReBAC Graph Cycle Deny-Effect Gate

## Purpose
Prevents false-positive RBAC findings when relationship-based access control (ReBAC) graphs contain relationship cycles that could theoretically lead to privilege escalation, but the policy evaluation engine implements cycle detection and deny-effect propagation to prevent exploitation.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. An RBAC review identifies relationship cycles in the ReBAC graph (e.g., user A manages user B who manages user A)
2. The authorization system uses a ReBAC or relationship-based model (Google Zanzibar, Auth0, OPA, Topaz, Keto)
3. The policy engine implements cycle detection or deny-override semantics

### Gate Check: Cycle Detection

```yaml
check_cycle_detection:
  - detection_patterns:
      - "cycle.*detect|graph.*cycle|relationship.*loop|circular.*relationship"
      - "Zanzibar|ReBAC|relationship.*graph|tuple.*store|graph.*DB"
      - "policy.*engine|authorization.*engine|PDP|OPA|Topaz|Keto"
  - pass: "When the authorization engine implements cycle detection at evaluation time (Zanzibar-style reachability with TTL, OPA with depth limits), downgrade to informational. Rationale: Runtime cycle detection prevents infinite recursion and ensures policy evaluation terminates correctly even with graph cycles."
  - fail: "When the authorization engine does not implement cycle detection and relies on graph acyclicity as a precondition, retain severity. Rationale: Undetected cycles in a ReBAC graph can cause infinite evaluation loops, denial of service, or incorrect authorization decisions."
```

### Gate Check: Deny-Override Semantics

```yaml
check_deny_override_semantics:
  - detection_patterns:
      - "deny.*override|explicit.*deny|deny.*priority|negative.*authori"
      - "default.*deny|deny.*all|blacklist|blocklist|revoke.*override"
      - "policy.*conflict|decision.*ambiguity|evidence.*conflict"
  - pass: "When the policy engine implements deny-override semantics (explicit deny takes precedence over any allow), cycles that create ambiguous allow paths are resolved to deny, downgrade severity. Rationale: Deny-override semantics ensure that cycles cannot create unintended allow paths."
  - fail: "When the policy engine uses allow-override or first-match-wins semantics without explicit cycle handling, retain severity. Rationale: In non-deny-override systems, cycles can create unexpected allow paths that violate least privilege."
```

## Resolution Path
1. Verify the authorization engine implements cycle detection (query timeout, max depth, or reachability TTL)
2. Confirm deny-override semantics are configured and tested for all policy evaluation paths
3. Add graph cycle monitoring to detect and alert on new relationship cycles as they form
4. Document the cycle detection strategy and test quarterly with adversarial graph scenarios

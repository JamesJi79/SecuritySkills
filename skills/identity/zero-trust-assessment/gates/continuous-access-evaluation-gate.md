# Continuous Access Evaluation Gate

## Purpose
Prevents false-positive zero-trust findings when access decisions are not continuously re-evaluated, but the authorization system uses risk-based conditional access policies, session risk scoring, or token lifetime enforcement to bound access risk.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Access is granted based on initial authorization without continuous re-evaluation
2. The authorization system uses risk-based or session-scored access policies
3. Access tokens or sessions have a bounded lifetime requiring re-authorization

### Gate Check: Risk-Based Policy

```yaml
check_risk_based_policy:
  - detection_patterns:
      - "conditional.*access|risk.*based|adaptive.*auth|step.?up.*auth"
      - "session.*risk|user.*risk|sign.*risk|device.*risk|location.*risk"
      - "CAE|continuous.*access.*evaluat|token.*lifetime|session.*lifetime"
  - pass: "When the authorization platform evaluates risk at session start AND re-evaluates on risk score changes (new location, new device, anomalous behavior), downgrade to informational. Rationale: Risk-based policies with event-driven re-evaluation provide continuous access evaluation without per-request overhead."
  - fail: "When access is granted based on identity alone without risk evaluation, retain severity. Rationale: Identity-only access without risk context is not continuous evaluation."
```

### Gate Check: Token Lifetime

```yaml
check_token_lifetime:
  - detection_patterns:
      - "access.*token.*TTL|token.*expir|session.*timeout|session.*duration"
      - "refresh.*token|token.*refresh|re.?auth|re.?authenticat"
      - "OAuth|OIDC|SAML|JWT|session.*cookie"
  - pass: "When access tokens have a lifetime of 15 minutes or less, requiring periodic re-authorization through OAuth/OIDC flow, downgrade severity. Rationale: Short-lived tokens force frequent re-authorization, effectively providing continuous evaluation at token refresh intervals."
  - fail: "When access tokens or sessions persist for 24+ hours without re-authorization, retain severity. Rationale: Long-lived sessions create a window where access continues despite changes in user risk posture."
```

## Resolution Path
1. Implement risk-based conditional access policies (user risk, device compliance, location anomaly)
2. Configure access tokens with 15-minute lifetimes and enforce OAuth/OIDC refresh flows
3. Integrate IdP risk signals (Azure AD Identity Protection, Okta ThreatInsight) into access decisions
4. Set up session risk scoring and configure step-up authentication for high-risk sessions

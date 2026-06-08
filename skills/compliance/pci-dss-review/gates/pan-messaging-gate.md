# End-User Messaging PAN Evidence Gate

## Purpose
Prevents false-positive PCI DSS PAN-in-messaging findings when primary account numbers (PANs) transmitted through end-user messaging channels (email, SMS, chat, push notifications) use tokenization, truncation (first-six/last-four), or format-preserving encryption that renders the PAN data useless for fraud even if the messaging channel is intercepted.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "PAN transmitted via unencrypted messaging" as High/Critical
2. The PAN data in messaging is tokenized, truncated (BIN+last4), or encrypted
3. The messaging channel is authenticated (user must be logged in to view)

### Gate Check: PAN Protection Assessment

```yaml
check_pan_protection:
  - detection_patterns:
      - "PAN.*message|card.*number.*email|PAN.*SMS|PAN.*notification"
      - "token.*card|truncat.*PAN|mask.*PAN|first.*last.*four|BIN.*last"
      - "format.*preserv.*encrypt|FPE|vault.*token|card.*reference"
  - pass: "PAN in messaging is tokenized or truncated (BIN+last4 only) → Downgrade to Medium (Compliance Note). Rationale: Tokenized or truncated PANs cannot be used for fraud. PCI DSS requirements for PAN-at-rest encryption do not apply to tokenized data."
  - fail: "Full PAN transmitted in messaging → Keep severity. Full PAN in messaging violates PCI DSS Requirement 4 and exposes cardholder data."
```

### Gate Check: Channel Authentication

```yaml
check_channel_authentication:
  - detection_patterns:
      - "email.*notification|SMS.*alert|push.*notif|in-app.*message"
      - "authenticat.*portal|login.*required|verified.*channel"
  - pass: "Messaging delivered through authenticated channels (logged-in portal, verified device) → Accept with Recommendation. Recommendation: Add confidentiality notice in message template."
  - fail: "PAN sent via unauthenticated channel (plain SMS, unauthenticated email) → Escalate to Critical. Unauthenticated channels cannot verify the recipient's identity."
```

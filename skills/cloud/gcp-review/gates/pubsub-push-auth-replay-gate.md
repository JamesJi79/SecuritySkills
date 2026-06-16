# Pub/Sub Push Authentication Audience Replay Gate

## Purpose
Prevents false-positive findings when push subscription OIDC token audience and endpoint replay protections are verified, by requiring the reviewer to verify that a generic audience across multiple services and message replay without deduplication are not creating authentication gaps.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Pub/Sub push subscriptions use OIDC token authentication
2. Token audience and endpoint replay protections are documented as verified
3. Endpoint accepts a generic OIDC audience that could apply to multiple services, or message retry can replay non-idempotent actions

### Gate Check: OIDC Token Audience Scope

```yaml
check_oidc_audience_scope:
  - detection_patterns:
      - "Pub/Sub|pubsub|push subscription"
      - "OIDC|OpenID Connect|token audience"
      - "audience|aud"
      - "authentication|auth header"
      - "push endpoint|webhook"
  - pass: >
      "Each push subscription uses a unique OIDC audience value tied to a single
      receiving service or endpoint. The audience is not shared across different
      services. The receiving endpoint verifies the audience claim matches its
      own identifier before processing the message."
    Rationale: "A generic OIDC audience shared across multiple services means a
      token issued for one push subscription can be replayed against another
      service that accepts the same audience. This breaks the authentication
      boundary — Pub/Sub proves the message came from Google, but not which
      subscription or service it was intended for."
  - fail: >
      "OIDC audience is generic or shared across multiple receiving services.
      The push endpoint does not verify the audience claim. Recommend using a
      unique audience per subscription and validating it at the receiving
      endpoint."
```

### Gate Check: Message Deduplication and Idempotency

```yaml
check_message_idempotency:
  - detection_patterns:
      - "retry|redeliver|retry policy"
      - "ack deadline|nack|dead letter"
      - "idempotent|dedup|deduplication"
      - "exactly-once|at-least-once"
  - pass: >
      "The receiving endpoint is idempotent or uses Pub/Sub's exactly-once
      delivery with message deduplication ID. Message retry during ack deadline
      extension or nack does not cause duplicate side effects (duplicate
      charges, duplicate notifications, duplicate writes)."
    Rationale: "Pub/Sub push delivery is at-least-once by default. Without
      exactly-once delivery or idempotent processing, a message retry (triggered
      by ack deadline expiry or nack) causes the side effect to execute
      multiple times. A non-idempotent action like a financial transfer or
      authorization grant is replayed."
  - fail: >
      "Receiving endpoint is not idempotent and Pub/Sub exactly-once delivery
      is not enabled. Message retry or redelivery can cause duplicate side
      effects. Recommend either making the endpoint idempotent (use a
      deduplication key) or enabling exactly-once delivery."
```

## Resolution Path
1. Assign a unique OIDC audience per push subscription, specific to the receiving service
2. Validate the audience claim at each push endpoint
3. Enable exactly-once delivery or implement idempotent processing with a deduplication key
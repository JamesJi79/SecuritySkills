# Workload Identity Token Audience Scope Gate

## Purpose
Prevents false-positive findings when projected service account tokens set explicit audience and short TTL, by requiring the reviewer to verify that the token audience is not accepted by unintended cloud APIs or internal services, and that tokens are not mounted into sidecar/debug containers that do not need them.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Pod uses projected service account (Workload Identity) tokens with explicit audience
2. Token has short TTL configured
3. Token audience could match unintended cloud APIs or internal services, or token is mounted into a sidecar/debug container

### Gate Check: Token Audience Scope Validation

```yaml
check_token_audience_scope:
  - detection_patterns:
      - "projected service account|workload identity"
      - "token audience|audience|--audience"
      - "token expiration|expirationSeconds|TTL"
      - "serviceAccountToken|token request"
      - "gke-wi|iam\.gserviceaccount\.com"
  - pass: >
      "Each projected token's audience is scoped to the single intended API or
      service. The audience does not match a broader pattern (e.g.,
      `https://iam.googleapis.com/` without a specific service resource). Token
      TTL is set to the minimum viable duration (1 hour or less)."
    Rationale: "A Workload Identity token with audience
      `https://iam.googleapis.com/` (no resource) is accepted by all IAM
      methods, effectively granting broader access than intended. The token's
      audience must be as specific as the receiving service requires. A long
      TTL increases the exposure window if the pod is compromised."
  - fail: >
      "Token audience is overly broad (e.g., `https://iam.googleapis.com/`
      without resource, or a generic audience that matches multiple services).
      TTL exceeds 1 hour without documented operational requirement. Recommend
      narrowing the audience to the specific service/resource and reducing TTL."
```

### Gate Check: Token Mount Scope

```yaml
check_token_mount_scope:
  - detection_patterns:
      - "serviceAccountToken|token mount"
      - "sidecar|init container|debug container"
      - "volumeMount|volume|projected"
      - "serviceAccountName|service account"
      - "containers:|spec.containers"
  - pass: >
      "Workload identity tokens are mounted only into the container(s) that
      require them. Sidecar containers, init containers, and debug/ephemeral
      containers do not receive the token unless they have a documented need.
      Token mounts use read-only filesystem and least-privilege volume
      projection."
    Rationale: "A token mounted into a sidecar or debug container that does not
      need it expands the attack surface. If the sidecar is compromised, the
      token can be exfiltrated and used to authenticate to the unintended
      service as the pod's identity."
  - fail: >
      "Workload identity token is mounted into containers (sidecar, init,
      debug) that do not have a documented need for it. Recommend scoping token
      mounts to only the containers that require authentication, and using
      read-only mounts."
```

## Resolution Path
1. Scope each token audience to the single intended API/service, not a broad pattern
2. Set token TTL to minimum viable duration (1 hour or less)
3. Mount tokens only into containers with documented authorization requirements
4. Use read-only filesystem for token volumes
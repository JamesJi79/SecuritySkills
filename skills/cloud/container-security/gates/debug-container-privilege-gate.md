# Debug Container and Ephemeral Privilege Gate

## Purpose
Prevents false-positive "privileged container" flags when ephemeral debug containers (kubectl debug, ephemeral containers in Kubernetes) or sidecar containers with elevated permissions are used for legitimate debugging purposes and are explicitly scoped to specific namespaces, time-bound, and auditable.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "privileged container" or "container running as root" as High/Critical
2. The privileged container is ephemeral (kubectl debug, debug sidecar, temporary troubleshooting pod)
3. The container has explicit namespace scoping and time-bound TTL

### Gate Check: Ephemeral Privilege Assessment

```yaml
check_ephemeral_privilege:
  - detection_patterns:
      - "privileged.*true|securityContext.*privileged|--privileged"
      - "kubectl.*debug|ephemeral.*container|debug.*sidecar|debug.*pod"
      - "ttl.*seconds|activeDeadlineSeconds|timeout.*debug"
  - pass: "Debug container is ephemeral with TTL AND scoped to specific namespace → Downgrade to Medium (Observation). Rationale: Ephemeral debug containers are an accepted Kubernetes debugging practice. The risk is limited by the container's short lifetime and explicit namespace scoping. Ensure debug sessions are logged and approved."
  - fail: "Container runs privileged persistently (Deployment, StatefulSet, DaemonSet) OR no TTL → Keep severity. Persistent privileged containers should run as non-root with dropped capabilities."
```

### Gate Check: Audit Trail Assessment

```yaml
check_audit_trail:
  - detection_patterns:
      - "audit.*log|kubernetes.*audit|cloud.*audit|kubectl.*auth.*check"
      - "pod.*exec|kubectl.*exec|debug.*session|kubectl.*debug"
  - pass: "Kubernetes audit logging enabled for pod exec/debug operations AND incident response runbook references debug container pattern → Accept. Escalation only if audit logs show unauthorized usage."
  - fail: "No audit logging for privileged operations → Escalate to High. Without audit trails, ephemeral privilege escalation cannot be distinguished from compromise."
```

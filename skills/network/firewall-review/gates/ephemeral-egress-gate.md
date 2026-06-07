# Ephemeral Egress and Cloud Effective-Rule Gate

## Purpose
Prevents false-positive "over-permissive egress" findings when cloud firewall rules (AWS Security Group egress, Azure NSG, GCP firewall, OCI security list) allow broad egress but are attached to ephemeral resources (auto-scaling groups, spot fleets, Lambda, container tasks) that cannot be exploited for persistent C2 communication.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "0.0.0.0/0 egress" or "overly permissive outbound rule" as High
2. The resource is ephemeral (auto-scaling group, spot instance, Lambda, ECS/Fargate task, Kubernetes pod)
3. The resource has no persistent inbound access from the internet

### Gate Check: Ephemeral Resource Assessment

```yaml
check_ephemeral_resource:
  - detection_patterns:
      - "0\.0\.0\.0/0.*egress|::/0.*egress|outbound.*any|all.*traffic.*out"
      - "security_group|security.*group.*egress|nsg.*outbound|firewall.*rule.*egress"
      - "auto-scaling|spot|lambda|fargate|ecs.*task|eks.*pod|cloud.*run"
  - pass: "Resource is ephemeral AND has no persistent inbound access → Downgrade to Low (Observation). Rationale: Ephemeral resources cannot host persistent C2 infrastructure. Broad egress is required for package downloads, container registries, and API calls. Recommend adding specific egress rules for known endpoints."
  - fail: "Resource is persistent (long-lived VM, bare metal) OR has persistent inbound access → Keep severity. Implement least-privilege egress rules."
```

### Gate Check: Effective-Rule Analysis

```yaml
check_effective_rule:
  - description: "Evaluate using cloud provider's effective-rule/accessible analysis tools"
  - detection_patterns:
      - "effective.*rule|accessible.*from|reachability.*checker|network.*analyzer"
      - "AWS:*ReachabilityAnalyzer|Azure:*NetworkWatcher|GCP:*FirewallInsights"
  - pass: "Effective-rule analysis shows egress is used for legitimate purposes (package registries, container images, monitoring endpoints) → Downgrade to Recommendation. Add allow-listed egress rules for known endpoints."
  - fail: "Effective-rule analysis confirms unknown/unnecessary egress destinations → Keep severity. Remove unused egress rules."
```

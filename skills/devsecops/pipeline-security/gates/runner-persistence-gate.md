# Self-Hosted Runner Persistence and Trust-Boundary Gate

## Purpose
Prevents false-positive "runner persistence" flags when CI/CD self-hosted runners use ephemeral instances (auto-scaling groups, spot instances, container groups) that cannot persist beyond a single job run, or when the runner environment uses disk encryption and immutable infrastructure patterns.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "self-hosted runner persistence" or "runner trust boundary violation" as High/Critical
2. Runners are ephemeral (auto-scaling, spot/preemptible instances, Kubernetes pods, container groups)
3. Runner storage is ephemeral or encrypted-at-rest (instance store, encrypted EBS, tempfs)

### Gate Check: Ephemeral Runner Assessment

```yaml
check_ephemeral_runners:
  - detection_patterns:
      - "self-hosted|selfhosted|self.*runner|actions-runner"
      - "auto-scaling|spot.*instance|preemptible|kubernetes.*runner|container.*group"
      - "ephemeral|immutable|golden.*image|ami.*pipeline"
  - pass: "Runners are ephemeral with no persistent storage between jobs → Downgrade to Medium (Architecture Note). Rationale: Ephemeral runners cannot persist malware or exfiltrate credentials across job boundaries. The trust boundary is scoped to the job duration."
  - fail: "Runners are persistent (long-lived VMs, dedicated servers) OR unencrypted persistent storage → Keep severity. Implement runner rotation or disk encryption."
```

### Gate Check: Trust Boundary Assessment

```yaml
check_trust_boundary:
  - description: "Assess whether cross-job data leakage is possible"
  - detection_patterns:
      - "GITHUB_TOKEN|ACTIONS_ID_TOKEN|WORKFLOW.*TOKEN|id-token"
      - "docker.*cache|actions/cache|pip.*cache|npm.*cache|m2.*repository"
  - pass: "No shared cache/mounts between jobs AND runner is single-use → Downgrade to Low. Trust boundary is adequately scoped."
  - fail: "Shared job caches OR runner reused across jobs → Keep severity. Each job's artifacts could leak to subsequent jobs."
```

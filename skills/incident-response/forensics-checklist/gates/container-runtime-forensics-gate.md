# Container Runtime Forensics Gate

## Purpose
Prevents false-positive forensics findings when container runtime evidence (ephemeral volumes, overlay filesystem, terminated pods) appears to be lost due to container lifecycle, but the cluster has compensating forensic capabilities (cluster-level audit logging, persistent event store, runtime telemetry).

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A forensics assessment identifies that container runtime data is unavailable post-termination
2. The cluster uses ephemeral storage (emptyDir, overlayfs) with no persistent volume for forensics
3. Compensating forensic evidence exists through cluster audit logs, k8s events, runtime telemetry, or sidecar logging

### Gate Check: Cluster-Level Forensics

```yaml
check_cluster_level_forensics:
  - detection_patterns:
      - "cluster.*audit|k8s.*audit|kubernetes.*event|audit.*log"
      - "Falco|Tetragon|Cilium|Tracee|Sysdig|kubearmor|event.*collect"
      - "sidecar.*log|fluentd|fluentbit|log.*shipper|log.*forward"
  - pass: "When the cluster has audit logging enabled (API server audit, k8s events exported), AND runtime security monitoring (Falco/Tetragon) captures system call events, downgrade to informational. Rationale: Cluster-level and runtime telemetry provide forensic evidence equivalent to container-local artifacts for most incident types."
  - fail: "When the cluster has no audit logging or runtime security monitoring, retain severity. Rationale: Without cluster-level or runtime forensic capabilities, terminated containers leave no forensic trace."
```

### Gate Check: Evidence Retention Policy

```yaml
check_evidence_retention_policy:
  - detection_patterns:
      - "evidence.*retention|log.*retention|event.*retention|forensic.*retention"
      - "Splunk|Elasticsearch|Loki|cloud.*log|log.*archive|S3.*log"
      - "incident.*response|forensic.*readiness|IR.*preparedness"
  - pass: "When the cluster audit logs and runtime events are retained for at least the organization's evidence retention period (typically 90+ days for incident response), downgrade severity. Rationale: Retained telemetry provides the evidentiary basis for post-incident forensics even without container-local artifacts."
  - fail: "When logs are retained for less than 30 days or have no defined retention policy, retain severity. Rationale: Short retention periods may result in loss of forensic evidence before investigation completes."
```

## Resolution Path
1. Enable Kubernetes API server audit logging and export to a SIEM or long-term storage
2. Deploy runtime security monitoring (Falco, Tetragon, or Cilium) for system-call-level forensics
3. Configure structured container logging to stdout/stderr with a sidecar log shipper
4. Set log retention to match the organization's incident response evidence retention policy (minimum 90 days)

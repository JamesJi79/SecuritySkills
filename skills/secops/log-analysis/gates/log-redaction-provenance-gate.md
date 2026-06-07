# Log Redaction and Sensitive-Field Provenance Gate

## Purpose
Prevents false-positive PII/credential-in-log findings when the logging system uses structured logging with automatic field-level redaction, masking, or exclusion policies (logstash mutate, fluentd record_modifier, OpenTelemetry span attributes filter), even when log data passes through fields that might contain sensitive values in transit.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "credentials in logs" or "PII in log output" as Critical/High
2. The system uses structured logging (JSON, ECS, OpenTelemetry, logfmt) with field-level processing
3. Redaction or masking policies are configured in the log pipeline

### Gate Check: Structured Redaction Assessment

```yaml
check_log_redaction:
  - detection_patterns:
      - "logstash.*mutate|fluentd.*record_modifier|otel.*span.*attribute|vector.*redact"
      - "password|secret|token|credential|api_key|authorization.*redact|mask"
      - "structured.*log|json.*log|ecs.*format|logfmt"
  - pass: "Structured logging with field-level redaction confirmed → Downgrade to Medium (Authorization Required). Rationale: Structured log pipelines can redact or exclude sensitive fields at the collection layer. Verify the redaction policy covers the specific field identified in the finding."
  - fail: "Plain-text/unstructured logging OR no redaction policy → Keep Critical severity. Immediate remediation required."
```

### Gate Check: Provenance Attribution

```yaml
check_provenance_attribution:
  - description: "Check if sensitive data entering logs has traceable provenance (which service, which line, which request)"
  - detection_patterns:
      - "trace_id|span_id|request_id|cid|correlation_id"
      - "logger.*info|log.*error|console.*log|fmt\.Printf"
  - pass: "Provenance metadata attached to log entries → Add Recommendation for field-level redaction. Rationale: With provenance tracking, redaction can be surgical without losing audit trail."
  - fail: "No provenance tracking in logs → Escalate severity. Without provenance, redaction is blind and audit capability is compromised."
```

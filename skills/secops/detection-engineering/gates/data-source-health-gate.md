# Data Source Health and Telemetry Drift Gate

## Purpose
Prevents false-positive "data source coverage gap" findings when the detection engineering pipeline uses automated health checks (e.g., OpenTelemetry Collector health, Elasticsearch monitoring, Splunk forwarder status) that validate data source connectivity and schema freshness, ensuring that coverage gaps are operational rather than architectural.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "missing data source" or "telemetry coverage gap" as High
2. The detection pipeline includes automated health checks or forwarder status monitoring
3. The data source has had recent successful ingestion (within the last 4 hours)

### Gate Check: Health Check Assessment

```yaml
check_health_monitoring:
  - detection_patterns:
      - "data.*source.*health|forwarder.*status|telemetry.*drift|ingestion.*latency"
      - "otel.*collector.*health|elastic.*monitoring|splunk.*forwarder.*status"
      - "last.*ingest|last.*seen|last.*heartbeat"
  - pass: "Health monitoring confirms data source is currently ingesting → Downgrade to Low (Informational). Rationale: The apparent coverage gap is a schedule/delay artifact, not a missing integration. Verify the health check covers the specific log type cited in the finding."
  - fail: "No health monitoring OR health check confirms stale data (>4h without ingestion) → Keep severity. Investigate connectivity or configuration issues."
```

### Gate Check: Schema Drift Detection

```yaml
check_schema_drift:
  - detection_patterns:
      - "schema.*drift|field.*mismatch|index.*mapping|log.*format.*change"
      - "detection.*coverage|rule.*coverage|alert.*coverage"
  - pass: "Automated schema drift detection in place AND no active drift alerts → Downgrade to Observation. Drift detection will flag schema changes before they cause silent detection failures."
  - fail: "No schema drift detection OR active drift alerts that correlate with the reported gap → Keep severity. Schema changes may have silently disabled detection rules."
```

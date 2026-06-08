# Ingestion Latency and Time-Window Evidence Gate

## Purpose
Prevents false-positive "data ingestion gap" findings when log sources have documented ingestion latency that causes apparent detection coverage gaps, but the detection rules are designed to account for the expected latency window. The current skill may flag time-window violations that are actually normal ingestion behavior.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "ingestion latency" or "detection time-window gap" as Medium/High
2. The data source has documented ingestion latency (e.g., batch processing, streaming delay, forwarder queue)
3. Detection rules are configured with time windows that account for the documented latency

### Gate Check: Latency Assessment

```yaml
check_latency_assessment:
  - detection_patterns:
      - "ingestion.*latency|data.*delay|forwarder.*lag|batch.*interval"
      - "detection.*window|rule.*timerange|lookback.*period|schedule.*delay"
      - "SIEM.*lag|log.*delay|streaming.*delay|batch.*process"
  - pass: "Documented latency < detection rule time window (with buffer) → Downgrade to Low (Informational). Rationale: Detection rules designed around actual latency windows correctly account for normal ingestion delays."
  - fail: "No documented latency OR detection rule window shorter than actual latency → Keep severity. Detection gaps will occur during scheduled ingestion delays."
```

### Gate Check: Time-Window Coverage

```yaml
check_time_window_coverage:
  - detection_patterns:
      - "schedule.*every|every.*hour|cron.*schedule|batch.*run"
      - "lookback.*min|search.*window|timerange.*sec"
  - pass: "Detection rules use lookback windows ≥ 2x the documented ingestion latency → Accept. The buffer ensures detection coverage even during intermittent latency spikes."
  - fail: "Detection rules use fixed time ranges without accounting for ingestion delay → Escalate. Events ingested after the rule's scheduled execution will be missed until the next run."
```

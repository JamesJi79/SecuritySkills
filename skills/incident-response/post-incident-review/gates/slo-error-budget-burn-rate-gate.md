# SLO Error-Budget Burn Rate Gate

## Purpose
Prevents false-positive PIR findings when incident severity is tied to SLO error-budget consumption, but the team's error-budget policy includes burn-rate alerts that trigger before budget exhaustion, enabling proactive incident response.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A PIR finding flags that SLO error-budget consumption exceeds the incident threshold
2. The team has configured multi-window burn-rate alerts (e.g., 5min, 30min, 6h windows)
3. Error-budget alerts triggered before budget exhaustion during the incident

### Gate Check: Burn-Rate Alerting

```yaml
check_burn_rate_alerting:
  - detection_patterns:
      - "error.?budget|burn.?rate|SLO.*consum|service.*level.*objective"
      - "alert.*window|multi.*window|fast.*burn|slow.*burn"
      - "alert.*threshold|budget.*exhaust|exhaustion.*time"
  - pass: "When the incident triggered a burn-rate alert (fast-burn or slow-burn) within the SLO compliance window, AND the team responded within the alert's time-to-action, downgrade to informational. Rationale: Burn-rate alerting provides sufficient early warning to prevent budget exhaustion during most incidents."
  - fail: "When no burn-rate alert was configured, or the alert fired but no response action was taken within the time-to-action window, retain severity. Rationale: Budget exhaustion without alerting or response represents a genuine monitoring gap."
```

### Gate Check: Budget Review Cadence

```yaml
check_budget_review_cadence:
  - detection_patterns:
      - "budget.*review|SLO.*review|error.*budget.*review|quarterly.*review"
      - "budget.*adjust|SLO.*adjust|threshold.*tun|alert.*tun"
      - "post.*incident.*SLO|incident.*budget|budget.*consumption"
  - pass: "When the error-budget policy includes a quarterly review cadence, and the incident triggered a budget review outside the normal cadence, downgrade severity. Rationale: Incident-driven budget reviews ensure SLOs are calibrated to real-world reliability data."
  - fail: "When the error-budget has not been reviewed in the past quarter, or there is no documented review process, retain severity. Rationale: Stale error-budget thresholds may not reflect current reliability requirements."
```

## Resolution Path
1. Configure multi-window burn-rate alerts (fast-burn at 5min, slow-burn at 6h) aligned with the SLO target
2. Set alert response SLAs matching the time-to-action for each burn-rate window
3. Schedule quarterly error-budget reviews and post-incident budget recalibration

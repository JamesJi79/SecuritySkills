# Privilege Elevation Approval Gate

## Purpose
Prevents false-positive privileged access findings when users can elevate privileges without separate approval, but the elevation mechanism (sudo, PIM, just-in-time) enforces time-bound access, audit logging, and automatic de-escalation.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Users can elevate to a privileged role without a separate approval workflow
2. The elevation is time-bound (expires automatically)
3. All elevated sessions are logged and audited

### Gate Check: Time-Bound Elevation

```yaml
check_time_bound_elevation:
  - detection_patterns:
      - "privilege.*elevat|role.*elevat|sudo|PIM|privileged.*identity.*management"
      - "just.?in.?time|JIT|time.*bound|ephemeral.*elevat|temporary.*elevat"
      - "elevat.*expir|auto.*de.?escalat|session.*timeout|privilege.*expir"
  - pass: "When privilege elevation is automatically revoked after a defined period (4-8 hours for admin, 1 hour for root), downgrade to informational. Rationale: Time-bound elevation with automatic de-escalation limits risk to the elevation window only."
  - fail: "When elevated privileges persist indefinitely or require manual de-escalation, retain severity. Rationale: Persistent or manual-de-escalation elevation creates standing privilege risk."
```

### Gate Check: Elevation Audit

```yaml
check_elevation_audit:
  - detection_patterns:
      - "audit.*log|elevat.*log|sudo.*log|PIM.*activ|role.*activ"
      - "session.*record|command.*log|keystroke.*log|screen.*record"
      - "alert.*elevat|anomaly.*elevat|unusual.*elevat|elevat.*notif"
  - pass: "When every privilege elevation is logged with user, target, time, duration, and commands executed, AND the logs are monitored for anomalous patterns, downgrade severity. Rationale: Fully audited elevation with monitoring provides detective control."
  - fail: "When elevation logs do not capture commands executed or are not monitored, retain severity. Rationale: Unmonitored elevation logs cannot detect misuse."
```

## Resolution Path
1. Configure all privilege elevation mechanisms with time-bound auto-de-escalation
2. Enable comprehensive audit logging (who, what, when, duration, commands)
3. Set up alerts for anomalous elevation patterns (off-hours, unusual targets, prolonged sessions)
4. Review elevation logs weekly for compliance with the principle of least privilege

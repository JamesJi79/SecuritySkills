# Emergency Stop and Rollback Drill Gate

## Purpose
Prevents false-positive "missing kill switch" findings when the agent system documents emergency stop and rollback procedures that have been validated through drills, tabletop exercises, or automated recovery tests — even if no production incident has triggered them. Design documentation alone is insufficient; this gate requires evidence that the procedures actually work.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "no emergency stop" or "no rollback capability" as Critical/High
2. The system documents kill switches, emergency stop procedures, or rollback mechanisms
3. There is documented evidence of drill execution (runbook sign-off, test results, tabletop exercise notes, automated recovery test output)

### Gate Check: Drill Evidence Assessment

```yaml
check_drill_evidence:
  - detection_patterns:
      - "emergency.*stop|kill.*switch|rollback.*capability|blast.*radius"
      - "drill|tabletop.*exercise|recovery.*test|failover.*drill"
      - "runbook.*sign.?off|recovery.*verification|test.*result"
  - pass: "Documented drill evidence with specific outcomes (passed/failed, X% success rate, recovery time ≤ Y) → Downgrade to Medium (Observation). Rationale: Validated procedures with measured outcomes are more reliable than undocumented kill switches. Failed drills identify improvement areas."
  - fail: "No drill evidence OR drills documented without outcomes → Keep severity. Undocumented procedures may fail in real incidents."
```

### Gate Check: Concurrent Action Handling

```yaml
check_concurrent_actions:
  - detection_patterns:
      - "queued.*call|delegated.*agent|running.*task|in-flight.*action"
      - "write.*commit|pending.*mutation|incomplete.*transaction"
  - pass: "Emergency stop specifically addresses in-flight actions (queued tool calls, delegated agents, pending writes) → Accept. Proper emergency stop must handle concurrent operations beyond simple process termination."
  - fail: "Emergency stop only terminates the agent process without addressing in-flight actions → Escalate. Concurrent operations can continue executing after agent termination."
```

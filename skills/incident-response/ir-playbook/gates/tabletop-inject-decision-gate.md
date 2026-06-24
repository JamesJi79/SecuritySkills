# Tabletop Inject Decision Gate

## Purpose
Prevents false-positive IR playbook findings when tabletop exercise inject decisions appear unrealistic or overly complex, but the injects are designed to test specific decision-making processes rather than operational speed.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A tabletop exercise inject requires a decision that seems unrealistic under time pressure
2. The inject's purpose is to exercise decision-making authority, communication escalation, or resource prioritization
3. The exercise facilitator provides inject context and decision support during the session

### Gate Check: Decision-Making Focus

```yaml
check_decision_making_focus:
  - detection_patterns:
      - "tabletop|table.?top|TTX|simulation|war.?game|drill"
      - "decision.*point|decision.*author|escalation.*decision|priorit.*decision"
      - "inject.*decision|scenario.*inject|facilitator.*note|discussion.*point"
  - pass: "When the inject explicitly states that the exercise focus is decision-making (not operational speed), and facilitator notes provide context for the decision, downgrade to informational. Rationale: Decision-focused injects intentionally simplify operational details to isolate the decision process being tested."
  - fail: "When the inject expects both a rapid operational response AND a complex decision without facilitator support, retain severity. Rationale: Injects conflating speed and decision complexity test neither reliably."
```

## Resolution Path
1. Add facilitator notes to each inject explaining what decision process is being evaluated
2. Separate speed-focused injects from decision-focused injects in the exercise timeline
3. Document the exercise objective (decision-making, communication, or technical response) for each inject

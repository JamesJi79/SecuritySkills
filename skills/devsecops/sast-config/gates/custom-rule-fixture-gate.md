# Custom Rule Test Fixture Evidence Gate

## Purpose
Prevents false-positive "insufficient SAST coverage" findings when the codebase uses custom SAST rules that include test fixtures demonstrating rule correctness, even if the rule coverage percentage appears low. The gate evaluates whether custom rules have adequate test evidence rather than relying solely on coverage metrics.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "insufficient SAST coverage" or "custom rule gap" as Medium/High
2. Custom SAST rules exist with corresponding test fixtures
3. Test fixtures cover both positive (should trigger) and negative (should not trigger) cases

### Gate Check: Fixture Completeness

```yaml
check_fixture_completeness:
  - detection_patterns:
      - "custom.*rule|SAST.*rule|custom.*pattern|rule.*fixture"
      - "test.*fixture|positive.*test|negative.*test|false.*positive.*test"
      - "Semgrep.*test|codeql.*test|sonar.*test|gosec.*test"
  - pass: "Custom rule has at least one positive test (should alert) and one negative test (should not alert) → Downgrade to Medium (Observation). Rationale: Custom rules with bidirectional test fixtures are more trustworthy than coverage metrics alone."
  - fail: "Custom rule has no test fixtures OR only positive/negative tests without the counterpart → Keep severity. Rules without negative tests are prone to false positives."
```

### Gate Check: Fixture Quality

```yaml
check_fixture_quality:
  - detection_patterns:
      - "fixture.*file|test.*case|rule.*test|assert.*alert"
      - "ok.*no.*match|should.*match|rule.*id.*test"
  - pass: "Test fixtures use realistic code patterns (not trivial placeholders) → Accept. Recommend periodic fixture review to ensure patterns stay relevant."
  - fail: "Test fixtures use trivial patterns (empty functions, single-line files) → Escalate. Trivial fixtures don't validate rule correctness in real code scenarios."
```

# LLM-Assisted Triage Evidence Gate

## Purpose
Prevents false-positive downgrade of alert severity when LLM-generated triage recommendations are accepted without independent verification of the LLM's reasoning chain and supporting evidence.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. The triage output references an LLM-generated analysis or recommendation as the primary disposition basis
2. The LLM's reasoning chain is not accompanied by verifiable evidence from the alert data (raw logs, SIEM fields, threat intel matches)
3. The disposition confidence is rated High or Medium without corroborating manual correlation

### Gate Check: LLM Reasoning Trace

```yaml
check_llm_reasoning_trace:
  - detection_patterns:
      - "LLM (analysis|assessment|suggests|recommends)"
      - "AI-generated (triage|disposition)"
      - "based on (LLM|AI|language model) (analysis|output)"
  - pass: "When LLM reasoning is accompanied by step-by-step trace of evidence sources (raw event fields, matched rules, TI lookups), severity may be downgraded. Rationale: Traceable reasoning enables auditor verification of each claim."
  - fail: "When LLM output is presented as a disposition without traceable evidence links, retain original severity and flag for manual review. Rationale: Untraceable AI reasoning is not auditable evidence."
```

### Gate Check: Evidence Completeness

```yaml
check_evidence_completeness:
  - detection_patterns:
      - "disposition: (TP|BTP|FP)"
      - "confidence: (High|Medium)"
      - "escalation: (Yes|No)"
  - pass: "When at least 3 of the 4 evidence sources (alert payload fields, correlated events, threat intel matches, asset context) are cited in the reasoning, downgrade is permitted. Rationale: Multi-source correlation reduces false-positive risk from single-source LLM misinterpretation."
  - fail: "When fewer than 3 evidence sources support the LLM's disposition, or when only LLM text is cited, retain original severity. Rationale: Insufficient evidence for confident disposition."
```

## Resolution Path
1. Include the LLM's raw input (alert data sent to the model) and output (disposition, reasoning) as an appendix to the triage report
2. Cross-reference each LLM claim against at least one verifiable data source from the alert or correlated events
3. Mark the triage report with "LLM-assisted" and ensure a human analyst reviews and signs off before escalation

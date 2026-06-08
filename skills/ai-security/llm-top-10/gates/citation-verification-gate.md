# Factual Claim and Citation Verification Gate

## Purpose
Prevents false-positive LLM09 misinformation findings when factual claims cite specific, verifiable sources (including inline citations, retrieval-grounded passages, or hyperlinked references), even when no formal fact-checking score is provided. The current skill flags any AI-generated output as potentially unverified without distinguishing source-attributed claims from unsupported assertions.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "misinformation risk" or "unverified factual claim" as High/Critical
2. Each material factual claim in the output is accompanied by a specific, accessible source (URL, document reference, dataset citation, inline citation)
3. The citation format follows a recognized standard (APA, MLA, numbered footnotes, hyperlinks, RAG source indicies)

### Gate Check: Citation Existence

```yaml
check_citation_existence:
  - detection_patterns:
      - "misinformation|misinfo|hallucination|LLM09|factual.*error"
      - "citation|reference|source.*claim|claim.*attribution"
      - "according to|per.*source|as reported by|see.*reference|RAG.*source"
  - pass: "Every material factual claim has an inline citation or verifiable source reference → Downgrade to Medium (Defense-in-Depth). Rationale: Citation-attributed claims are verifiable and auditable. The risk shifts from hallucination to citation accuracy, which is a lower-severity concern."
  - fail: "Unsourced factual claims present OR citations reference non-existent/unreachable sources → Keep original severity. Require source verification."
```

### Gate Check: Claim Verifiability

```yaml
check_claim_verifiability:
  - detection_patterns:
      - "generated text|AI.*output|LLM.*response|model.*claim"
      - "fact.*check|verify.*source|source.*exist|support.*text"
  - pass: "Claims cite specific, verifiable sources (URLs that resolve, DOIs that exist, document IDs that can be looked up) → Accept with Recommendation to add fact-checking. Claims are technically verifiable even if formal verification requires manual effort."
  - fail: "Claims cite generic sources ('research shows', 'studies indicate') without specific references → Escalate to High. Generic attribution is indistinguishable from hallucination."
```

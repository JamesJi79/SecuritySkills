# Approval-Artifact Provenance Gate

## Purpose
Prevents false-positive "approval bypass" findings when AI agent approval decisions are bound to canonical executable artifacts (signed container digests, SLSA provenance attestations, signed commits) rather than model-written summaries or natural-language descriptions. The current skill may flag all approval-to-artifact binding as insufficient when the binding is done through cryptographic attestation rather than explicit code references.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "approval not bound to artifact" or "approval bypass risk" as High/Critical
2. The system uses cryptographic attestation for approval-artifact binding (SLSA provenance, in-toto attestation, cosign signatures, Sigstore bundle)
3. Approval records include digest references (SHA256, OCI digest, git commit hash)

### Gate Check: Attestation Binding

```yaml
check_attestation_binding:
  - detection_patterns:
      - "approval.*artifact|artifact.*approval|binding.*approval"
      - "slsa|in-toto|cosign|sigstore|attestation.*provenance"
      - "sha256:|digest|oci.*digest|commit.*hash|git.*sha"
  - pass: "Approval bound to artifact via cryptographic attestation (SLSA/in-toto/Sigstore) → Downgrade to Low (Observation). Rationale: Cryptographic attestation provides stronger binding than code references. Attestations are tamper-evident and verifiable independently of the approval workflow."
  - fail: "Approval recorded against natural-language description or untrusted artifact path → Keep High/Critical severity. Implement digest-based artifact pinning."
```

### Gate Check: Privacy-Preserving Alternatives

```yaml
check_privacy_alternatives:
  - detection_patterns:
      - "prompt.*hash|redact.*parameter|policy.*trace|correlation.*id"
      - "privacy.*preserv|mask.*prompt|anonymize.*approval|hash.*artifact"
  - pass: "Privacy-preserving alternatives (prompt hashes, redacted parameters, policy traces, correlation IDs) used to avoid exposing sensitive context in approval records → Accept. Ensure correlation IDs can be traced to full context during incident response."
  - fail: "Full prompt/context exposed in approval records → Recommend privacy-preserving alternatives. Information exposure risk in approval audit trail."
```

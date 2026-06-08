# SBOM Artifact Freshness Evidence Gate

## Purpose
Prevents false-positive "SBOM mismatch" findings when the SBOM is bound to the specific software artifact under review through artifact digest, build/release ID, generator version, and pipeline provenance—even if the SBOM timestamp appears stale. The current skill records only the SBOM timestamp without requiring artifact binding evidence.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "stale SBOM" or "SBOM-artifact mismatch" as High
2. The SBOM includes artifact binding metadata (digest, build ID, release ID, pipeline ID)
3. The binding metadata matches the artifact under review

### Gate Check: Artifact Binding

```yaml
check_artifact_binding:
  - detection_patterns:
      - "SBOM.*freshness|SBOM.*stale|artifact.*digest|build.*SBOM"
      - "SBOM.*timestamp|point.*in.*time|snapshot.*date"
      - "generator.*version|pipeline.*SBOM|release.*SBOM"
  - required_binding:
      - "Artifact digest (SHA256 or similar)"
      - "Build or release ID"
      - "SBOM generator name and version"
      - "Pipeline or CI run that produced the SBOM"
  - pass: "SBOM includes ALL four artifact binding fields AND matches the reviewed artifact → Downgrade to Low (Informational). Rationale: A bound SBOM describes the exact artifact, regardless of when it was generated."
  - fail: "SBOM missing artifact binding OR binding does not match reviewed artifact → Keep High severity. Unbound SBOMs may describe different code than what is deployed."
```

### Gate Check: Freshness Context

```yaml
check_freshness_context:
  - detection_patterns:
      - "deploy.*date|release.*date|artifact.*age|SBOM.*age"
      - "supply.*chain.*review|vendor.*risk|SBOM.*valid"
  - pass: "SBOM age is within the organization's accepted window AND artifact binding is confirmed → Downgrade to Observation. Age is secondary when binding is confirmed."
  - fail: "SBOM age exceeds accepted window AND no artifact binding → Escalate. Old unbounded SBOMs should not be used for compliance or vulnerability response."
```

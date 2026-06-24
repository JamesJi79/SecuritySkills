# Artifact Attestation Subject Gate

## Purpose
Prevents false-positive findings when CI/CD pipeline security reviews flag missing artifact attestation for build artifacts that are produced and consumed within a trusted supply chain with compensating integrity controls (signed git tags, branch protection, SLSA-compliant build platform).

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A build artifact (container image, binary, package) is flagged as lacking attestation or SLSA provenance
2. The artifact is built on a platform with branch protection, required reviews, and signed commits
3. The artifact is consumed only within the same trusted organization or supply chain

### Gate Check: Compensating Integrity Controls

```yaml
check_compensating_integrity_controls:
  - detection_patterns:
      - "attestation|provenance|SLSA|in.?to.?to|signed.?tag|signed.?commit"
      - "branch.?protection|required.?review|status.?check|CODEOWNERS"
      - "container.*sign|image.*sign|cosign|notary|sigstore|fulcio"
  - pass: "When the build platform enforces branch protection, required PR reviews, and signed commits, AND the artifact is distributed through a trusted registry with access controls, downgrade to informational. Rationale: Platform-level integrity controls provide equivalent assurance to per-artifact attestation for internal supply chains."
  - fail: "When the build platform lacks branch protection or the artifact is distributed through public or untrusted channels without attestation, retain severity. Rationale: Without platform integrity, missing attestation creates genuine supply chain risk."
```

### Gate Check: Attestation Implementation Feasibility

```yaml
check_attestation_feasibility:
  - detection_patterns:
      - "container.*build|docker.*build|kaniko|buildah|ko|jib"
      - "gradle.*build|maven.*deploy|npm.*publish|pip.*publish"
      - "github.*actions|gitlab.*ci|jenkins|circleci"
  - pass: "When the build toolchain supports attestation generation (Cosign, Jib, Tekton Chains) AND the team has a documented plan to implement it within the next sprint, downgrade severity. Rationale: A documented implementation plan with toolchain support reduces urgency."
  - fail: "When the toolchain does not support attestation, or there is no plan to implement it, retain severity. Rationale: Missing attestation in a supply chain without compensating controls is a security gap requiring remediation."
```

## Resolution Path
1. Document the current build platform's integrity controls (branch protection, signed commits, registry access controls)
2. Determine which attestation format (SLSA provenance, in-toto, Cosign) is feasible for the current toolchain
3. If using GitHub Actions or GitLab CI, enable OIDC-based attestation via Sigstore or native CI/CD attestation features
4. If the artifact is internal-only and platform integrity is strong, document the compensating controls as an exception

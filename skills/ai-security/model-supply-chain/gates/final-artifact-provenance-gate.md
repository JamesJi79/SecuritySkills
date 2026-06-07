# Final Artifact Provenance Gate

## Purpose
Prevents false-positive "missing final-artifact verification" findings when the ML pipeline produces signed model artifacts (safetensors with SHA256 digests, ONNX with model signatures, MLflow model registry with versioning) or when the output is validated against a known-good test suite before release, even if formal SLSA provenance is not yet implemented.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "no final-artifact provenance" or "no output integrity check" as High
2. The pipeline produces signed or digest-verified model artifacts
3. The pipeline includes post-training validation (accuracy benchmark, fairness test, adversarial robustness check)

### Gate Check: Artifact Signing

```yaml
check_artifact_signing:
  - detection_patterns:
      - "safetensors|model.*signature|mlflow.*register|model.*version.*tag"
      - "onnx.*sign|tensorflow.*saved_model|torch.*jit.*script"
      - "sha256.*model|digest.*artifact|hash.*model.*file"
  - pass: "Model artifact has cryptographic digest OR model registry versioning → Downgrade to Medium (Recommendation). Rationale: Digest verification ensures artifact integrity. Model registry versioning provides audit trail for which artifact was deployed and when."
  - fail: "No artifact digest and no registry versioning → Keep severity. Without provenance, the deployed artifact cannot be verified against what was tested and approved."
```

### Gate Check: Validation Pipeline

```yaml
check_validation_pipeline:
  - detection_patterns:
      - "accuracy.*test|benchmark.*suite|evaluation.*pipeline|model.*eval"
      - "fairness.*check|adversarial.*test|robustness.*validation"
      - "golden.*dataset|test.*suite.*model|regression.*test"
  - pass: "Pipeline includes automated validation against known-good test suite → Accept. Validation results provide functional provenance even without formal SLSA attestation."
  - fail: "No post-training validation → Escalate to High. Artifacts may contain regressions, backdoors, or degraded performance not caught before deployment."
```

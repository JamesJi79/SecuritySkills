# Remote Code Execution Provenance Gate

## Purpose
Prevents false-positive "unverified remote code" findings when code is fetched from trusted registries with integrity verification (PyPI with hash pinning, npm with lockfile + SRI, Hugging Face Hub with commit pinning, Docker Hub with digest) even when the code is dynamically loaded at runtime. The current skill may conflate dynamic loading with untrusted code execution.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "remote code execution" or "dynamic code loading" as Critical
2. The code is loaded from a trusted registry with integrity verification
3. The registry artifact is pinned to a specific version, commit, or digest

### Gate Check: Registry Integrity

```yaml
check_registry_integrity:
  - detection_patterns:
      - "from.*transformers|huggingface.*hub|from_pretrained|load_dataset"
      - "pip.*install|npm.*install|docker.*pull|ghcr.*pull"
      - "hash.*pin|integrity.*sha|lock.*file|digest.*verify"
  - pass: "Code loaded from trusted registry WITH integrity verification → Downgrade to Medium (Defense-in-Depth). Rationale: Pinned versions with integrity hashes prevent supply-chain substitution attacks. The risk is limited to the pinned version's known vulnerabilities."
  - fail: "Code loaded from raw URL, unpinned registry, or local file system → Keep Critical severity. Untracked code changes can introduce backdoors."
```

### Gate Check: Model Provenance

```yaml
check_model_provenance:
  - detection_patterns:
      - "model.*card|model.*provenance|huggingface.*metadata|model.*sha"
      - "safetensors|onnx.*model|pickle.*model|ckpt.*file"
  - pass: "Model has signed provenance (model card, safetensors, ONNX signature) → Accept. Model provenance provides the model's training lineage and security review."
  - fail: "Model loaded from untrusted source without provenance → Escalate. Untrusted models can contain backdoors, trojans, or unsafe pickle deserialization."
```

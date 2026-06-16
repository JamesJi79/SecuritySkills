# Module Source Digest and Mirror Pinning Gate

## Purpose
Prevents false-positive findings when Terraform/OpenTofu module source pins tag plus digest or trusted mirror, by requiring the reviewer to verify that mutable references (branches, tags) and private registry mirrors are not bypassing integrity verification.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. IaC module source references a tag, branch, or registry path
2. Source includes a digest hash or references a trusted private mirror
3. Module source uses a mutable branch or tag from a public Git source without checksum verification

### Gate Check: Module Source Integrity

```yaml
check_module_source_integrity:
  - detection_patterns:
      - "source\s*=\s*\"git::"
      - "source\s*=\s*\"[^\"]+//"
      - "ref\s*=\s*\"[a-f0-9]{7,40}\"|tag\s*=\s*\"[^\"]+\""
      - "version\s*=\s*\"[~^><=]"
      - "registry\.terraform\.io|registry\.opentofu\.org"
  - pass: >
      "Every module source reference uses an immutable content-addressable
      identifier (Git commit SHA pinned with digest, or registry version pinned
      to an exact semver with verified checksum). Mutable references (branches,
      floating tags) are not used for any module sourced from public Git
      repositories. Mirror resolution uses only trusted, integrity-verified
      registries."
    Rationale: "Tag mutability and branch-based references introduce a
      supply-chain integrity risk. A tag can be retagged to point to a
      different commit, and a branch always points to the latest commit. Digest
      pinning (S3 checksum, or Terraform registry protocol version checksum)
      ensures the module content is what the reviewer intended."
  - fail: >
      "One or more modules use mutable source references (branch, floating tag
      without digest) from public Git. Recommend pinning to an immutable commit
      SHA with a registry checksum, or sourcing from a trusted private mirror
      with verified integrity."
```

### Gate Check: Private Registry Mirror Integrity

```yaml
check_mirror_integrity:
  - detection_patterns:
      - "mirror|private registry"
      - "prox(y|ied)|cache"
      - "terraform providers mirror"
      - "filesystem_mirror|network_mirror"
  - pass: >
      "Private registry mirrors enforce content-addressed serving (version +
      checksum or protocol-level integrity verification). The mirror cannot
      serve a different module under the same version identifier. Mirror
      updates require signed or verified provenance."
    Rationale: "A compromised or misconfigured private mirror can serve a
      modified module under the same version tag. Terraform registry protocol
      v1 supports SHA256 checksum verification — mirrors that skip or disable
      this verification create a supply-chain vector."
  - fail: >
      "Private mirror configuration does not enforce content-addressed serving
      or checksum verification. Recommend enabling registry protocol integrity
      checks or implementing signed provenance for mirror updates."
```

## Resolution Path
1. Replace all mutable Git references (branches, floating tags) with immutable commit SHAs
2. Enable registry protocol checksum verification for all module downloads
3. For private mirrors, implement content-addressed serving with signed provenance

# Secret Exposure vs Control Gap Gate

## Purpose
Prevents false-positive secret-detection findings by distinguishing between *actual exposed secrets* (committed credentials, tokens, API keys) and *architectural control gaps* (missing gitleaks config, missing pre-commit hooks, missing secrets baseline). The current skill flags the latter as though they were the former, which conflates operational posture with active exposure.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags the absence of `.gitleaks.toml`, `.secrets.baseline`, TruffleHog CI job, or pre-commit hooks
2. The repo contains no committed `.env` files, no checked-in API keys, no hardcoded tokens or credentials
3. The CI pipeline does not push or deploy secrets to any external service

### Gate Check: Exposure vs. Control Gap

```yaml
check_exposure_vs_gap:
  - description: "Determine if the finding is an active secret exposure or a missing control"
  - detection_patterns:
      - "no \.gitleaks\.toml|no \.secrets\.baseline|missing pre-commit|TruffleHog.*not configured"
      - "gitleaks|trufflehog|secrets.*scanner|secret.*detect"
  - pass: "No committed secrets found in repo history (git diff HEAD, .env*, token patterns, key patterns) → Downgrade to Medium (Recommendation). Rationale: This is a missing preventative control, not an active exposure. The finding should be reclassified as 'Secrets Detection Coverage Gap' rather than 'Exposed Secret Credential'."
  - fail: "Confirmed committed secrets found → Keep original severity. Proceed to standard secrets management review."
```

### Gate Check: Evidence Collection

```yaml
check_evidence_collection:
  - description: "Verify the reviewer has actually searched for committed secrets before concluding exposure"
  - required_evidence:
      - "git log -p --all -S '<pattern>' for common secret patterns (API_KEY, password, secret, token, credential)"
      - "find . -name '.env*' -not -path '*/.git/*'"
      - "grep -r '-----BEGIN.*PRIVATE KEY-----' . --include='*.{key,pem,p12,pfx}' 2>/dev/null"
      - "Check GitHub secret scanning alerts if available"
  - pass: "Evidence collected and no active secrets found → Apply control-gap downgrade"
  - fail: "No evidence collection documented → Instruct reviewer to collect evidence before filing finding"
```

## Resolution Path

1. If the finding is a **control gap**: Create or recommend adding `.gitleaks.toml`, `.secrets.baseline`, or pre-commit hook configuration. File as a Medium-severity recommendations track item.
2. If the finding is an **active exposure**: Escalate to immediate secret rotation, revoke compromised credentials, audit git history with `git filter-repo` or BFG Repo-Cleaner.

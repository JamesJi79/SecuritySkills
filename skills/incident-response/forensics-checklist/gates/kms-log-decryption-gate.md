# KMS Log Decryption Gate

## Purpose
Prevents false-positive forensics findings when KMS-encrypted logs are inaccessible during investigation due to key rotation or access control, but the organization implements key escrow, automatic decryption at log ingestion, or KMS key access audit trails.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. KMS-encrypted logs (CloudTrail, application logs, database audit logs) cannot be decrypted
2. The organization uses KMS key escrow or automatic decryption at ingestion time
3. KMS key access is audited and key rotation events are tracked

### Gate Check: Decryption-at-Ingestion

```yaml
check_decryption_at_ingestion:
  - detection_patterns:
      - "KMS|key.*management.*service|encrypt.*log|decrypt.*log|log.*encrypt"
      - "CloudTrail.*encrypt|S3.*server.*side.*encrypt|SSE.?KMS|AWS.*KMS"
      - "log.*ingestion|log.*pipeline|log.*forward|decrypt.*at.*ingest"
  - pass: "When logs are decrypted at ingestion time before storage in the SIEM/log analytics platform, downgrade to informational. Rationale: Decryption-at-ingestion ensures log content is available for investigation regardless of KMS key state."
  - fail: "When logs remain encrypted in the log analytics platform and are decrypted on read, retain severity. Rationale: On-read decryption creates a dependency on KMS key availability during investigations."
```

### Gate Check: Key Escrow

```yaml
check_key_escrow:
  - detection_patterns:
      - "key.*escrow|key.*backup|key.*rotat|key.*archive"
      - "recovery.*key|master.*key|key.*store|HSM|cloud.*HSM"
      - "key.*access.*audit|key.*usage.*log|key.*grant|key.*policy"
  - pass: "When KMS keys used for log encryption are escrowed (backed up to a secondary region or HSM), AND key access is audited with alerts for unauthorized use, downgrade severity. Rationale: Escrowed keys with audit trails ensure log decryptability and detect key misuse."
  - fail: "When KMS keys are not escrowed or key access is not audited, retain severity. Rationale: Without escrow, KMS key loss or rotation renders encrypted logs permanently inaccessible."
```

## Resolution Path
1. Configure logs to be decrypted at ingestion time by the SIEM or log analytics platform
2. Implement KMS key escrow with cross-region replication for forensic availability
3. Enable KMS key access auditing with alerts for unauthorized decryption attempts
4. Document the key recovery procedure in the incident response plan

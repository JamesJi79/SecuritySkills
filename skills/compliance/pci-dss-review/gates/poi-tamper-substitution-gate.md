# POI Device Tamper and Substitution Evidence Gate

## Purpose
Prevents false-positive PCI DSS POI device tamper findings when the assessed environment uses hardware security modules (HSMs), tamper-evident seals, secure enclaves, or remote attestation that make physical tampering detectable or impractical. The current skill may flag any POI environment lacking manual inspection logs as non-compliant.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "POI device tamper protection missing" as High/Critical
2. The environment uses hardware-based tamper detection (HSM, TPM, secure enclave, tamper-evident seals)
3. OR the POI interaction is remote/API-based with no physical device present

### Gate Check: Hardware Tamper Evidence

```yaml
check_hardware_tamper:
  - detection_patterns:
      - "POI.*tamper|tamper.*evidence|device.*substitution|terminal.*replace"
      - "HSM|TPM|secure.*enclave|tamper.*evident.*seal|remote.*attestation"
      - "PCI.*tamper|point.*of.*interaction|PIN.*entry.*device"
  - pass: "Hardware-based tamper detection covers all POI touchpoints with documented verification frequency → Downgrade to Low (Compliance Note). Rationale: Hardware tamper detection (HSM/TPM/seals) meets PCI DSS requirements when properly managed."
  - fail: "No hardware tamper detection for physical POI devices → Keep severity. Physical POI devices without tamper evidence are a PCI DSS violation."
```

### Gate Check: Substitution Detection

```yaml
check_substitution_detection:
  - detection_patterns:
      - "device.*inventory|serial.*number|hardware.*register|device.*attest"
      - "replace.*device|swap.*terminal|substitute.*reader"
  - pass: "POI device inventory with attestation (signed serials, TPM quotes, HSM certificates) → Accept. Substitution would require breaking hardware attestation."
  - fail: "No device inventory or attestation → Escalate. Undocumented device substitution is a common PCI DSS attack vector."
```

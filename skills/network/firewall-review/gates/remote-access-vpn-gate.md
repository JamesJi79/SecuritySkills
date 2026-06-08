# Remote Access VPN and Split-Tunnel Evidence Gate

## Purpose
Prevents false-positive "split-tunnel risk" findings when remote access VPN configurations use per-app VPN (tunnel all work traffic, allow personal traffic direct) on managed devices with endpoint compliance checks, MDM policy enforcement, and device posture verification. The current firewall-review skill may flag any split-tunnel configuration as insecure without evaluating compensating controls.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "split-tunnel enabled" or "remote access VPN risk" as High
2. The VPN uses per-app/per-route tunnel policies (not full-tunnel with bypass)
3. Endpoint compliance (MDM, device posture, OS version) is verified before tunnel establishment

### Gate Check: Split-Tunnel Assessment

```yaml
check_split_tunnel:
  - detection_patterns:
      - "split.?tunnel|remote.*access.*VPN|VPN.*bypass|per.*app.*VPN"
      - "MDM.*policy|device.*complian|endpoint.*posture|device.*attest"
      - "tunnel.*all.*traffic|route.*based.*VPN|app.*level.*tunnel"
  - pass: "Per-app/per-route VPN with endpoint compliance verification → Downgrade to Medium (Observation). Rationale: Managed devices with MDM and device posture checks significantly reduce split-tunnel risk. Corporate traffic is tunneled; personal traffic is isolated."
  - fail: "Full split-tunnel without endpoint compliance → Keep severity. Unmanaged split-tunnel allows malware on the personal network to pivot to corporate resources."
```

### Gate Check: Compliance Verification

```yaml
check_compliance_verification:
  - detection_patterns:
      - "device.*check|OS.*version|patch.*level|disk.*encrypt"
      - "antivirus.*status|firewall.*status|device.*attestation"
  - pass: "Endpoint compliance verified before VPN tunnel establishment AND periodic re-checks during session → Accept. Compliance verification ensures only trusted devices can access corporate resources."
  - fail: "No device compliance check before tunnel establishment → Escalate. Any device can use the VPN, rendering perimeter controls ineffective."
```

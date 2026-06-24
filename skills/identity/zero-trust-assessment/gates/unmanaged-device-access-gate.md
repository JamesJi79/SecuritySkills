# Unmanaged Device Access Gate

## Purpose
Prevents false-positive zero-trust findings when unmanaged devices (BYOD, contractor machines, guest devices) can access internal applications, but compensating controls including browser isolation, read-only session mode, session recording, and DLP policies limit the data exposure risk.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Unmanaged devices (not enrolled in MDM/UEM, no corporate security agent) can access internal applications
2. Access is limited to specific low-sensitivity applications or read-only mode
3. Compensating controls (browser isolation, DLP, session recording, clipboard/print/upload restrictions) are enforced

### Gate Check: Browser Isolation

```yaml
check_browser_isolation:
  - detection_patterns:
      - "browser.*isolat|remote.*browser|clientless.*access|VDI.*access"
      - "BYOD|unmanaged.*device|contractor.*access|guest.*access|bring.*your.*own"
      - "read.?only|view.*only|download.*restrict|clipboard.*restrict"
  - pass: "When access from unmanaged devices is routed through a browser isolation solution (Cloudflare Browser Isolation, Zscaler Cloud Browser, Menlo Security) or remote desktop/VDI, downgrade to informational. Rationale: Browser isolation renders data visually without exposing raw data to the unmanaged device."
  - fail: "When unmanaged devices have native application access (installable client, direct VPN, full SSH/RDP) without isolation, retain severity. Rationale: Native access from unmanaged devices exposes the application and its data to the untrusted device."
```

### Gate Check: DLP Enforcement

```yaml
check_dlp_enforcement:
  - detection_patterns:
      - "DLP|data.?loss.*prevent|data.*exfiltrat|watermark|print.*block"
      - "download.*block|upload.*scan|clipboard.*block|copy.*restrict"
      - "session.*record|screen.*record|user.*activity.*log"
  - pass: "When DLP policies block download, print, and clipboard copy from sessions initiated by unmanaged devices, AND all user activity is recorded, downgrade severity. Rationale: DLP controls on unmanaged device sessions prevent data exfiltration while recording user activity."
  - fail: "When unmanaged device sessions have no DLP controls or session recording, retain severity. Rationale: Unrestricted access from unmanaged devices without DLP creates an exfiltration pathway."
```

## Resolution Path
1. Route unmanaged device access through a browser isolation or VDI solution
2. Enforce DLP policies that block download, print, and copy for unmanaged sessions
3. Enable session recording for all unmanaged device access
4. Configure conditional access policies to require step-up auth for unmanaged device sessions

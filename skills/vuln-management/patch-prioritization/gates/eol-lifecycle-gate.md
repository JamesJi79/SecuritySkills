# EOL and No-Patch Lifecycle Evidence Gate

## Purpose
Prevents false-positive "missing patch" findings when a vulnerability affects software that has reached End-of-Life (EOL) or has no available patch from the vendor. The patch-prioritization skill should distinguish between "patch available but not applied" (actionable) and "no patch exists" (requires migration or compensating controls).

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "missing patch" or "unpatched vulnerability" as High/Critical
2. The affected software is EOL or the vendor has not released a patch
3. Compensating controls (WAF rules, network segmentation, disable feature) exist

### Gate Check: Patch Availability

```yaml
check_patch_availability:
  - detection_patterns:
      - "EOL|end.?of.?life|end.?of.?support|unsupported.*version"
      - "no.*patch|vendor.*not.*releas|patch.*not.*available|supplier.*fix"
      - "CVE.*no.*fix|unpatchable|won.?t.*fix|no.*remediation"
  - pass: "Vulnerability has no available patch (EOL software, vendor not releasing fix) → Downgrade to Medium (Risk Acceptance Required). Rationale: Cannot patch what doesn't exist. Requires formal risk acceptance or migration plan."
  - fail: "Patch IS available but not applied → Keep Critical severity. This is a true unpatched vulnerability requiring immediate remediation."
```

### Gate Check: Compensating Controls

```yaml
check_compensating_controls:
  - detection_patterns:
      - "WAF.*rule|network.*segment|firewall.*block|access.*control"
      - "feature.*disabled|module.*removed|mitigation.*in.*place"
      - "compensat.*control|workaround|vendor.*recommend"
  - pass: "Compensating controls fully mitigate the EOL/no-patch vulnerability (e.g., WAF blocks the exploit, feature is disabled) → Accept with Risk Acceptance. Document the compensating control as the official mitigation."
  - fail: "No compensating controls OR controls only partially mitigate → Keep severity. EOL software without compensating controls requires immediate migration."
```

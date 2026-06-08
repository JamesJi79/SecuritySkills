---
name: benign-provenance-native-build
expected: pass
---

# Benign package with verified provenance and CI sandbox

## Package metadata

```
package: native-addon
postinstall: node-gyp rebuild
publisher: verified_org
provenance: sigstore_verified
script_network_access: blocked_in_CI
```

## Evidence

| Field | Value |
|---|---|
| Maintainer history | Stable — same publisher for 18 months |
| Publisher verification | Sigstore + GitHub verified org |
| Script behavior | Native build only — no network, env, or conditional execution |
| CI sandbox | Egress disabled, registry allow-list enabled |

## Expected review result

Pass the takeover gates. The package is from a verified publisher with stable history, native-build-only script, and CI sandbox controls.

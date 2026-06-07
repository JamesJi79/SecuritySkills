# MCP/Plugin Tool Provenance Gate

## Purpose
Prevents false-positive "unverified plugin tool" findings when MCP (Model Context Protocol) servers, plugins, or tool servers are pinned to specific versions, use signed manifests, or are deployed from a curated registry with integrity verification (e.g., npm package lock, pip requirements hash, Docker content trust, Sigstore verification).

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "unverified MCP/tool-server provenance" as High
2. The tool/plugin has version pinning (semver lock, git tag, digest pin)
3. The tool/plugin uses signed manifests or integrity verification (Subresource Integrity, package lock, Docker Content Trust)

### Gate Check: Version Pinning

```yaml
check_version_pinning:
  - detection_patterns:
      - "mcp.*server|tool.*server|plugin.*install|mcp_.*install"
      - "package-lock|yarn.lock|pipfile\.lock|poetry.*lock|go\.sum"
      - "digest.*pin|@sha256|image.*digest|container.*digest"
  - pass: "Version pinning with integrity verification confirmed → Downgrade to Low (Informational). Rationale: Lock files and digest pins provide supply-chain integrity. The MCP server cannot be silently replaced without updating the lock file."
  - fail: "No version pinning OR no integrity verification → Keep severity. Unpinned MCP servers can be replaced via supply-chain attack."
```

### Gate Check: Secret Scoping

```yaml
check_secret_scoping:
  - detection_patterns:
      - "per.*server.*secret|tool.*secret.*scope|mcp.*secret"
      - "env.*per.*tool|secret.*permission|scope.*credential"
  - pass: "Secrets scoped per MCP server/tool (not shared global credentials) → Accept. Each tool server has access only to its required secrets."
  - fail: "Shared/global secrets accessible to all MCP servers → Escalate to High. A compromised MCP server gains access to all tool credentials."
```

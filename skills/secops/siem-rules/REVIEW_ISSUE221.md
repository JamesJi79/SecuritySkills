# SecuritySkills Audit Report — siem-rules (Issue #221)

> **Auditor:** Hermes Agent — Review Subagent
> **Repo:** github.com/UnitOneAI/SecuritySkills
> **Date:** 2026-06-03
> **Skill:** skills/secops/siem-rules/SKILL.md
> **Issue:** #221 — "add deployment metadata and alert validation"

---

## Audit Summary

| Metric | Value |
|--------|-------|
| Skill Name | siem-rules |
| Bundle | SecOps |
| File Path | `skills/secops/siem-rules/SKILL.md` |
| Overall Status | **PARTIAL** — minor gaps found |
| Issue Scope | Deployment metadata + alert validation |
| Estimated Enhancement Complexity | **Medium** |

---

## Per-Rule Assessment

### Rule 1 — Skills Are System Layer, Not Markdown Files
**Status: PARTIAL**

| Component | Present? | Notes |
|-----------|----------|-------|
| Executable verification steps | NO | No scripts exist; query validation is all manual prose |
| Automation scripts / workflow triggers | NO | No rule deployment scripts, no CI/CD integration patterns |
| Data patterns (regex, signatures, AST) | PARTIAL | KQL/SPL query patterns are inline in the markdown, but no extractable pattern files |
| Scaffolding templates | PARTIAL | Output format template exists in Section 5 but is minimal; no deployable ARM/JSON/YAML templates |

**Finding:**
The skill is entirely a single markdown file. It contains comprehensive documentation and query examples but no executable components. To serve as a true "system layer," it should include:
- A `/scripts/` directory with validation scripts (e.g., KQL syntax checker, test query runner)
- A `/templates/` directory with deployable rule templates (Sentinel Analytics Rule JSON, Splunk savedsearches.conf)
- A `/references/` directory extracting the inline ATT&CK tables, KQL operator reference, and SPL reference into standalone files

**Action Required:** ADD `/scripts/`, `/templates/`, and `/references/` directories with deployable components.

---

### Rule 2 — Verification Before Done
**Status: PARTIAL**

| Verification Component | Present? | Notes |
|-----------------------|----------|-------|
| Expected behavior (what secure looks like) | YES | Section 4 describes findings classification severity levels |
| Actual behavior check (how to confirm fix held) | NO | No actual verification steps; Pitfall #4 mentions this conceptually but doesn't provide concrete simulation steps |
| Falsifiable test or simulation step | NO | No test data, no simulation commands, no expected output assertions |

**Senior Engineer Gate:** Would a senior security engineer accept this as verified?
**NEEDS WORK** — The output format includes a `Validation` field but leaves it as a placeholder `[How to test the rule produces a true positive]`. A senior engineer would want concrete procedures for generating test events (e.g., `Invoke-Mimikatz` for credential dumping tests, password spray simulation scripts, atomics-red-team integration).

**Action Required:** ADD a dedicated verification section with concrete simulation/test procedures.

---

### Rule 3 — Demand Elegance
**Status: PASS**

| Elegance Check | Finding |
|----------------|---------|
| Redundant sub-bullets that restate parent | NO (clean) — Sections are well-structured with clear hierarchy |
| Overlap with other skills in same bundle | PARTIAL — Some overlap with `detection-engineering` skill (both cover ATT&CK mapping and detection logic), but the split is reasonable (Sigma rules vs. platform-specific KQL/SPL) |
| Overengineered logic for simple vuln class | NO (clean) — Content is appropriately detailed for the complexity tiers described |

**Refactor Notes:**
Minor overlap with `detection-engineering` is acceptable since SIEM rules are the platform-specific implementation of detection logic. No refactoring needed.

**Action Required:** NONE

---

### Rule 4 — File System = Context Engine
**Status: FAIL**

| Directory Convention | Required? | Exists? | Action |
|---------------------|-----------|---------|--------|
| `/references/` — threat patterns, MITRE links, KQL/SPL references | YES | NO | CREATE |
| `/scripts/` — verification scripts, query syntax checkers | YES | NO | CREATE |
| `/templates/` — rule deployment scaffolding (ARM, JSON, YAML) | YES | NO | CREATE |

**Inline knowledge to extract:**
- ATT&CK technique-to-data-source mapping table (Section 6)
- KQL operator quick reference (Section 6)
- SPL command quick reference (Section 6)
- Sentinel table reference (Section 3)
- Splunk sourcetype reference (Section 3)
- Azure AD ResultType error code table (Section 3)
- Windows Event Code reference (embedded in SPL section)

**Action Required:** CREATE `/references/`, `/scripts/`, and `/templates/` directories; EXTRACT inline reference data to `/references/`.

---

### Rule 5 — Self-Improvement Loop (Gotchas)
**Status: PASS**

| Gotchas Component | Present? | Count |
|------------------|----------|-------|
| Known false positive patterns | YES | 5 pitfalls in Section 7 (Common Pitfalls) |
| Precision traps (fix breaks agent behavior) | YES | Pitfalls cover over-broad queries, hardcoding, performance, validation gaps |
| Real exploit pattern lessons (agentic context) | PARTIAL | Pitfalls are general; could benefit from platform-specific gotchas (e.g., Sentinel KQL pagination limits, Splunk search timeouts) |

**Existing Gotchas:**
Section 7 covers 5 solid pitfalls: (1) Overly broad queries, (2) Performance impact, (3) Hardcoded values, (4) No validation against TP test cases, (5) Duplicate alert suppression.

**Gotchas to Add:**
1. **Platform quota limits** — KQL queries in Sentinel have a 500,000 row limit per query; queries returning more rows silently truncate results. Always consider `take`/`limit` and query efficiency.
2. **Time zone assumptions** — Splunk `_time` is always UTC but Windows event logs often record local time. Always use `convert timeformat=` or `strftime` with explicit timezone.

**Action Required:** EXPAND existing gotchas with platform-specific entries.

---

### Rule 6 — Avoid Over-Constraining the Agent
**Status: PASS**

| Over-Constraint Check | Finding |
|-----------------------|---------|
| Rigid prescriptive steps that remove agent judgment | NO (clean) — Intent-first structure with flexible patterns |
| Missing rationale ("why" behind security control) | NO (present) — Rationale is provided for thresholds, tuning methodology, and pattern selection |
| Instructions that cause failure on valid edge cases | NO (clean) — Queries use variables and configurable thresholds |

**Structure Check:** Does the skill follow **Intent → Constraints → Flexibility**?
**YES** — Each detection pattern starts with intent (the threat), constraints (data sources, time windows), and flexible parameters (thresholds, exclusions).

**Action Required:** NONE

---

### Rule 7 — Subagent Strategy Alignment
**Status: PASS**

| Subagent Check | Finding |
|----------------|---------|
| Single-responsibility (one focused subagent can execute) | YES — SIEM rule development is a focused domain |
| No cross-bundle context dependency | YES — Standalone skill within SecOps bundle |
| Parallelizable (marked explicitly?) | NO — Not explicitly marked, but could be parallelized with detection-engineering |
| Mixed concerns present | NO (clean) — All sections relate to SIEM rule lifecycle |

**Action Required:** NONE (could optionally add `parallelizable: true` note)

---

## Issue #221-Specific Findings

### Deployment Metadata — MISSING

The skill currently has **no structured deployment metadata**. Key gaps:

1. **No rule packaging format** — No ARM template for Sentinel Analytics Rules, no Splunk savedsearches.conf example, no YAML/JSON schema for rule metadata
2. **No CI/CD integration** — No guidance on deploying rules via infrastructure-as-code (Terraform, Bicep, Ansible)
3. **No versioning schema** — No semantic versioning for rules, no changelog format
4. **No environment mapping** — No guidance on promoting rules through dev → test → prod
5. **No entity mapping output** — While the output format table shows entity types, it doesn't show the actual JSON/API payload for Sentinel entity mapping or Splunk data models

### Alert Validation — PARTIAL

The skill references validation but doesn't provide concrete mechanisms:

1. **Output format placeholder** — The `Validation` field reads `[How to test the rule produces a true positive]` — an empty template
2. **No simulation framework** — No integration with atomic-red-team, Caldera, or Stratus Red Team
3. **No test data** — No sample log data to validate queries against
4. **No expected output assertions** — No documented expected result counts or patterns

---

## Enhancement Plan

**Priority:** P1 — SecOps bundle first

**Estimated Complexity:** **Medium**

**Changes to implement:**

1. **Add deployment metadata section** — New Section 5a after current Section 5 (Output Format), covering:
   - Rule metadata JSON/YAML schema
   - Sentinel Analytics Rule ARM template pattern
   - Splunk savedsearches.conf example
   - CI/CD pipeline integration guidance
   - Environment promotion strategy

2. **Replace validation placeholder with concrete procedures** — Rewrite the `Validation` line in Section 5 output format template with:
   - Atomic Red Team test references
   - Log simulation commands
   - Expected output assertions
   - Query execution verification steps

3. **Extract reference data** — Move inline tables to `/references/` files

4. **Create template files** — Add `/templates/sentinel-analytics-rule.json` and `/templates/splunk-savedsearches.conf`

5. **Expand gotchas** — Add platform-specific gotchas as noted in Rule 5

---

## Precision Regression Check

- [x] Agent behavior preserved after enhancement (adding sections, not removing)
- [x] Vulnerability/detection class still covered after refactor
- [ ] No new false positives introduced (N/A — no detection logic changed)
- [ ] Verified against synthetic agent session (pending implementation)

---

## Audit Completion Checklist

- [x] Skill scored per all 7 rules
- [x] Heatmap filled for applicable rules
- [x] FAIL rules have Action Required filled
- [x] PARTIAL rules have Action Required filled
- [x] `/references/` directories need creation
- [x] `/scripts/` logic extraction needed
- [x] `/templates/` scaffolding needed
- [x] Gotchas section present (needs expansion)
- [ ] All enhanced components verified (pending)
- [ ] Precision regression check passed (pending)

---

*SecuritySkills Audit v1.0 — UnitOne.ai*
*Issue #221 — siem-rules: add deployment metadata and alert validation*

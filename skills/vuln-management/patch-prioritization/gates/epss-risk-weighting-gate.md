# EPSS v3 Active Exploitation Weighting Gate

## Purpose
Prevents rigid SLA enforcement for high-CVSS vulnerabilities with negligible exploitation probability by incorporating EPSS v3 trend analysis and CISA KEV ransomware labels into SLA tier assignment.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. The SLA assignment is driven primarily by CVSS base score (e.g., "all 9.0+ = P0 Emergency / 24h")
2. EPSS score for the vulnerability is below 0.1 (negligible exploitation probability)
3. The vulnerability is NOT listed on CISA KEV as "Known Exploited" or "Ransomware"

### Gate Check: EPSS Risk-Based SLA Override

```yaml
check_epss_sla_override:
  - condition: "CVSS >= 9.0 AND EPSS < 0.01"
    action: "Override P0 (24h) → P2 (30-day scheduled). Rationale: EPSS < 1% means near-zero probability of exploitation in the wild. 24-hour SLA imposes unnecessary emergency change risk."
  - condition: "CVSS >= 9.0 AND EPSS 0.01-0.1"
    action: "Override P0 (24h) → P1 (72h). Rationale: EPSS > 1% indicates measurable exploitation activity, but below 10% does not warrant emergency response."
  - condition: "CVSS >= 9.0 AND EPSS >= 0.1 AND < 0.4"
    action: "Maintain P0 (24h). EPSS >= 10% indicates active exploitation in the wild. 24-hour SLA is justified."
  - condition: "CVSS >= 9.0 AND EPSS >= 0.4"
    action: "Escalate to P0-Emergency with executive notification. EPSS >= 40% indicates widespread active exploitation."
```

### Gate Check: CISA KEV Ransomware Label

```yaml
check_kev_ransomware_override:
  - description: "CISA KEV 'Ransomware' label overrides all EPSS-based SLA adjustments"
  - rule: "If CISA KEV 'Known Exploited' AND 'Ransomware' label is True → Force P0 / 24h regardless of EPSS score"
  - rationale: "Ransomware-labeled vulnerabilities are actively used by ransomware operators. Response speed directly impacts ransom payment probability."
  - exception: "Compensating controls that fully mitigate the vulnerability (WAF rule, network segmentation, feature disabled) may downgrade to P1 / 72h"
```

### Gate Check: EPSS Trend Analysis

```yaml
check_epss_trend:
  - description: "Evaluate EPSS score trajectory over 7/30/90 days to detect rising threats"
  - rising: "EPSS 7-day trend > 30% increase → Escalate one SLA tier even if current score is low"
  - falling: "EPSS 7-day trend > 50% decrease → May downgrade one SLA tier if no other risk factors present"
  - stable: "EPSS within ±10% over 30 days → Maintain current SLA tier"
```

## Remediation Steps

When this gate modifies an SLA assignment:

1. **Document the override** — Record in the patch plan: "SLA adjusted from [original] to [adjusted] based on EPSS <threshold> (score: X.XX) and CISA KEV status: [listed/not listed]."
2. **Flag compensated vulnerabilities** — If compensating controls exist, the SLA may be further relaxed. Reference compensating-controls-assessment in SKILL.md.
3. **Set review date** — Schedule a re-evaluation in 30 days. EPSS scores change daily; a vulnerability with EPSS 0.005 today may be 0.5 next month.
4. **Notify stakeholders** — If SLA was downgraded, inform asset owners and change management of the adjusted timeline.

## False Positive Prevention

- Do NOT apply EPSS overrides to CISA KEV "Known Exploited" vulnerabilities — KEV status always takes precedence.
- Do NOT apply EPSS overrides to vulnerabilities with active exploitation intelligence (threat feeds, dark web mentions, vendor advisories) — override only when ACTIVE EXPLOITATION is CONFIRMED.
- Do NOT apply EPSS overrides to internet-facing assets with sensitive data — maintain strict SLA for externally exposed critical systems.

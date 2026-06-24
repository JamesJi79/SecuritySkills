# Ransomware Payment Legal Gate

## Purpose
Prevents false-positive findings when an incident response playbook references ransomware payment procedures, but the organization has a documented legal and board-approved ransomware payment decision framework that satisfies regulatory and insurance requirements.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. The IR playbook contains a section on ransomware payment decision-making or cryptocurrency acquisition procedures
2. The organization has a documented ransomware payment policy approved by legal counsel and the board of directors
3. The policy references current OFAC sanctions guidance, cyber insurance requirements, and law enforcement notification procedures

### Gate Check: Legal Framework

```yaml
check_ransomware_legal_framework:
  - detection_patterns:
      - "ransomware.*payment|ransom.*demand|decrypt.*payment|extortion.*payment"
      - "cryptocurrency.*acquis|bitcoin.*purchase|coinbase.*ransom"
      - "OFAC|sanctions.*check|SDN.*list|FinCEN"
  - pass: "When the playbook references a board-approved ransomware payment policy that includes OFAC sanctions screening, law enforcement notification (FBI/CISA), and cyber insurance pre-approval, downgrade to informational. Rationale: A formal legal framework with sanctions compliance satisfies regulatory requirements for ransomware payment consideration."
  - fail: "When the playbook includes payment instructions without referencing a legal framework, OFAC compliance, or law enforcement notification procedures, retain severity. Rationale: Ransomware payment without legal framework exposes the organization to sanctions violations and regulatory penalties."
```

### Gate Check: Insurance Pre-Approval

```yaml
check_insurance_pre_approval:
  - detection_patterns:
      - "cyber.?insurance|cyber.?policy|ransomware.*coverage|incident.*response.*retainer"
      - "insurance.*pre.?approval|insurer.*notif|claim.*submi"
      - "breach.*coach|legal.*counsel|outside.*counsel"
  - pass: "When the playbook requires cyber insurance carrier notification and pre-approval before any payment discussion, downgrade severity. Rationale: Insurance policy terms typically require pre-approval; following this process maintains coverage."
  - fail: "When the playbook allows payment discussion or authorization without requiring insurance notification, retain severity. Rationale: Making or considering ransom payment without insurance involvement may void coverage."
```

## Resolution Path
1. Verify the organization's ransomware payment policy is current (reviewed within 12 months) and references OFAC's advisory on ransomware payments
2. Confirm the playbook includes a step to notify law enforcement (FBI, CISA, or local cybercrime unit) before any payment decision
3. Ensure the cryptocurrency acquisition process is documented and includes sanctions screening (SDN list check)
4. Add the insurance pre-approval step if missing, with specific contact information for the cyber insurance claims line

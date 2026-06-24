# Customer Comms Status-Page Gate

## Purpose
Prevents false-positive IR playbook findings when incident communication to customers is delayed or uses informal channels, but the organization has a status page and automated notification system with predefined communication templates.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A PIR finding flags that customer communications during the incident were delayed or inconsistent
2. The organization maintains a public status page (Statuspage, Incident.io, Atlassian Opsgenie)
3. Communication templates exist for different incident types and severity levels

### Gate Check: Status Page Availability

```yaml
check_status_page_availability:
  - detection_patterns:
      - "status.*page|statuspage|incident.*page|service.*health|service.*status"
      - "customer.*notif|customer.*updat|customer.*communicat"
      - "automated.*notif|notif.*template|incident.*template|communicat.*template"
  - pass: "When the organization has a public status page with automated incident creation, AND communication templates are defined for at least three incident milestones (detected, investigating, resolved), downgrade to informational. Rationale: Status page with automated milestone updates provides consistent customer communication with minimal manual effort."
  - fail: "When no status page exists, or communication is ad-hoc without templates, retain severity. Rationale: Ad-hoc incident communication without templates or automation leads to inconsistent or delayed customer updates."
```

### Gate Check: SLA Bump Notification

```yaml
check_sla_bump_notification:
  - detection_patterns:
      - "SLA.*bump|SLA.*violat|SLA.*exceed|notification.*SLA"
      - "escalation.*notif|management.*notif|customer.*SLA|contract.*SLA"
      - "incident.*SLA|response.*time|resolution.*time|customer.*impact"
  - pass: "When the status page automatically updates when an incident is at risk of exceeding customer SLAs, AND premium/enterprise customers receive targeted notifications, downgrade severity. Rationale: SLA-aware status page updates ensure high-value customers receive proactive communication."
  - fail: "When no SLA-bump notification exists and customers learn about incidents through support tickets or social media, retain severity. Rationale: Reactive customer incident communication damages trust and may breach contractual notification obligations."
```

## Resolution Path
1. Deploy a status page solution with automated incident creation from monitoring alerts
2. Create communication templates for each severity level: detecting, investigating, mitigating, resolved
3. Configure SLA-bump notifications for customers with contractual notification requirements
4. Test the end-to-end communication flow during tabletop exercises quarterly

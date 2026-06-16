# Break-Glass Audit Trail Evidence Gate

## Purpose
Prevents false-positive findings when emergency PHI access has a pre-approved workflow and immutable post-use review, by requiring the reviewer to verify that the break-glass access cannot bypass accountability controls before classifying the pattern as compliant.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. System implements emergency/break-glass access to ePHI
2. A pre-approved workflow and post-use review process is documented
3. The break-glass role can view ePHI without reason capture or independent manager review

### Gate Check: Break-Glass Accountability Controls

```yaml
check_break_glass_accountability:
  - detection_patterns:
      - "break.?glass|emergency access"
      - "pre.?approved workflow"
      - "post.?use review"
      - "privileged access|emergency role"
      - "PHI|ePHI|protected health information"
  - pass: >
      "Break-glass access requires reason capture at time of access, includes
      automatic notification to security officer and privacy officer, and
      produces immutable audit records in a separate system from the one the
      privileged user can access. Manager review is independent and enforced
      within 48 hours."
    Rationale: "HIPAA 45 CFR 164.312(b) requires audit controls. Emergency
      access procedures under 164.312(a)(2)(iii) are addressable but, when
      implemented, must include accountability. Audit logs stored in the same
      system the emergency user can alter defeat the purpose of auditing."
  - fail: >
      "Break-glass access lacks reason capture, does not notify security/privacy
      officers, or stores audit logs in the same system the emergency user can
      alter. Require independent immutable audit trail, reason capture, and
      automated officer notification before approving emergency access pattern."
```

### Gate Check: Post-Use Review Enforcement

```yaml
check_post_use_review:
  - detection_patterns:
      - "post.?use review|post.?access review"
      - "manager review|supervisor review"
      - "justification|reason for access"
      - "time limit|expiration|auto.?revoke"
  - pass: >
      "Post-use review is enforced within a documented time window (48 hours
      recommended), reviewer is independent of the access requester, and
      unresolved findings escalate to the designated security/privacy officer
      automatically."
    Rationale: "Post-use review is the compensating control for emergency
      access without prior authorization. Without a defined review window and
      escalation path, review obligations can be deferred indefinitely, creating
      a standing privilege escalation."
  - fail: >
      "Post-use review has no defined time window, reviewer is not independent,
      or there is no escalation path for unresolved findings. Recommend defining
      a maximum review window and automated escalation."
```

## Resolution Path
1. Ensure break-glass access captures reason at time of access (not retroactively)
2. Store audit logs in a separate immutable system from the one the emergency user can access
3. Configure automatic notification to security officer and privacy officer upon break-glass activation
4. Enforce post-use review within 48 hours by an independent reviewer

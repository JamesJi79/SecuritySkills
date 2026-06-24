# Shared Admin Attribute Abuse Gate

## Purpose
Prevents false-positive privileged access findings when shared administrative accounts (root, administrator, break-glass) have attributes that appear inconsistent with least privilege, but the accounts are managed through a privileged access management (PAM) system with session recording, credential rotation, and just-in-time (JIT) elevation.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A shared admin account has broad privileges (domain admin, root, cloud admin)
2. The account is managed through a PAM system (CyberArk, BeyondTrust, Delinea, Azure PIM, HashiCorp Vault)
3. Access to the shared account requires approval, is time-bound, and is recorded

### Gate Check: PAM Session Controls

```yaml
check_pam_session_controls:
  - detection_patterns:
      - "PAM|privileged.*access.*management|CyberArk|BeyondTrust|Delinea|Thycotic"
      - "session.*record|session.*monitor|keystroke.*record|screen.*record"
      - "JIT|just.?in.?time|time.*bound|ephemeral|credential.*checkout"
  - pass: "When the shared account is accessed through a PAM system that enforces session recording, credential checkout with expiry, and approval workflows, downgrade to informational. Rationale: PAM-managed shared accounts with session recording and JIT access provide stronger controls than individual named admin accounts."
  - fail: "When the shared admin account password is shared outside of a PAM system (stored in a shared document, password manager group, or communicated verbally), retain severity. Rationale: Unmanaged shared credentials with session recording create an attribution gap."
```

### Gate Check: Credential Rotation

```yaml
check_credential_rotation:
  - detection_patterns:
      - "password.*rotat|credential.*rotat|secret.*rotat|key.*rotat"
      - "checkout.*expir|check-in|releas|automatic.*rotat"
      - "post.?session|post.?use.*rotat|ephemeral.*credential"
  - pass: "When the PAM system rotates the shared account password immediately after each checkout session, downgrade severity. Rationale: Post-session rotation ensures that even if session logs are incomplete, the credential cannot be reused."
  - fail: "When the shared account password is rotated on a fixed schedule (monthly/quarterly) rather than per-use, retain severity. Rationale: Fixed-schedule rotation leaves a window for credential reuse between rotations."
```

## Resolution Path
1. Check that all shared admin accounts are onboarded into the PAM system with session recording enabled
2. Verify post-session credential rotation is enabled for each account
3. Remove shared admin passwords from any non-PAM storage (shared documents, password managers)
4. Configure approval workflows for shared account access with time-bound checkouts

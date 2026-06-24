# Registrar Account Takeover MFA Evidence Gate

## Purpose
Prevents false-positive findings when domain registrar accounts are flagged as lacking MFA, but the account uses an alternative strong authentication method (FIDO2 security key, passkey, hardware TOTP, SSO with MFA) that is not detected by the standard MFA check.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A domain registrar account (GoDaddy, Namecheap, Cloudflare, AWS Route53, Google Domains) is flagged as MFA-disabled
2. The registrar supports authentication methods beyond standard TOTP (FIDO2, WebAuthn, passkeys, hardware tokens, SSO federation)
3. The account has domain management privileges (ability to transfer, delete, or modify DNS)

### Gate Check: Alternative MFA Detection

```yaml
check_alternative_mfa_detection:
  - detection_patterns:
      - "(u2f|fido2|webauthn|passkey|hardware.*token|yubikey|titan.*key)"
      - "(sso|saml|oidc|azure.*ad|okta|google.*workspace) (with|via|through)"
      - "security.*key|platform.*authenticator|biometric"
  - pass: "When the registrar account is authenticated via SSO that requires MFA at the IdP level, or has FIDO2/passkey registered as a second factor, downgrade to informational. Rationale: Alternative MFA methods provide equivalent or stronger protection than TOTP and may not be detected by standard MFA checks."
  - fail: "When the account relies solely on password authentication without any registered second factor or SSO, retain severity. Rationale: Password-only domain registrar access is a critical takeover risk."
```

### Gate Check: Account Activity Monitoring

```yaml
check_account_activity_monitoring:
  - detection_patterns:
      - "registrar|domain.*manage|dns.*hosting|name.*server"
      - "domain.*transfer|domain.*push|auth.*code|ep"
      - "registrant.*contact|whois|domain.*lock|transfer.*lock"
  - pass: "When the registrar account has out-of-band notifications (email + SMS) enabled for critical actions (transfer out, auth code request, contact change) AND a registrant lock or transfer lock is active, downgrade severity. Rationale: Layered administrative controls reduce the impact of a credential compromise even without MFA."
  - fail: "When critical action notifications are not enabled or the domain lacks a registrar/transfer lock, retain severity. Rationale: Without monitoring and locks, a credential compromise can silently exfiltrate domain ownership."
```

## Resolution Path
1. Log into the registrar's security settings and verify all registered authentication methods (not just whether TOTP is on)
2. If SSO MFA is used, confirm the IdP MFA policy is enforced on the registrar SAML/OIDC app
3. Enable domain transfer lock and registrant lock if not already active
4. Set up out-of-band notifications for all critical domain actions: transfer out, auth code request, contact modification, nameserver change
5. If MFA is genuinely absent, enable at least one strong factor (TOTP app, security key, or passkey) immediately

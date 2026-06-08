---
name: vulnerable-ai-web-app-without-guard
expected: fail
---

# Vulnerable AI-integrated web app missing security controls

## AI integration context

```
ai_endpoint: /api/v1/chat
prompt_injection_guard: none
data_boundary: full_conversation_included_in_context
third_party_model: unverified_public_api
```

## Evidence

| Field | Value |
|---|---|
| Prompt injection | None — raw user input passed directly to AI model |
| Data leakage | Full conversation (including PII) included in model context |
| Supply chain | Unverified public API, no SLA, no security assessment |
| Model update | Automatic updates from provider, no version control |

## Expected review result

Fail. No prompt injection protection, PII exposed in model context, unverified third-party API, and no version control.

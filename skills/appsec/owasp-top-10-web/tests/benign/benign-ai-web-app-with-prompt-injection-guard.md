---
name: benign-ai-web-app-with-prompt-injection-guard
expected: pass
---

# Benign AI-integrated web app with prompt injection and data leakage protection

## AI integration context

```
ai_endpoint: /api/v2/ai/chat
prompt_injection_guard: enabled (input sanitization + output validation)
data_boundary: PII_stripped_before_inference
third_party_model: verified_provider_with_SOC2
```

## Evidence

| Field | Value |
|---|---|
| Prompt injection | Input sanitization + output validation + rate limiting |
| Data leakage | PII stripped before inference, session isolated |
| Supply chain | SOC2 report reviewed, fallback to local model documented |
| Model update | Versioned model deployments with rollback capability |

## Expected review result

Pass. AI integration has prompt injection protection, data leakage prevention, and supply chain risk management.

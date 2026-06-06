# Sanitizer API and Framework Context Gate

## Purpose
Prevents false-positive `innerHTML` Critical severity flags by detecting when the code uses modern Sanitizer API, framework-specific protections (React/Vue/Svelte), or controlled context that makes `innerHTML` safe.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags `innerHTML`, `outerHTML`, `insertAdjacentHTML`, or similar direct HTML injection as "Critical" or "High"
2. The codebase uses a modern JavaScript framework (React, Vue, Svelte, Angular, Solid)
3. OR the code explicitly uses the Sanitizer API (`Element.setHTML()` or `Sanitizer`)
4. OR the `innerHTML` assignment uses a static/controlled string (not user input)

### Gate Check: Sanitizer API Usage

```yaml
check_sanitizer_api:
  - description: "Detect if the codebase uses the Sanitizer API (Element.setHTML or new Sanitizer)"
  - detection_patterns:
      - "Element.setHTML\\("
      - "new Sanitizer\\("
      - "\.setHTML\\("
  - pass: "Sanitizer API detected → Downgrade severity to Medium (Low). Rationale: Sanitizer API strips script content and malicious attributes before insertion."
  - fail: "No Sanitizer API → Continue to framework context check"
```

### Gate Check: Framework-Specific Context

```yaml
check_framework_context:
  - framework: "React"
    detection: "React.createElement, JSX, or dangerouslySetInnerHTML"
    rules:
      - "dangerouslySetInnerHTML with static content (no template/variable interpolation) → Downgrade to Medium"
      - "dangerouslySetInnerHTML with sanitized/escaped user content → Keep as High, flag for proper CSP"
      - "JSX with dynamic content that IS NOT innerHTML → No finding (React escapes by default)"
  - framework: "Vue"
    detection: "v-html directive"
    rules:
      - "v-html binding to a computed property that sanitizes → Downgrade to Medium"
      - "v-html binding to raw user input → Keep as High"
  - framework: "Svelte"
    detection: "{@html}" 
    rules:
      - "{@html} with template literal containing no raw user interpolation → Downgrade to Medium"
      - "{@html} with user-supplied content → Keep as High"
```

### Gate Check: Static Content Verification

```yaml
check_static_content:
  - description: "Verify whether innerHTML content is dynamically constructed from user input"
  - static_indicators:
      - "String literal (quoted content with no variables)"
      - "Template literal with only static segments"
      - "Predefined constant or configuration value"
      - "Server-rendered safe HTML (SSR output with CSP nonce)"
  - dynamic_indicators:
      - "User input concatenation (+ operator)"
      - "Template literal interpolation (${...}) with request/URL/db data"
      - "Response data, query parameters, or stored user content"
  - verdict_static: "Content is static/controlled → Downgrade to Low. Informational: 'innerHTML used with static content. No XSS vector.'"
  - verdict_dynamic: "Content is user-derived → Maintain Critical severity. Require Sanitizer API or DOMPurify before insertion."
```

## Remediation Steps

When this gate downgrades an innerHTML finding:

1. **Document the context** — "innerHTML finding downgraded from Critical to [X]. Rationale: [Sanitizer API / framework context / static content]."
2. **Recommend CSP addition** — Even with context-justified innerHTML, recommend `script-src` and `require-trusted-types-for` CSP headers as defense-in-depth.
3. **Flag for code review** — If Sanitizer API is used, verify the Sanitizer config doesn't allow `script` elements or `on*` handlers.

## False Positive Prevention

- Do NOT downgrade innerHTML findings that use `DOMPurify.sanitize()` or similar third-party libraries INSTEAD of native Sanitizer API — these should remain as Medium findings (they are safer than raw innerHTML but not as rigorously maintained as the native API).
- Do NOT downgrade innerHTML findings in legacy codebases without framework context (jQuery, vanilla JS, Backbone.js) — these are genuine XSS vectors.

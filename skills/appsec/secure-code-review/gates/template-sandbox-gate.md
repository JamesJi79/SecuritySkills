# Template Sandbox and Context-Escaping Gate

## Purpose
Prevents false-positive template injection findings when the codebase uses framework-native auto-escaping (React JSX, Vue template syntax, Angular interpolation, Jinja2 autoescape, Go text/template) that renders template injection impractical even when user input flows through template variables.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "template injection" or "server-side template injection (SSTI)" as Critical/High
2. The codebase uses a framework with auto-escaping (React, Vue, Angular, Jinja2 with autoescape, Go html/template)
3. The reported injection vector passes through template variables/functions, not raw template string concatenation

### Gate Check: Framework Auto-Escaping Assessment

```yaml
check_auto_escaping:
  - detection_patterns:
      - "template.*injection|SSTI|server-side template|handlebars|mustache"
      - "React\.createElement|JSX|v-bind|:innerHTML|ng-bind-html|jinja2.*autoescape"
  - pass: "Framework with auto-escaping confirmed → Downgrade to Medium (Context-Dependent). Rationale: The reported vector would require bypassing framework-level escaping (e.g., dangerouslySetInnerHTML, v-html, raw filter). If the code uses these bypasses, escalate; otherwise, this is a defense-in-depth finding."
  - fail: "No framework auto-escaping OR template string concatenation confirmed → Keep Critical severity. SSTI allows RCE in most template engines."
```

### Gate Check: Sandbox Escape Path

```yaml
check_sandbox_escape:
  - description: "Check if the template engine provides a sandbox and whether it can be escaped"
  - detection_patterns:
      - "sandbox.*bypass|sandbox.*escape|restricted.*python|eval.*template"
      - "jinja2.*sandbox|go.*template.*no.*escape"
  - pass: "Template engine uses sandbox mode (Jinja2 SandboxedEnvironment, Go text/template with restricted funcs) → Downgrade to Low. Escaping sandboxed environments requires known CVEs."
  - fail: "Template engine without sandbox AND user input flows through template directives → Keep High/Critical."
```

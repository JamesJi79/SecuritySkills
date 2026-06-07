# Tool-Output Taint and Delegated Capability Gate

## Purpose
Prevents false-positive "tool-output taint" findings when AI agent tool outputs are consumed through structured schemas with explicit capability scoping (Pydantic models, Zod schemas, TypeScript interfaces, protobuf definitions) that validate and constrain how tool outputs can be used, preventing taint propagation even when agent tool outputs contain external data.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "tool-output taint" or "delegated capability misuse" as High/Critical
2. Tool outputs are validated through structured schemas before consumption
3. Agent capabilities are scoped to specific tools with defined input/output contracts

### Gate Check: Structured Schema Validation

```yaml
check_schema_validation:
  - detection_patterns:
      - "pydantic.*model|zod.*schema|typescript.*interface|protobuf.*message"
      - "tool.*output|function.*result|mcp.*response|agent.*tool.*call"
      - "validation.*schema|input.*sanitiz|output.*filter|taint.*check"
  - pass: "Tool outputs validated through structured schemas with capability scoping → Downgrade to Low (Observation). Rationale: Schema validation prevents unexpected data shapes and provides a contract boundary. Taint propagation requires bypassing the schema validation layer."
  - fail: "Tool outputs consumed as raw/untyped data → Keep severity. Without schema validation, any tool output can be interpreted as any type, enabling injection and data confusion attacks."
```

### Gate Check: Capability Scoping

```yaml
check_capability_scoping:
  - detection_patterns:
      - "capability.*scope|permission.*tool|tool.*allowlist|function.*allow"
      - "agent.*can.*only|tool.*restrict|scope.*delegate|limit.*tool"
  - pass: "Agent capabilities scoped to explicit allowlist of tools with defined contracts → Accept. Capability scoping ensures tool misuse requires compromising the capability management system."
  - fail: "Agent has unrestricted tool access OR tools lack input/output contracts → Escalate to High. Unrestricted agents can delegate capabilities to untrusted tool outputs, creating capability escalation paths."
```

### Gate Check: Delegation Depth

```yaml
check_delegation_depth:
  - detection_patterns:
      - "delegate.*task|sub.*agent|subtask.*agent|recursive.*agent"
      - "max.*depth|max.*delegation|iteration.*limit|recursion.*limit"
  - pass: "Delegation depth explicitly limited AND parent agent reviews sub-agent outputs before action → Accept. Controlled delegation prevents capability escalation through recursive agent calls."
  - fail: "Unbounded delegation OR sub-agent outputs consumed without parent review → Escalate to High. Deep delegation chains create opaque capability boundaries."
```

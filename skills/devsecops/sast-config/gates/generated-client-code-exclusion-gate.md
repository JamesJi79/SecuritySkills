# Generated Client Code Exclusion Gate

## Purpose
Prevents false-positive SAST findings when generated client code (OpenAPI clients, gRPC stubs, GraphQL codegen, SDK wrappers) contains security issues that are outside the developer's control and cannot be remediated by modifying the generated output.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. The flagged file is in a directory or has a header comment indicating auto-generation (OpenAPI, gRPC, GraphQL, Swagger Codegen, etc.)
2. The finding is in generated code that mirrors an API specification rather than hand-written business logic
3. The generation tool and source specification are under version control and can be remediated at the spec level

### Gate Check: Generated File Marker

```yaml
check_generated_file_marker:
  - detection_patterns:
      - "auto-generated|auto.?generated|generated.?by|do.?not.?edit|DO NOT EDIT"
      - "openapi.?generator|swagger.?codegen|grpc.*generat|protoc"
      - "graphql.*codegen|client.*gen|sdk.*generat"
  - pass: "When the file has a generated marker AND the generation tool and source spec are in the same repository, downgrade to informational. Rationale: Issues in generated code should be fixed at the spec/template level, not in the generated output. The real vulnerability is in the spec."
  - fail: "When the file has a generated marker but no source spec or generation tool is version-controlled, retain severity. Rationale: Generated code without a spec is effectively orphaned code that must be maintained manually, making the finding actionable."
```

### Gate Check: Spec-Level Fix Available

```yaml
check_spec_level_fix_available:
  - detection_patterns:
      - "api.*spec|openapi.*yaml|openapi.*json|swagger|proto|graphql.*schema"
      - "template.*file|mustache|handlebars|codegen.*template"
      - "generator.*config|codegen.*config|openapitools.json"
  - pass: "When the vulnerability can be fixed by modifying the API spec or codegen template (e.g., adding input validation patterns to the spec, updating template security headers), downgrade severity. Rationale: Spec-level fixes propagate to all generated clients, providing a systemic fix."
  - fail: "When the vulnerability is inherent to the code generation process itself and cannot be fixed at the spec/template level, retain severity. Rationale: Findings that require post-generation patching are genuine code quality issues."
```

## Resolution Path
1. Identify the source spec file (OpenAPI YAML, .proto, GraphQL schema, etc.) and codegen configuration
2. Determine if the finding can be remediated by modifying the spec (e.g., adding pattern constraints, security definitions) or the codegen template
3. If spec-level fix is possible, submit a PR to the spec/template and regenerate the client
4. If spec-level fix is not possible, add a post-generation patch script or add the generated directory to the SAST scanner's exclusion list with a documented exception

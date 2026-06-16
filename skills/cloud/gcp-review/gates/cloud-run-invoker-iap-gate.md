# Cloud Run Invoker and IAP Effective Path Gate

## Purpose
Prevents false-positive findings when Cloud Run service requires intended invoker/IAP path and denies direct URL when needed, by requiring the reviewer to verify that IAP protects the frontend but the direct Cloud Run URL is not left publicly accessible, and that invoker roles are not granted through unintended folder/project inheritance.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Cloud Run service defines invoker IAM or is behind Identity-Aware Proxy (IAP)
2. Service is configured to deny direct URL access when IAP is required
3. Invoker role could be inherited from folder/project level, making the URL public

### Gate Check: Effective Ingress Path Verification

```yaml
check_effective_ingress:
  - detection_patterns:
      - "Cloud Run|cloud run|cloudrun"
      - "invoker|Invoker|roles/run.invoker"
      - "IAP|Identity-Aware Proxy|identity aware proxy"
      - "ingress|ingress rule|ingress settings"
      - "direct URL|run\.app|default URL"
  - pass: >
      "Cloud Run ingress is set to "require IAP" mode (ingress = internal-and-cloud-load-balancing)
      when IAP is the intended access path. The default `run.app` URL is disabled
      (ingress settings restrict to load balancer traffic only). IAP is configured
      on the External HTTPS Load Balancer frontend. No direct URL access bypasses
      IAP authentication."
    Rationale: "IAP protects the frontend Load Balancer path, but the Cloud Run
      service also has a direct `run.app` URL. If the direct URL is accessible
      (ingress = all), any user with the URL can bypass IAP entirely. IAP and
      invoker IAM are independent controls — both must be verified."
  - fail: >
      "Cloud Run ingress allows direct URL access (ingress = all or
      internal-only), which bypasses IAP authentication. Recommend setting
      ingress to require Cloud Load Balancing traffic when IAP is the intended
      access path, and disabling the default `run.app` URL if not needed."
```

### Gate Check: Invoker IAM Inheritance Audit

```yaml
check_invoker_inheritance:
  - detection_patterns:
      - "invoker|roles/run\.invoker"
      - "allUsers|allAuthenticatedUsers"
      - "folder|project|organization IAM"
      - "IAM inheritance|conditional binding"
      - "public access|anonymous access"
  - pass: >
      "Invoker IAM bindings are scoped directly to the Cloud Run service resource
      (not inherited from parent folder/project). There are no allUsers or
      allAuthenticatedUsers bindings at the project or folder level that would
      grant unintended invoker access to this service. Conditional IAM bindings
      with resource-level conditions are used when project-level grants are
      necessary."
    Rationale: "A project-level roles/run.invoker grant to allUsers
      inadvertently makes every Cloud Run service in the project publicly
      accessible, regardless of per-service invoker settings. IAM inheritance
      is a common source of unintended public exposure."
  - fail: >
      "Invoker role is granted through folder or project inheritance, or has
      allUsers/allAuthenticatedUsers bindings that apply to this service.
      Recommend binding invoker roles directly to the Cloud Run service resource
      and auditing parent-level IAM for unintended public access grants."
```

## Resolution Path
1. Set Cloud Run ingress to require Cloud Load Balancing traffic when IAP is used
2. Disable or restrict the default `run.app` URL
3. Bind invoker roles directly to the Cloud Run service resource, not through project/folder inheritance
4. Audit project and folder IAM for allUsers/allAuthenticatedUsers bindings that include roles/run.invoker
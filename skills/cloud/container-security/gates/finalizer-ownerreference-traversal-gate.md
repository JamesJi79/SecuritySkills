# Kubernetes Finalizer and OwnerReference Traversal Gate

## Purpose
Prevents false-positive findings when controllers validate ownerReferences/finalizers before acting on resources, by requiring the reviewer to verify that an attacker cannot add malicious ownerReferences or finalizers to block deletion, trigger unintended controller actions, or exploit cross-namespace references.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Controller logic acts based on ownerReferences or finalizers on Kubernetes resources
2. Controller validates ownerReferences/finalizers before acting
3. An attacker could add a malicious ownerReference or finalizer to block deletion or trigger controller side effects

### Gate Check: OwnerReference Validation

```yaml
check_ownerreference_validation:
  - detection_patterns:
      - "ownerReference|ownerReferences"
      - "metadata\.ownerReferences"
      - "controller|operator|reconciler"
      - "blockOwnerDeletion|orphanDependents"
      - "apiVersion|kind|name|uid"
  - pass: >
      "The controller verifies ALL fields of the ownerReference (apiVersion,
      kind, name, AND uid) before taking action based on it. The controller
      does not act on ownerReferences where the uid does not match an existing,
      accessible resource. Cross-namespace ownerReferences are rejected because
      Kubernetes does not enforce cross-namespace ownership — the controller
      MUST implement its own boundary check."
    Rationale: "An attacker can set an ownerReference pointing to any resource
      they do not own. A controller that only checks name and kind (without uid)
      will act on the malicious reference. Cross-namespace ownerReferences are
      particularly dangerous because Kubernetes allows them syntactically but
      does not verify the owner exists in the same namespace."
  - fail: >
      "Controller does not validate the uid field of ownerReferences, or does
      not reject cross-namespace ownerReferences. An attacker can create a
      resource with a malicious ownerReference pointing to a different namespace
      or resource type, potentially triggering unintended controller behavior.
      Recommend validating uid and rejecting cross-namespace references."
```

### Gate Check: Finalizer Abuse Prevention

```yaml
check_finalizer_abuse:
  - detection_patterns:
      - "finalizer|finalizers|metadata\.finalizers"
      - "deletion|delete|remove|block"
      - "controller|operator|reconciler"
      - "foregroundDeletion|backgroundDeletion"
  - pass: >
      "The controller validates that a finalizer was set by an authorized party
      (e.g., only the controller itself or a known set of components) before
      blocking deletion based on its presence. Finalizer removal requires
      authentication as the original setter or an administrator. Stale finalizers
      (orphaned when the original setter is gone) have a timeout or manual
      override mechanism."
    Rationale: "An attacker can add a finalizer to a resource, causing the
      deletion to hang indefinitely (the resource enters Terminating state but
      never completes). If the controller blindly respects all finalizers
      without verifying the setter's identity, the attacker can create a
      denial-of-service on resource cleanup."
  - fail: >
      "Controller does not verify the authority of the finalizer setter before
      honoring it. An attacker can add a finalizer to a resource, blocking
      deletion without authorization. Recommend implementing finalizer
      provenance checks and a stale-finalizer timeout mechanism."
```

## Resolution Path
1. Validate all ownerReference fields (including uid) before acting on ownership
2. Reject cross-namespace ownerReferences explicitly
3. Implement finalizer provenance checking — only honor finalizers from known, authorized setters
4. Add a stale finalizer timeout or manual override for orphaned finalizers
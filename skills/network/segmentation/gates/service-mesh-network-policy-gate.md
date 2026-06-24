# Service Mesh and NetworkPolicy Patterns Gate

## Purpose
Prevents false-positive segmentation alerts when service mesh sidecar proxies and Kubernetes NetworkPolicy rules create cross-namespace traffic that is authorized by the mesh control plane.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Traffic crosses namespace or network segment boundaries
2. Source and destination pods are both part of a service mesh (Istio, Linkerd, Consul Connect, Cilium Mesh)
3. mTLS is enabled between the communicating services as confirmed by mesh telemetry

### Gate Check: Service Mesh Authorization

```yaml
check_service_mesh_authorization:
  - detection_patterns:
      - "istio|linkerd|consul.?connect|cilium.?mesh|kuma|nginx.?mesh"
      - "sidecar|envoy|proxy|data.?plane"
      - "authorization.?policy|authz.?policy|mesh.?policy"
  - pass: "When both pods have sidecar proxies and an AuthorizationPolicy or equivalent allows the detected traffic, downgrade to informational. Rationale: Service mesh enforces intent-based segmentation at L7 with mutual TLS, making raw network-layer alerts redundant for authorized flows."
  - fail: "When one or both pods lack sidecar proxies, or no AuthorizationPolicy matches the traffic, retain original severity. Rationale: Traffic crossing segment boundaries without mesh authorization is a genuine bypass of intended segmentation."
```

### Gate Check: NetworkPolicy Coverage

```yaml
check_network_policy_coverage:
  - detection_patterns:
      - "network.?policy|netpol|k8s.?network"
      - "namespace.*isolation|segment.*policy|micro.?segment"
      - "egress.*policy|ingress.*policy|default.*deny"
  - pass: "When the source namespace has a NetworkPolicy that explicitly allows egress to the destination namespace/port, downgrade severity. Rationale: Kubernetes NetworkPolicy provides explicit intent-based allowlisting at L3/L4, which supersedes generic segmentation rules."
  - fail: "When no NetworkPolicy allows the traffic (default-deny is in effect) or the policy does not cover the detected port/protocol, retain severity. Rationale: Traffic that violates declared NetworkPolicy is a genuine segmentation bypass regardless of mesh presence."
```

## Resolution Path
1. Verify both communicating pods have sidecar proxies injected (kubectl get pods -n ns -o json | jq .items[].metadata.annotations)
2. Check for an AuthorizationPolicy that matches source principal, destination service, and HTTP method/port
3. Validate that a NetworkPolicy in the source namespace allows egress to the destination namespace on the detected port
4. If both mesh and NetworkPolicy authorize the flow, document the exception with references to the mesh and NetPol YAML definitions

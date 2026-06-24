# NAT Egress Attribution Gate

## Purpose
Prevents false-positive firewall review findings when NAT egress traffic is flagged as untraceable to individual sources, but the organization implements VPC flow logs, proxy logs, or cloud NAT audit logging that maps egress traffic to source instances.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Firewall logs show outbound traffic from a NAT gateway IP without source instance attribution
2. VPC flow logs, cloud NAT logs, or proxy logs capture source-destination mappings
3. Log retention supports incident response timelines (90+ days of NAT/proxy logs)

### Gate Check: NAT Gateway Logging

```yaml
check_nat_gateway_logging:
  - detection_patterns:
      - "NAT.*gateway|cloud.*NAT|NAT.*instance|source.*NAT|egress.*NAT"
      - "flow.*log|VPC.*flow.*log|network.*flow|traffic.*flow"
      - "proxy.*log|forward.*proxy|egress.*proxy|transparent.*proxy"
  - pass: "When the NAT gateway has flow logging enabled (AWS VPC Flow Logs for NAT, GCP Cloud NAT logging, Azure NAT gateway flow logs) AND logs are retained for 90+ days, downgrade to informational. Rationale: NAT flow logs with sufficient retention provide source attribution for incident response."
  - fail: "When NAT gateways have no flow logging or retention is less than 30 days, retain severity. Rationale: Untraceable NAT egress traffic prevents source attribution during incident investigation."
```

### Gate Check: Proxy Attribution

```yaml
check_proxy_attribution:
  - detection_patterns:
      - "forward.*proxy|egress.*proxy|web.*proxy|authenticat.*proxy"
      - "proxy.*log|proxy.*audit|proxy.*access|squid|nginx.*proxy"
      - "user.*attribution|source.*attribution|instance.*tag|workload.*id"
  - pass: "When all egress traffic is routed through an authenticated forward proxy that logs source username or instance ID for every request, downgrade severity. Rationale: Authenticated proxy logs provide per-request source attribution that supersedes NAT gateway-level logging."
  - fail: "When egress traffic bypasses the proxy or the proxy does not log authenticated source identity, retain severity. Rationale: Proxy that does not log source identity provides no attribution benefit over unlogged NAT."
```

## Resolution Path
1. Enable VPC flow logs for all NAT gateway subnets with 90-day retention
2. Deploy an authenticated forward proxy for all outbound traffic and log source identity
3. Create a runbook for tracing egress traffic to source using NAT flow logs or proxy logs
4. Test the attribution process quarterly by tracing sample egress flows

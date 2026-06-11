# DNS Privacy and Internal Name Leakage Gate

## Purpose
Prevents false-positive DNS forwarding reviews by ensuring that encrypted upstream DNS (DoT/DoH) is not automatically considered secure without verifying EDNS Client Subnet behavior, split-horizon/internal suffix handling, QNAME minimization, and query log retention/redaction.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. The review approves encrypted DNS forwarding (DoT, DoH, or DNS-over-HTTPS) to a public upstream resolver (e.g., Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9).
2. The configuration forwards both internal and external queries through the same upstream (no explicit split-horizon or private-zone handling).
3. The review report does not record ECS behavior, QNAME minimization status, or private suffix handling.

### When NOT to fire
- The resolver is a dedicated stub/forwarder with explicit private-domain and private-address blocks (e.g., Unbound with `private-domain` and `private-address` directives).
- The upstream resolver is known to strip ECS and the organization has accepted the privacy trade-off in writing.
- All internal queries are handled by a separate resolver or zone that does not reach the public upstream.

---

## Evidence Collection

### Required Checks

**1. EDNS Client Subnet (ECS) Check**
```python
# Example: Check if ECS is enabled in dnsmasq or Unbound
# dnsmasq: check for "add-subnet" directive
# Unbound: check for "edns-subnet-prefix" or "send-client-subnet" directive
# CoreDNS: check "whoami" plugin or "forward" plugin ECS configuration
```
- Record whether ECS is enabled, disabled, or not configured.
- If enabled: record prefix length, approved upstreams, and data-sharing rationale.
- If disabled: note that upstream may still derive location from source IP.

**2. Split-Horizon / Internal Suffix Handling**
```python
# Check for internal/reserved suffix lists
# BIND/Unbound: private-domain, private-address, local-zone
# dnsmasq: local, server=/domain/upstream patterns
# CoreDNS: rewrite, internal zones in Corefile
# Windows AD: conditional forwarders for AD zones
```
- Verify the resolver has explicit handling for: `.local`, `.lan`, `.corp`, `.internal`, `.home.arpa`, `cluster.local`, `.consul`, Active Directory SRV names (`_msdcs.*`, `_ldap._tcp.*`).
- If missing → flag as split-horizon leakage risk.

**3. QNAME Minimization**
- Verify the resolver has QNAME minimization enabled (`qname-minimisation: yes` in Unbound, `--qname-minimisation` in dnsmasq).
- Record the minimization mode (strict vs relaxed).

**4. Private Reverse Lookup Handling**
```python
# Check for RFC 1918 reverse zones
# in-addr.arpa for 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
# ip6.arpa for fe80::/10, fd00::/8 (ULA)
```
- Verify private reverse lookups are NOT forwarded to public resolvers.
- Flag if no private reverse zone or forwarder is configured.

**5. Leak Test Evidence**
- Require runtime leak-test results (e.g., from `dnsleaktest.com`, `ipleak.net`, or custom test).
- Record: which resolver addresses were observed, whether internal names appeared in upstream queries.

**6. Query Log Retention and Redaction**
```python
# Check for logging configuration
# Unbound: log-queries, log-replies, log-servfail
# dnsmasq: log-queries, log-facility
# CoreDNS: log plugin
# rsyslog/syslog-ng forwarding to SIEM
```
- Verify that query logs do not retain raw sensitive qnames (internal hostnames, tokens in hostnames, usernames).
- Check for retention limits, access controls, hashing, or redaction of sensitive qnames and client IPs.
- Flag if full qname logging is enabled without documented retention limits and access controls.

---

## Remediation Guidance

### If ECS is enabled without privacy rationale:
- Disable ECS or restrict to the minimum prefix length needed for CDN geo-routing.
- Document approved upstreams that strip ECS and the accepted data-sharing risk.

### If split-horizon leakage is confirmed:
- Add explicit private-domain/local-zone entries for all internal suffixes.
- Configure conditional forwarding to internal resolvers for AD/Consul/K8s zones.
- Add a runtime leak test to the deployment pipeline.

### If QNAME minimization is missing:
- Enable QNAME minimization (strict mode).
- Test with known privacy-sensitive domains to confirm the resolver behaves correctly.

### If query logs are too permissive:
- Implement redaction of qname subdomains (e.g., strip the first label containing user/token identifiers).
- Set retention limits (e.g., 90 days for security, 7 days for operational).
- Add access controls restricting log access to security operations personnel.

---

## Validation

- [ ] ECS status recorded (enabled/disabled/not configured)
- [ ] Internal suffix handling verified and documented
- [ ] QNAME minimization enabled and confirmed
- [ ] Private reverse lookups do not reach public resolvers
- [ ] Runtime leak test results attached
- [ ] Query log retention and redaction policies documented

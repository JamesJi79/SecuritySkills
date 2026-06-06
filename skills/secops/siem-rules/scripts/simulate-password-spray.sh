#!/usr/bin/env bash
#===============================================================================
# Password Spray Simulation Script
# Part of: SecuritySkills / skills/secops/siem-rules
# Purpose: Generate test events to validate Password Spray detection rules
# Usage:
#   bash scripts/simulate-password-spray.sh
#
# This script generates simulated failed login events for testing.
# It writes sample data to stdout for validation against Sentinel/Splunk rules.
#
# WARNING: Do NOT run against production environments.
#===============================================================================

set -euo pipefail

echo "=== Password Spray Simulation ==="
echo "ATT&CK: T1110.003"
echo "Generating simulated failed login events..."
echo ""

# Simulate password spray attack characteristics:
# - Single source IP targeting multiple accounts
# - Rapid succession of failed logins
# - Supporting details for threshold validation

SOURCE_IPS=("10.0.0.45" "10.0.0.46" "192.168.1.200")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Use a recent timestamp for validation
RECENT_TS=$(date -u -v-5M +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d '5 minutes ago' +"%Y-%m-%dT%H:%M:%SZ")

echo "---"
echo "Event source: Simulation"
echo "Simulation window: 10 minutes"
echo "Distinct accounts targeted: 15"
echo "Source IP: ${SOURCE_IPS[0]}"
echo "Target accounts: user-001 through user-015"
echo "---"
echo ""

# Generate 15 distinct account login attempts (10+ = meets threshold)
for i in $(seq 1 15); do
    ACCOUNT="user-$(printf "%03d" $i)"
    echo "[${RECENT_TS}] FAILED_LOGIN | IP:${SOURCE_IPS[0]} | User:${ACCOUNT}@lab.local | ResultType:50126 | Reason:Invalid password"
done

# Add a few more from different IPs (below threshold per IP)
for i in $(seq 1 3); do
    ACCOUNT="user-$(printf "%03d" $i)"
    echo "[${RECENT_TS}] FAILED_LOGIN | IP:${SOURCE_IPS[1]} | User:${ACCOUNT}@lab.local | ResultType:50126 | Reason:Invalid password"
done

echo ""
echo "=== Expected Detection Results ==="
echo "Source IP ${SOURCE_IPS[0]}: 15 distinct accounts, 15 total attempts"
echo "  -> Exceeds threshold of 10 -> SHOULD TRIGGER ALERT"
echo "Source IP ${SOURCE_IPS[1]}: 3 distinct accounts, 3 total attempts"
echo "  -> Below threshold of 10 -> SHOULD NOT TRIGGER ALERT"
echo "Source IP ${SOURCE_IPS[2]}: 0 distinct accounts"
echo "  -> No activity -> SHOULD NOT TRIGGER ALERT"
echo ""
echo "=== Validation Pass Criteria ==="
echo "1. Query returns 1 result (only ${SOURCE_IPS[0]} exceeds threshold)"
echo "2. Result shows DistinctAccounts = 15, AttemptCount = 15"
echo "3. AttackDuration is <= 10 minutes"
echo "4. No alerts for ${SOURCE_IPS[1]} or ${SOURCE_IPS[2]}"
echo ""
echo "=== Integration with Detection Tools ==="
echo "To run with Atomic Red Team:"
echo "  Invoke-AtomicTest T1110.003 -InputArgs @{'SourceIP' = '${SOURCE_IPS[0]}'}"
echo ""
echo "To validate KQL query in Sentinel:"
echo "  Paste the password spray KQL query into Log Analytics"
echo "  Set time range to 'Last 30 minutes'"
echo "  Confirm at least 1 row returned"
echo ""
echo "=== End of Simulation ==="

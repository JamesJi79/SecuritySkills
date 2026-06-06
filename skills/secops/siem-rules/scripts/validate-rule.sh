#!/usr/bin/env bash
#===============================================================================
# SIEM Rule Validation Script
# Part of: SecuritySkills / skills/secops/siem-rules
# Purpose: Validate KQL and SPL query syntax, run basic sanity checks
# Usage:
#   ./scripts/validate-rule.sh <path-to-query-file>
#   ./scripts/validate-rule.sh --kql "query string"
#   ./scripts/validate-rule.sh --spl "query string"
#   ./scripts/validate-rule.sh --file <path> --lang kql|spl
#
# Requirements:
#   Standard POSIX tools (grep, sed)
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'
PASS=0
FAIL=0
WARN=0

usage() {
    echo "Usage:"
    echo "  $0 <path-to-query-file>               # Auto-detect language"
    echo "  $0 --kql \"query string\"               # Validate KQL query"
    echo "  $0 --spl \"query string\"               # Validate SPL query"
    echo "  $0 --file <path> --lang kql|spl        # Explicit language"
    echo ""
    echo "Checks: syntax, security, performance, best practices"
    exit 1
}

check_result() {
    local check_name="$1"
    local status="$2"
    local message="${3:-}"

    if [ "$status" = "PASS" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $check_name"
        PASS=$((PASS + 1))
    elif [ "$status" = "WARN" ]; then
        echo -e "  ${YELLOW}[WARN]${NC} $check_name: $message"
        WARN=$((WARN + 1))
    else
        echo -e "  ${RED}[FAIL]${NC} $check_name: $message"
        FAIL=$((FAIL + 1))
    fi
}

validate_kql() {
    local query="$1"
    echo "--- KQL Validation ---"

    # Check 1: Has time filter
    if echo "$query" | grep -qiE '(TimeGenerated|Timestamp|TimeCreated)[[:space:]]*(>=?|between|in)'; then
        check_result "Time filter present" "PASS"
    else
        check_result "Time filter missing" "FAIL" "Query must filter by time to avoid scanning entire table"
    fi

    # Check 2: Has 'where' clause
    if echo "$query" | grep -qiE '\|[[:space:]]*where[[:space:]]'; then
        check_result "'where' clause present" "PASS"
    else
        check_result "Missing 'where' clause" "WARN" "Query may need filters to be efficient"
    fi

    # Check 3: Hardcoded private IPs (but not false positives like "10m" time windows)
    # Match complete IP addresses, not partial number patterns
    if echo "$query" | grep -qiE '(^|[^0-9])10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}'; then
        check_result "Hardcoded private IP" "WARN" "Consider using a watchlist instead"
    else
        check_result "No hardcoded private IPs" "PASS"
    fi

    # Check 4: Public IP literals in query body (not comments)
    local body=$(echo "$query" | grep -v '^[[:space:]]*//')
    if echo "$body" | grep -qiE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'; then
        check_result "Contains IP literals" "WARN" "Consider using threat intel or watchlists"
    else
        check_result "No IP literals" "PASS"
    fi

    # Check 5: Uses 'let' statements for thresholds
    if echo "$query" | grep -qiE '^let[[:space:]]+[a-zA-Z_]'; then
        check_result "Uses let statements for thresholds" "PASS"
    else
        check_result "Threshold variables" "WARN" "Consider using 'let' for configurable thresholds"
    fi

    # Check 6: 'summarize' with 'by' clause
    if echo "$query" | grep -qiE '\|[[:space:]]*summarize'; then
        if echo "$query" | grep -qiE 'by[[:space:]]+'; then
            check_result "'summarize' with 'by' clause" "PASS"
        else
            check_result "'summarize' missing 'by' clause" "WARN" "Aggregation without grouping may return single row"
        fi
    fi

    # Check 7: Entity mapping fields
    for entity in "UserPrincipalName" "Account" "IPAddress" "Computer"; do
        if echo "$query" | grep -qiE "$entity"; then
            check_result "Entity field '$entity' found" "PASS"
        fi
    done

    # Check 8: Uses 'project' to limit columns
    if echo "$query" | grep -qiE '\|[[:space:]]*project[[:space:]]'; then
        check_result "Uses 'project' to limit columns" "PASS"
    else
        check_result "Missing 'project'" "WARN" "Add 'project' to limit output columns for performance"
    fi

    # Check 9: ATT&CK reference in comments
    if echo "$query" | grep -qiE '(T[0-9]{4}(\.[0-9]{3})?|ATT.CK)'; then
        check_result "ATT&CK reference in comments" "PASS"
    else
        check_result "ATT&CK reference missing" "WARN" "Add ATT&CK technique ID in query header comment"
    fi
}

validate_spl() {
    local query="$1"
    echo "--- SPL Validation ---"

    # Check 1: Has index specification
    if echo "$query" | grep -qiE 'index[[:space:]]*='; then
        check_result "Index specified" "PASS"
    else
        check_result "Index not specified" "FAIL" "Missing 'index=' will scan all indexes"
    fi

    # Check 2: Has sourcetype or eventcode filter
    if echo "$query" | grep -qiE '(sourcetype|EventCode|source)[[:space:]]*='; then
        check_result "Sourcetype/EventCode filter present" "PASS"
    else
        check_result "Missing sourcetype filter" "FAIL" "Query needs sourcetype or EventCode filter"
    fi

    # Check 3: Time filter
    if echo "$query" | grep -qiE '(earliest|latest|_time)'; then
        check_result "Time filter structure" "PASS"
    else
        check_result "Time filter" "WARN" "Query should use earliest/latest for scheduled searches"
    fi

    # Check 4: Stats with 'by' clause
    if echo "$query" | grep -qiE '[|]?[[:space:]]*stats[[:space:]]'; then
        if echo "$query" | grep -qiE 'stats[[:space:]]+.*\bby\b'; then
            check_result "'stats' with 'by' clause" "PASS"
        else
            check_result "'stats' without 'by'" "WARN" "Unbounded stats may produce unexpected results"
        fi
    fi

    # Check 5: Hardcoded values
    if echo "$query" | grep -qiE '(user[[:space:]]*=[[:space:]]*["'"'"']|username[[:space:]]*=[[:space:]]*["'"'"'])'; then
        check_result "Hardcoded username" "WARN" "Use lookup tables instead of hardcoded usernames"
    else
        check_result "No hardcoded usernames" "PASS"
    fi

    # Check 6: Uses 'table' to limit output
    if echo "$query" | grep -qiE '[|]?[[:space:]]*table[[:space:]]'; then
        check_result "Uses 'table' to format output" "PASS"
    else
        check_result "Missing 'table' command" "WARN" "Add 'table' to limit output fields"
    fi

    # Check 7: Uses 'bin' for time bucketing
    if echo "$query" | grep -qiE '[|]?[[:space:]]*bin[[:space:]]+_time[[:space:]]'; then
        check_result "Time bucketing with 'bin'" "PASS"
    else
        check_result "Missing time bucketing" "WARN" "Use 'bin _time' to bucket events for aggregation"
    fi

    # Check 8: ATT&CK reference
    if echo "$query" | grep -qiE '(T[0-9]{4}(\.[0-9]{3})?|ATT.CK)'; then
        check_result "ATT&CK reference in comments" "PASS"
    else
        check_result "ATT&CK reference missing" "WARN" "Add ATT&CK technique ID in query header comment"
    fi

    # Check 9: Uses eval for computed fields
    if echo "$query" | grep -qiE '[|]?[[:space:]]*eval[[:space:]]'; then
        check_result "Uses 'eval' for computed fields" "PASS"
    else
        check_result "No 'eval' usage" "WARN" "Consider 'eval' for computed fields instead of inline calculations"
    fi
}

# --- Main ---
if [ $# -eq 0 ]; then
    usage
fi

query=""
lang=""

case "${1:-}" in
    --help)
        usage
        ;;
    --kql)
        query="$2"
        lang="kql"
        ;;
    --spl)
        query="$2"
        lang="spl"
        ;;
    --file)
        file="$2"
        lang="${3:-}"
        if [ ! -f "$file" ]; then
            echo "Error: File not found: $file"
            exit 1
        fi
        query=$(cat "$file")
        if [ -z "$lang" ]; then
            if echo "$query" | grep -qiE '^(let[[:space:]]|SigninLogs|SecurityEvent|DeviceProcessEvents)'; then
                lang="kql"
            elif echo "$query" | grep -qiE '^(index=|search[[:space:]]|sourcetype=)'; then
                lang="spl"
            else
                echo "Error: Cannot auto-detect language. Use --lang kql|spl"
                exit 1
            fi
        fi
        ;;
    *)
        if [ -f "$1" ]; then
            file="$1"
            query=$(cat "$file")
            lang="${2:-}"
            if [ -z "$lang" ]; then
                if echo "$query" | grep -qiE '^(let[[:space:]]|SigninLogs|SecurityEvent)'; then
                    lang="kql"
                elif echo "$query" | grep -qiE '^(index=|search[[:space:]])'; then
                    lang="spl"
                else
                    echo "Error: Cannot auto-detect language. Use --kql or --spl"
                    exit 1
                fi
            fi
        else
            usage
        fi
        ;;
esac

echo "=============================================="
echo " SIEM Rule Validation"
echo " Language: $lang"
echo "=============================================="
echo ""

if [ "$lang" = "kql" ]; then
    validate_kql "$query"
elif [ "$lang" = "spl" ]; then
    validate_spl "$query"
else
    echo "Error: Unsupported language '$lang'. Use 'kql' or 'spl'."
    exit 1
fi

echo ""
echo "=============================================="
echo " Results: $PASS passed, $WARN warnings, $FAIL failed"
echo "=============================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0

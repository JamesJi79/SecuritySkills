# Mobile App Crash Forensics Gate

## Purpose
Prevents false-positive forensics findings when mobile app crashes that occur on production devices do not generate sufficient forensic data, but the app implements crash reporting (Crashlytics, Sentry, AppCenter) and client-side logging that captures crash context.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A mobile app crash occurred on a production device without a full memory dump
2. Crash reporting SDK (Firebase Crashlytics, Sentry, AppCenter) is integrated and captures crash traces
3. Client-side breadcrumb logging captures user actions leading to the crash

### Gate Check: Crash Reporter Coverage

```yaml
check_crash_reporter_coverage:
  - detection_patterns:
      - "crash.*report|Crashlytics|Sentry|AppCenter|HockeyApp|Bugsee"
      - "stack.*trace|exception.*log|crash.*log|crash.*dump"
      - "breadcrumb|user.*action|session.*replay|event.*trace"
  - pass: "When the crash reporter captures stack traces, device state, and breadcrumb logs for at least the last 50 user actions, downgrade to informational. Rationale: Crash reporter breadcrumbs and stack traces provide sufficient forensic context for most mobile security investigations."
  - fail: "When no crash reporter is integrated, or crash reports lack stack traces and breadcrumb context, retain severity. Rationale: Unlogged mobile crashes leave no forensic trace for incident response."
```

### Gate Check: Remote Logging

```yaml
check_remote_logging:
  - detection_patterns:
      - "remote.*log|cloud.*log|server.*side.*log|log.*aggregat"
      - "device.*log|application.*log|diagnostic.*log|telemetry"
      - "log.*upload|diagnostic.*upload|crash.*upload|symbolicate"
  - pass: "When crash reports are automatically uploaded and symbolicated (deobfuscated stack traces) in the crash reporting dashboard, downgrade severity. Rationale: Symbolicated crash traces enable root cause analysis without requiring access to the physical device."
  - fail: "When crash reports are stored only on-device or require physical device access to retrieve, retain severity. Rationale: On-device crash data may be lost if the device is reset, wiped, or replaced post-incident."
```

## Resolution Path
1. Integrate a crash reporting SDK (Crashlytics or Sentry) with breadcrumb logging of user actions
2. Enable automatic crash upload with user consent for security incidents
3. Configure symbol upload for deobfuscated stack traces in the crash dashboard
4. Set up crash alerting for security-relevant exception types

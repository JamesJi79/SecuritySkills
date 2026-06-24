# Unmanaged Device Access Gate

## Purpose
Prevents false-positive zero-trust findings when unmanaged devices can access internal applications, but compensating controls (browser isolation, read-only access, session recording, DLP) limit the risk of unmanaged device access.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. Unmanaged devices (BYOD, contractor devices, guest devices) can access internal applications
2. Access is restricted to specific applications that are configured for unmanaged device use
3. Compensating controls (browser isolation, DLP, session recording, read-only mode) are enabled

YAML gate checks would validate that browser isolation or read-only session mode is enforced for unmanaged device access, and that DLP controls prevent data exfiltration from unmanaged sessions.

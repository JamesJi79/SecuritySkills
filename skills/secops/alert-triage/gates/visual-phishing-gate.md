# QR and Visual Phishing Evidence Gate

## Purpose
Prevents false-positive "visual phishing" findings when an alert-triage skill flags QR codes or visual content in emails as phishing indicators without accounting for legitimate use cases (QR codes in marketing emails, legitimate attachments with images, trusted sender visual signatures). The gate provides criteria for distinguishing malicious visual content from benign.

## Detection Logic

### Trigger Conditions
Fire this gate when ALL of the following are true:
1. A finding flags "QR code in email" or "visual phishing attempt" as High/Critical
2. The QR code or visual content is from a known/legitimate sender domain with SPF/DKIM/DMARC pass
3. The content appears in a transactional or expected email context (newsletter, receipt, marketing)

### Gate Check: Legitimate Context Assessment

```yaml
check_legitimate_context:
  - detection_patterns:
      - "QR.*code|visual.*phish|image.*phish|phish.*image"
      - "newsletter|marketing.*email|receipt.*email|transactional.*email"
      - "SPF.*pass|DKIM.*pass|DMARC.*pass|sender.*reput"
  - pass: "Sender has authenticated email (SPF/DKIM/DMARC all pass) AND QR/visual content is in expected context → Downgrade to Low (Observation). Rationale: Legitimate senders use QR codes in marketing. Authentication provides sender accountability."
  - fail: "Unauthenticated sender OR QR content in unexpected context (urgent action requested, credential harvesting lure) → Keep severity. These are common visual phishing indicators."
```

### Gate Check: QR Destination Analysis

```yaml
check_qr_destination:
  - detection_patterns:
      - "QR.*code.*destination|QR.*link|scan.*url|QR.*redirect"
      - "url.*shorten|bit\.ly|tinyurl|redirect.*domain"
  - pass: "QR code links to an expected domain matching the sender's known business domain → Accept. Recommendation: Verify the destination URL matches exactly (not a lookalike domain)."
  - fail: "QR code links to an unknown, lookalike, or recently registered domain → Escalate. QR codes with suspicious destinations are a growing attack vector."
```

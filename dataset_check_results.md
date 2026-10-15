### False-alarm test on the SMS Spam Collection (rules only)

| Group | Messages | Result |
|---|---|---|
| Normal messages (ham) | 4827 | 4797 left alone (99.4%), 29 marked Suspicious (0.6%), 1 marked Likely scam (0.0%) |
| Spam | 747 | 126 flagged (16.9%), 13 as Likely scam (1.7%) |

Rules that fired most often on normal messages:

- urgency: 24
- personal_info_request: 2
- unknown_sender: 2
- too_good_to_be_true: 1
- otp_request: 1


"""Rule checks: look for classic scam red flags in a message using plain Python.

Each flag has a short plain-language label. detect_signals() returns the flags
it found, plus the piece of text (evidence) that triggered each one.

SAFETY: this file only reads text. It never opens or visits a link.
"""

import re

from .extract import extract_facts, get_domain

# What each flag means, in plain language (shown to the user later).
FLAG_LABELS = {
    "urgency": "Pressures you to act fast",
    "fee_request": "Asks you to pay a small fee",
    "suspicious_link": "Contains a link that looks fake or risky",
    "impersonation": "Claims to be someone official or someone you know",
    "account_threat": "Threatens your account or says something is wrong with it",
    "otp_request": "Asks you to hand over a security code",
    "too_good_to_be_true": "Promises money or prizes that sound too good to be true",
    "off_platform_contact": "Tries to move the chat to another app",
    "unknown_sender": "Opens like a message from a stranger",
    "crypto_investment": "Pushes crypto or trading investments",
    "gift_cards": "Asks you to buy gift cards or send codes",
    "secrecy": "Asks you to keep it secret",
    "personal_info_request": "Asks for your card, bank or login details",
    "brand_mismatch": "Says it is from a known company, but the link goes somewhere else",
}

# Text patterns for each flag. (?i) at the start means upper/lower case does not matter.
TEXT_RULES = {
    "urgency": [
        r"(?i)\bwithin \d+\s*(hours?|hrs?|minutes?|mins?|days?)\b",
        r"(?i)\bin the next \d+\s*(hours?|hrs?|minutes?|mins?)\b",
        r"(?i)\b(immediately|urgent(ly)?|right away|act now|asap|last chance|final notice|today only)\b",
        r"(?i)\bavoid (suspension|closure|cancell?ation|deactivation|return(ed)?|being returned|penalt(y|ies)|legal action)\b",
        r"(?i)\bverify now\b",
    ],
    "fee_request": [
        r"(?i)\b(customs|delivery|redelivery|processing|release|handling|clearance)\s+(fee|charge|duty)s?\b",
        r"(?i)\bunpaid\s+(\w+\s+)?(fee|fine|toll|balance)s?\b",
        r"(?i)\bpay\b[^.]{0,40}\b(fee|fine|toll)s?\b",
    ],
    "impersonation": [
        # Message starts with a well-known company name, like "DHL: ..."
        r"(?i)^\s*(dhl|fedex|ups|usps|paypal|amazon|apple|microsoft|netflix|irs|hmrc)\s*[:\-]",
        # "This is Mark from the Fraud Department" / "It's your manager"
        r"(?i)\b(this is|it'?s|i am|i'm)\b[^.!?\n]{0,40}\b(manager|boss|ceo|director|supervisor|"
        r"fraud (department|dept|team)|security (department|dept|team)|support team|"
        r"customer (service|support)|police|officer)\b",
        r"(?i)\b(tax authority|revenue service|tax office|irs|hmrc)\b",
    ],
    "account_threat": [
        r"(?i)\b(account|card|profile|access)\b[^.]{0,40}\b(suspend(ed)?|suspension|locked|disabled|closed|compromised|restricted)\b",
        r"(?i)\b(unusual|suspicious)\b[^.]{0,20}\b(sign-?in|login|activity|transaction)s?\b",
        r"(?i)\bavoid suspension\b",
    ],
    "otp_request": [
        r"(?i)\b(read|send|share|tell|give|forward|provide)\b[^.]{0,30}\b(code|otp|pin|passcode|password)\b",
        r"(?i)\b(code|otp)\b[^.]{0,30}\b(we|i)\s+(just\s+)?sent\b",
    ],
    "too_good_to_be_true": [
        r"(?i)\byou(?:'ve| have)?\s+(won|been selected|been chosen)\b",
        r"(?i)\bcongratulations\b",
        r"(?i)\bearn\s+\$?\d[\d,]*\s*(per|a|/)\s*(day|hour|week)\b",
        r"(?i)\bmade \d+%",
        r"(?i)\bguaranteed (returns?|profit)\b",
        r"(?i)\bno experience (needed|required)\b",
        r"(?i)\beligible for a refund\b",
    ],
    "off_platform_contact": [
        r"(?i)\b(on|via)\s+(telegram|whatsapp|signal|wechat)\b",
        r"(?i)\bt\.me/",
    ],
    "unknown_sender": [
        r"(?i)\bwrong number\b",
        r"(?i)\bfound your (cv|resume|profile|number|email)\b",
        r"(?i)\bi'?m\s+[a-z]+\s+from\b",
    ],
    "crypto_investment": [
        r"(?i)\b(crypto(currency)?|bitcoin|btc|ethereum|forex|trading platform|investment platform|trader)\b",
    ],
    "gift_cards": [
        r"(?i)\b(buy|purchase|get|send|pick up)\b[^.]{0,30}\bgift ?cards?\b",
        r"(?i)\bgift ?card codes?\b",
        r"(?i)\bsend (me )?the codes?\b",
    ],
    "secrecy": [
        r"(?i)\bkeep (this|it) (between us|secret|quiet|confidential)\b",
        r"(?i)\bdon'?t tell (anyone|anybody|your)\b",
        r"(?i)\bbetween us\b",
    ],
    "personal_info_request": [
        r"(?i)\b(confirm|verify|update|enter|provide|send|submit)\b[^.]{0,25}"
        r"\b(bank|card|payment|billing|login|account|identity|personal|passport)\b[^.]{0,15}"
        r"\b(details?|info(rmation)?|number|credentials|password)\b",
        r"(?i)\b(update|confirm|verify)\s+your\s+(personal\s+)?(info(rmation)?|details|address|identity)\b",
    ],
}

# For these flags, "Never share this code" must NOT count as a request.
NEGATION_CHECKED = {"otp_request"}
NEGATION_RE = re.compile(r"(?i)(never|do not|don'?t|not)\s*$")

# --- Link checks -----------------------------------------------------------

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy",
    "is.gd", "goo.gl", "shorturl.at", "ow.ly",
}
RISKY_ENDINGS = (".xyz", ".top", ".click", ".icu", ".buzz", ".tk", ".gq", ".ml", ".cf", ".loan")
SCAM_WORDS = {
    "secure", "verify", "login", "signin", "refund", "claim", "prize", "winner",
    "billing", "update", "account", "support", "redelivery", "parcel", "wallet",
    "confirm", "unlock", "reward", "gov",
}


def link_problems(url, domain):
    """Return a list of plain-language reasons why a link looks risky."""
    reasons = []

    if domain in SHORTENERS:
        reasons.append("is a link shortener that hides the real destination")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        reasons.append("uses a raw IP address instead of a name")
    if "xn--" in domain:
        reasons.append("uses special characters that can imitate a real site")
    if domain.endswith(RISKY_ENDINGS):
        reasons.append("ends in a cheap domain type often used by scammers")

    name_part = domain.rsplit(".", 1)[0]
    words = [w for w in re.split(r"[-.]", name_part) if w in SCAM_WORDS]
    hyphens = domain.count("-")
    if hyphens >= 2:
        reasons.append("has several hyphens, a common trick in fake sites")
    elif hyphens == 1 and words:
        reasons.append("mixes a hyphen with words like '" + words[0] + "'")
    if words and hyphens >= 1:
        reasons.append("contains scam-style words (" + ", ".join(sorted(set(words))) + ")")

    # Plain http:// is only worth mentioning when something else looks off.
    if reasons and url.lower().startswith("http://"):
        reasons.append("does not use HTTPS")

    return reasons


# Companies scammers often pretend to be, and the websites that really belong to them.
BRANDS = {
    "USPS": (r"usps", {"usps.com", "usps.gov"}),
    "DHL": (r"dhl", {"dhl.com", "dhl.de", "dhl.co.uk"}),
    "FedEx": (r"fedex", {"fedex.com"}),
    "UPS": (r"ups", {"ups.com"}),
    "PayPal": (r"paypal", {"paypal.com", "paypal.me"}),
    "Amazon": (r"amazon", {"amazon.com", "amzn.to", "a.co", "amazon.co.uk", "amazon.de",
                           "amazon.ca", "amazon.in", "amazon.com.au", "amazon.sg"}),
    "Apple": (r"apple", {"apple.com", "icloud.com"}),
    "Microsoft": (r"microsoft", {"microsoft.com", "live.com", "office.com", "outlook.com"}),
    "Netflix": (r"netflix", {"netflix.com"}),
    "IRS": (r"irs", {"irs.gov"}),
    "HMRC": (r"hmrc", {"gov.uk"}),
    "Royal Mail": (r"royal mail", {"royalmail.com"}),
}


def brand_mismatch(text, domains):
    """If the message claims to BE a known company but no link goes to that company's
    real website, return a plain-language reason. Otherwise return None.

    "Claims to be" is deliberately narrow ("USPS: ...", "this is DHL", "Amazon security
    alert") so a shop saying "shipped via UPS" with its own tracking link is not flagged.
    """
    if not domains:
        return None
    for name, (pattern, official) in BRANDS.items():
        claim = re.compile(
            rf"(?i)(?:^\s*{pattern}\s*[:\-]"
            rf"|\b(?:this is|from|message from)\s+(?:the\s+)?{pattern}\b"
            rf"|\b{pattern}\s+(?:notice|alert|team|support|customer service|security|billing|account)\b)"
        )
        if not claim.search(text):
            continue
        if any(d == o or d.endswith("." + o) for d in domains for o in official):
            continue
        return f"claims to be {name}, but the link goes to {domains[0]}"
    return None


def _snippet(text, limit=80):
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def detect_signals(text, facts=None):
    """Return a list of red flags found in the message.

    Each item looks like:
      {"flag": "urgency", "label": "Pressures you to act fast", "evidence": "within 24 hours"}
    """
    if facts is None:
        facts = extract_facts(text)

    found = []

    for flag, patterns in TEXT_RULES.items():
        evidence = None
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                if flag in NEGATION_CHECKED:
                    before = text[max(0, match.start() - 20): match.start()]
                    if NEGATION_RE.search(before):
                        continue
                evidence = match.group(0)
                break
            if evidence:
                break
        if evidence:
            found.append({"flag": flag, "label": FLAG_LABELS[flag], "evidence": _snippet(evidence)})

    # Link check: look at each domain found in the message.
    for url, domain in zip(facts["urls"], [get_domain(u) for u in facts["urls"]]):
        reasons = link_problems(url, domain)
        if reasons:
            found.append({
                "flag": "suspicious_link",
                "label": FLAG_LABELS["suspicious_link"],
                "evidence": domain + " " + "; ".join(reasons[:2]),
            })
            break  # one link warning is enough for now

    mismatch = brand_mismatch(text, facts["domains"])
    if mismatch:
        found.append({
            "flag": "brand_mismatch",
            "label": FLAG_LABELS["brand_mismatch"],
            "evidence": _snippet(mismatch),
        })

    return found
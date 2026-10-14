"""Build a ready-to-send "report this scam" message from a check result.

Links and website names are made harmless (hxxp://, example[.]com) so nobody
clicks them by accident when the text is pasted into an email or chat.
No AI call is needed, so this costs nothing.
"""

import re
import textwrap


def defang(text, domains=()):
    """Make links harmless: http -> hxxp and dots in known websites -> [.]"""
    text = re.sub(r"(?i)\bhttp(s?)://", lambda m: "hxxp" + m.group(1) + "://", str(text))
    for domain in sorted(domains, key=len, reverse=True):
        pattern = r"(?<![\w.-])" + re.escape(domain) + r"(?![\w-])"
        text = re.sub(pattern, domain.replace(".", "[.]"), text, flags=re.IGNORECASE)
    return text


def build_report(result):
    """Return the report text, or None when the message looked safe."""
    if result["verdict"] == "Probably safe":
        return None

    facts = result["facts"]
    domains = facts["domains"]

    if result["ai_used"] and result["red_flags"]:
        reasons = [flag["title"] for flag in result["red_flags"]]
    else:
        reasons = [s["label"] for s in result["signals"]]
    reasons = [defang(r, domains) for r in reasons[:5]] or ["It looks like a scam"]

    lines = [
        "Subject: Suspected scam message",
        "",
        "Hello,",
        "",
        "I received a message that I believe is a scam, and I am reporting it",
        "so it can be investigated.",
        "",
        "Why I think it is a scam:",
    ]
    lines += [f"- {reason}" for reason in reasons]

    details = [f"- Website: {d.replace('.', '[.]')}" for d in domains]
    details += [f"- Phone number: {p}" for p in facts["phones"]]
    details += [f"- Handle: {h}" for h in facts["handles"]]
    if details:
        lines += ["", "Details from the message:"] + details

    wrapped = []
    for paragraph in defang(result["message"], domains).splitlines():
        wrapped += textwrap.wrap(paragraph, 72, break_long_words=False, break_on_hyphens=False) or [""]
    lines += ["", "The message I received (links made harmless):", '"""']
    lines += wrapped
    lines += ['"""', "", "Please look into it and block the sender if you can.", "", "Thank you."]
    return "\n".join(lines)
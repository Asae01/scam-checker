"""The pipeline: runs every step in order and returns one result for the screen.

Steps: extract facts -> rule checks -> (later: Tavily search) -> AI judgement.
If the AI step is not set up or fails, the rule-based answer is still returned,
so the app never shows an empty screen.
"""

from .extract import extract_facts
from .llm import NOT_CONFIGURED, ask_model
from .signals import detect_signals

LEVELS = ["Probably safe", "Suspicious", "Likely scam"]

# Protects your credits and keeps prompts small: longer messages are cut off.
MAX_CHARS = 2000

# How much each red flag adds to the risk score.
FLAG_WEIGHTS = {
    "otp_request": 3,
    "gift_cards": 3,
    "suspicious_link": 2,
    "personal_info_request": 2,
    "fee_request": 2,
    "secrecy": 2,
    "too_good_to_be_true": 2,
    "account_threat": 1,
    "urgency": 1,
    "impersonation": 1,
    "off_platform_contact": 1,
    "unknown_sender": 1,
    "crypto_investment": 1,
}

NEXT_STEPS = {
    "Likely scam": [
        "Do not click any links or reply to the message.",
        "Never share codes, passwords or card details with the sender.",
        "Block the sender and report the message to the app or your bank.",
        "If you already shared details or paid, contact your bank right away.",
    ],
    "Suspicious": [
        "Do not click links in the message.",
        "Contact the company through its official website or a phone number you already trust.",
        "If it claims to be someone you know, call them on a number you already have.",
    ],
    "Probably safe": [
        "Our checks found no common scam red flags, but no check is perfect.",
        "If something still feels off, contact the sender through a number or app you already trust.",
    ],
}


def rule_verdict(signals):
    """Turn the list of red flags into a score and a verdict label."""
    score = sum(FLAG_WEIGHTS.get(s["flag"], 1) for s in signals)
    if score >= 3:
        return score, "Likely scam"
    if score >= 1:
        return score, "Suspicious"
    return score, "Probably safe"


def analyze(message, use_ai=True, client=None):
    """Check a message and return everything the screen needs to show."""
    message = (message or "").strip()
    if not message:
        raise ValueError("Please paste a message to check.")

    was_truncated = len(message) > MAX_CHARS
    message = message[:MAX_CHARS]

    # Step 1: pull out links, phones, handles.
    facts = extract_facts(message)

    # Step 2: rule checks.
    signals = detect_signals(message, facts)
    score, verdict = rule_verdict(signals)

    # Step 3 (later): search the web with Tavily for the links and names found.

    # Step 4: ask the AI model to judge everything together.
    ai, ai_error = (None, None)
    if use_ai:
        ai, ai_error = ask_model(message, facts, signals, client=client)

    summary = None
    confidence = None
    red_flags = []
    next_steps = NEXT_STEPS[verdict]
    guard_note = None
    source = "rules only"

    if ai:
        source = "AI (Nemotron on Nebius) + rule checks"
        verdict = ai["verdict"]
        confidence = ai["confidence"]
        summary = ai["summary"]
        red_flags = ai["red_flags"]
        next_steps = ai["next_steps"] or NEXT_STEPS[verdict]

        # Safety net: the AI can be fooled by a clever message. If the rule checks
        # found strong red flags, never let the verdict drop to "Probably safe".
        if score >= 3 and LEVELS.index(verdict) < 1:
            verdict = "Suspicious"
            next_steps = NEXT_STEPS[verdict]
            guard_note = "The rule checks found strong warning signs, so we raised the caution level."

    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
        "red_flags": red_flags,
        "risk_score": score,
        "signals": signals,
        "facts": facts,
        "next_steps": next_steps,
        "was_truncated": was_truncated,
        "source": source,
        "ai_used": ai is not None,
        "ai_error": None if ai_error == NOT_CONFIGURED else ai_error,
        "guard_note": guard_note,
    }
"""The pipeline: runs every step in order and returns one result for the screen.

Steps: extract facts -> rule checks -> website age + Tavily web lookup -> AI judgement.
If the AI step is not set up or fails, the rule-based answer is still returned,
so the app never shows an empty screen.
"""

import time
from concurrent.futures import ThreadPoolExecutor

from .domainage import domain_age_signals
from .extract import extract_facts
from .llm import NOT_CONFIGURED, ask_model
from .sanitize import clean_message
from .search import search_entities
from .signals import FLAG_LABELS, detect_signals

LEVELS = ["Probably safe", "Suspicious", "Likely scam"]

# Protects your credits and keeps prompts small: longer messages are cut off.
MAX_CHARS = 2000

# How much each red flag adds to the risk score.
FLAG_WEIGHTS = {
    "otp_request": 3,
    "gift_cards": 3,
    "brand_mismatch": 3,
    "new_domain": 2,
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
    "hidden_characters": 1,
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


def analyze(message, use_ai=True, client=None, use_search=None, search_client=None,
            use_domain_age=None, age_opener=None):
    """Check a message and return everything the screen needs to show."""
    started = time.perf_counter()
    original = str(message or "").strip()
    if not original:
        raise ValueError("Please paste a message to check.")

    was_truncated = len(original) > MAX_CHARS

    # Step 0: clean the text (hidden characters, look-alike letters, card numbers).
    message, privacy = clean_message(original[:MAX_CHARS])
    if not message:
        raise ValueError("Please paste a message to check.")

    # Step 1: pull out links, phones, handles.
    facts = extract_facts(message)

    # Step 2: rule checks.
    signals = detect_signals(message, facts)
    hidden = privacy["hidden_chars"] + privacy["bidi_controls"]
    if privacy["bidi_controls"] or privacy["hidden_chars"] >= 3:
        signals.append({
            "flag": "hidden_characters",
            "label": FLAG_LABELS["hidden_characters"],
            "evidence": f"{hidden} hidden characters removed",
            "span": None,
        })

    # Step 3: network lookups, run side by side: web search (Tavily) and website age (RDAP).
    if use_search is None:
        use_search = use_ai
    if use_domain_age is None:
        use_domain_age = use_ai
    search_results, search_error, domain_ages = [], None, []
    lookups_started = time.perf_counter()
    if use_search or use_domain_age:
        with ThreadPoolExecutor(max_workers=2) as pool:
            search_job = pool.submit(search_entities, facts, client=search_client) if use_search else None
            age_job = (
                pool.submit(domain_age_signals, facts, message, opener=age_opener)
                if use_domain_age else None
            )
            if search_job:
                search_results, search_error = search_job.result()
            if age_job:
                age_signals, domain_ages = age_job.result()
                signals = signals + age_signals

    score, verdict = rule_verdict(signals)
    lookups_seconds = time.perf_counter() - lookups_started

    # Step 4: ask the AI model to judge everything together.
    ai, ai_error = (None, None)
    ai_started = time.perf_counter()
    if use_ai:
        ai, ai_error = ask_model(
            message, facts, signals, search_results=search_results[:6], client=client
        )
    ai_seconds = time.perf_counter() - ai_started

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

    if search_results:
        source += " + web search (Tavily)"

    return {
        "message": message,
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
        "domain_ages": domain_ages,
        "search_results": search_results,
        "search_error": None if search_error == NOT_CONFIGURED else search_error,
        "privacy": privacy,
        "timing": {
            "lookups": round(lookups_seconds, 2),
            "ai": round(ai_seconds, 2),
            "total": round(time.perf_counter() - started, 2),
        },
    }
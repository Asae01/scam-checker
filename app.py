"""Scam Message Checker: the screen people see.

Run it with:  streamlit run app.py
"""

import html
import json
import logging
import re
from pathlib import Path

import streamlit as st

from scamcheck.domainage import registrable
from scamcheck.highlight import highlight_html
from scamcheck.limits import DailyLimit
from scamcheck.pipeline import MAX_CHARS, analyze
from scamcheck.report import build_report, defang

log = logging.getLogger("scam-checker")

st.set_page_config(
    page_title="Scam Message Checker",
    page_icon="🛡️",
    layout="wide",
    menu_items={
        "About": "Paste a suspicious message to see what looks like a scam and what to do next. "
                 "Built for the Nebius x NVIDIA Global AI Hackathon.",
        "Report a bug": "https://github.com/Asae01/scam-checker/issues",
    },
)

MAX_CHECKS_PER_SESSION = 20  # AI checks per visitor session
MAX_AI_CHECKS_PER_DAY = 150  # AI checks per day across all visitors
SOURCE_URL = "https://github.com/Asae01/scam-checker"

# Icons are fixed, trusted drawings written here (never built from user text).
# No xmlns attribute is needed for inline SVG, and none may contain "http://".
_SVG = ('<svg width="28" height="28" viewBox="0 0 28 28" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" '
        'focusable="false">')
ICON_SHIELD = _SVG + '<path d="M14 3 24 7v7c0 5-5 9-10 12C9 23 4 19 4 14V7Z"/><path d="m9 14 3 3 7-7"/></svg>'
ICON_SCAM = _SVG + '<circle cx="14" cy="14" r="11"/><path d="m10 10 8 8m0-8-8 8"/></svg>'
ICON_SUSPICIOUS = (_SVG + '<path d="M14 3 26 24H2Z"/><path d="M14 10v6"/>'
                   '<circle cx="14" cy="20" r="0.75" fill="currentColor"/></svg>')
ICON_SAFE = _SVG + '<circle cx="14" cy="14" r="11"/><path d="m8 14 4 4 8-8"/></svg>'

STYLE = """
<style>
:root {
  --canvas: #e3e3e3; --card: #ffffff; --ink: #1d1f21; --lime: #d7f26b;
  --lavender: #b9aaf5; --lavender-soft: #ece8fd; --muted: #565a61; --line: #d3d3d3;
  --danger: #ff6a5b; --warn: #ffbe3d; --on-dark: #d9dce1;
}
[data-testid="stAppViewContainer"], [data-testid="stHeader"] { background: var(--canvas); }
[data-testid="stAppViewContainer"] {
  color: var(--ink);
  font-family: "Plus Jakarta Sans", "Manrope", "Segoe UI", system-ui, -apple-system, sans-serif;
  font-size: 16px;
  line-height: 1.5;
}
[data-testid="stMainBlockContainer"] { max-width: 1240px; padding-top: 2.5rem; padding-bottom: 2rem; }
[data-testid="stColumn"] :is([data-testid="stVerticalBlock"], [data-testid="stElementContainer"]) { min-width: 0; }
[data-testid="stColumn"] :is([data-testid="stTextArea"], [data-testid="stCode"]) { max-width: 100%; }

[data-testid="stAppViewContainer"] h1 {
  color: var(--ink); font-size: clamp(2.1rem, 5.5vw, 3.2rem); font-weight: 800;
  letter-spacing: -0.03em; line-height: 1.1; overflow-wrap: anywhere;
}
[data-testid="stAppViewContainer"] h2 { color: var(--ink); font-weight: 800; letter-spacing: -0.02em; }
[data-testid="stAppViewContainer"] [data-testid="stMainBlockContainer"] h3 {
  color: var(--ink); font-size: 1.35rem; font-weight: 800; letter-spacing: -0.01em;
  margin: 1.25rem 0 0.5rem; padding: 0;
}
[data-testid="stMarkdownContainer"] p, [data-testid="stWidgetLabel"] p { font-size: 1rem; line-height: 1.5; }
.icon-heading { display: flex; align-items: center; gap: 1rem; }
.icon-heading > svg { flex: 0 0 auto; }
.icon-heading > span { min-width: 0; overflow-wrap: anywhere; }

/* ---------- hero ---------- */
.hero { position: relative; isolation: isolate; overflow: hidden; background: var(--ink);
  color: var(--card); border-radius: 28px; padding: 2rem; margin-bottom: 1.5rem; }
.hero h1.icon-heading { color: var(--card); margin: 0 0 0.5rem; padding: 0; }
.hero .icon-heading > svg { width: 2.75rem; height: 2.75rem; color: var(--lime); }
.hero .accent { color: var(--lime); }
.hero-tag { color: var(--on-dark); max-width: 40rem; margin: 0 0 1.25rem; font-size: 1.05rem; }
.hero-chips { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.chip { border: 1px solid rgba(255, 255, 255, 0.4); border-radius: 999px; padding: 0.4rem 0.9rem;
  font-size: 0.875rem; font-weight: 700; color: var(--card); }
.chip.lime { background: var(--lime); border-color: var(--lime); color: var(--ink); }
.chip.lav { background: var(--lavender); border-color: var(--lavender); color: var(--ink); }
.hero-orbs { position: absolute; z-index: -1; top: -2.5rem; right: -2rem; display: flex; pointer-events: none; }
.hero-orbs span { display: block; border-radius: 50%; }
.hero-orbs .o1 { width: 11rem; height: 11rem; background: var(--lavender); }
.hero-orbs .o2 { width: 8rem; height: 8rem; background: var(--lime); margin: 5rem 0 0 -3.5rem; }
@media (max-width: 1000px) { .hero-orbs { display: none; } }

/* ---------- empty state ---------- */
.empty-state { background: var(--ink); color: var(--card); border-radius: 28px; padding: 2rem 1.5rem;
  min-height: 24rem; display: flex; flex-direction: column; align-items: center;
  justify-content: center; text-align: center; overflow-wrap: anywhere; }
.empty-state h2 { color: var(--card); font-size: clamp(1.5rem, 3vw, 2rem); line-height: 1.2; margin: 0; padding: 0; }
.empty-state p { color: var(--on-dark); margin: 1rem 0 0; }
.empty-state-art { display: flex; justify-content: center; padding: 0 0 2rem; }
.empty-state-circle { width: clamp(3.5rem, 8vw, 5.5rem); aspect-ratio: 1; border-radius: 50%; }
.empty-state-circle + .empty-state-circle { margin-left: -1.5rem; }
.empty-state-circle.lavender { background: var(--lavender); }
.empty-state-circle.lime { background: var(--lime); }
.empty-state-circle.white { background: var(--card); }

/* ---------- input card and example pills ---------- */
[data-testid="stElementContainer"]:has(.input-card-marker),
[data-testid="stElementContainer"]:has(.example-pills-marker) { display: none; }
[data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"] .input-card-marker) {
  background: var(--card); border: 0; border-radius: 28px; padding: 1.5rem;
}
[data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"] .example-pills-marker) {
  flex-direction: row; flex-wrap: wrap; gap: 0.5rem;
}
[data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"] .example-pills-marker) > [data-testid="stElementContainer"] {
  width: auto; max-width: 100%; flex: 0 1 auto;
}
[data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"] .example-pills-marker) button {
  background: var(--lavender-soft); color: var(--ink); border-color: var(--lavender-soft); padding-inline: 1rem;
}
[data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"] .example-pills-marker) button:hover {
  background: var(--lavender); border-color: var(--lavender);
}
[data-testid="stTextAreaRootElement"] { background: var(--card); border: 1px solid var(--line); border-radius: 20px; }
[data-testid="stTextArea"] textarea {
  background: var(--card); color: var(--ink); font-size: 1rem; line-height: 1.5; border-radius: 20px;
}
[data-testid="stTextArea"] textarea::placeholder { color: var(--muted); opacity: 1; }
[role="option"] { min-height: 44px; }
[data-testid="stButton"] button {
  background: var(--card); color: var(--ink); border: 1px solid var(--line); border-radius: 999px;
  min-height: 48px; padding: 0.5rem 1.5rem; font-weight: 700;
}
[data-testid="stButton"] button:hover { background: var(--lavender-soft); color: var(--ink); }
[data-testid="stButton"] [data-testid="stBaseButton-primary"] {
  background: var(--ink); color: var(--card); border-color: var(--ink);
}
[data-testid="stButton"] [data-testid="stBaseButton-primary"]:hover {
  background: var(--lime); color: var(--ink); border-color: var(--lime);
}
[data-testid="stAppViewContainer"] :is(button, a, input, textarea, select, [tabindex]):focus-visible {
  outline: 2px solid var(--ink); outline-offset: 3px;
}

/* ---------- verdict card ---------- */
.verdict-card { --accent: var(--danger); position: relative; isolation: isolate; overflow: hidden;
  border-radius: 28px; padding: 1.5rem; background: var(--ink); color: var(--card);
  margin-bottom: 0.5rem; overflow-wrap: anywhere; }
.verdict-card.v-sus { --accent: var(--warn); }
.verdict-card.v-safe { --accent: var(--lavender); background: var(--lime); color: var(--ink); }
.verdict-orbit { position: absolute; z-index: -1; top: -4rem; right: -3rem; width: 13rem; height: 13rem;
  border: 2rem solid var(--accent); border-radius: 50%; opacity: 0.16; }
.verdict-orbit::after { content: ""; position: absolute; inset: 1.5rem -4rem -1.5rem 4rem;
  border: 1px solid var(--accent); border-radius: 50%; }
.verdict-eyebrow { font-size: 0.875rem; font-weight: 700; margin-bottom: 0.5rem; }
.verdict-card h2.icon-heading { color: inherit; font-size: 2.1rem; font-weight: 800; margin: 0 0 0.75rem; padding: 0; }
.verdict-card .icon-heading > svg { width: 2.25rem; height: 2.25rem; }
.verdict-card .verdict-text { color: inherit; margin: 0 0 1rem; font-size: 1.05rem; line-height: 1.5; }
.verdict-badges { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.verdict-badge { border: 1px solid currentColor; border-radius: 999px; padding: 0.4rem 0.75rem;
  font-size: 0.875rem; line-height: 1.5; max-width: 100%; }
.verdict-badge.risk { background: var(--accent); color: var(--ink); border-color: var(--accent); font-weight: 700; }

/* ---------- steps, tabs, small parts ---------- */
.steps-card { background: var(--card); color: var(--ink); border-radius: 28px; padding: 1.5rem; }
.steps-card ol { list-style: none; counter-reset: steps; margin: 0; padding: 0; }
.steps-card li { counter-increment: steps; display: grid; grid-template-columns: 2rem minmax(0, 1fr);
  align-items: start; gap: 1rem; margin-bottom: 1rem; overflow-wrap: anywhere; }
.steps-card li:last-child { margin-bottom: 0; }
.steps-card li::before { content: counter(steps); display: grid; place-items: center; width: 2rem;
  height: 2rem; border-radius: 50%; background: var(--lime); color: var(--ink); font-weight: 800; }
[data-testid="stTabs"] { margin-top: 1.5rem; }
[data-testid="stTabs"] [role="tablist"] { flex-wrap: wrap; gap: 0.25rem; overflow: visible; width: fit-content;
  max-width: 100%; background: var(--card); border-radius: 999px; padding: 0.35rem;
  box-shadow: 0 6px 20px rgba(29, 31, 33, 0.07); }
[data-testid="stTabs"] [role="tab"] { background: transparent; color: var(--ink); border-radius: 999px;
  padding: 0.5rem 1.1rem; min-height: 44px; height: auto; white-space: normal; font-weight: 700; }
[data-testid="stTabs"] [role="tab"] p::before { content: ""; display: inline-block; width: 0.5rem; height: 0.5rem;
  border-radius: 50%; background: var(--lavender); margin-right: 0.55rem; vertical-align: middle; }
[data-testid="stTabs"] [role="tab"]:hover { background: var(--lavender-soft); }
[data-testid="stTabs"] [role="tab"][aria-selected="true"] { background: var(--ink); color: var(--card); }
[data-testid="stTabs"] [role="tab"][aria-selected="true"] p::before { background: var(--lime); }
[data-testid="stTabs"] [role="tablist"]::after,
[data-testid="stTab"] .react-aria-SelectionIndicator { display: none; }
[data-testid="stTabPanel"] { background: var(--card); color: var(--ink); border-radius: 28px; padding: 1.5rem;
  margin-top: 1rem; min-width: 0; overflow-wrap: anywhere; }
[data-testid="stExpander"] details, [data-testid="stAlertContainer"], [data-testid="stAlert"],
[data-testid="stCode"], [data-testid="stCode"] pre { border-radius: 20px; }
[data-testid="stExpander"] summary { min-height: 44px; }
[data-testid="stCode"] button { min-width: 44px; min-height: 44px; }
[data-testid="stCaptionContainer"] { color: var(--muted); }
[data-testid="stDivider"] hr { border-color: var(--line); }

/* ---------- how it works ---------- */
.how-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: 1rem; margin: 1.5rem 0 1rem; }
.how-card { border-radius: 28px; padding: 1.5rem; }
.how-card.lime { background: var(--lime); color: var(--ink); }
.how-card.lav { background: var(--lavender); color: var(--ink); }
.how-card.ink { background: var(--ink); color: var(--card); }
.how-num { display: inline-grid; place-items: center; width: 2rem; height: 2rem; border-radius: 50%;
  background: var(--ink); color: var(--card); font-weight: 800; margin-bottom: 0.75rem; }
.how-card.ink .how-num { background: var(--lime); color: var(--ink); }
.how-title { font-size: 1.2rem; font-weight: 800; letter-spacing: -0.01em; margin-bottom: 0.25rem; }
.how-text { margin: 0; color: inherit; }

/* ---------- motion (CSS only; switched off for people who ask for reduced motion) ---------- */
@keyframes rise { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }
@keyframes fade { from { opacity: 0; } to { opacity: 1; } }
@keyframes pop { 0% { opacity: 0; transform: scale(0.4); } 60% { opacity: 1; transform: scale(1.18); } 100% { transform: scale(1); } }
@keyframes bounce { 0%, 80%, 100% { transform: translateY(0) scale(1); } 40% { transform: translateY(-0.6rem) scale(1.12); } }
@keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-0.7rem); } }
@keyframes orbit { to { transform: rotate(360deg); } }

.hero { animation: rise 0.6s cubic-bezier(0.2, 0.8, 0.2, 1) both; }
.hero-orbs .o1 { animation: float 7s ease-in-out infinite; }
.hero-orbs .o2 { animation: float 9s ease-in-out infinite reverse; }
.empty-state { animation: fade 0.5s ease both; }
.empty-state-circle { animation: float 4.5s ease-in-out infinite; }
.empty-state-circle.lime { animation-delay: 0.5s; }
.empty-state-circle.white { animation-delay: 1s; }

.loader { display: flex; align-items: center; gap: 1rem; width: fit-content; max-width: 100%; background: var(--card);
  border-radius: 999px; padding: 0.9rem 1.5rem; box-shadow: 0 8px 24px rgba(29, 31, 33, 0.1);
  animation: rise 0.3s ease both; }
.loader-dots { display: flex; gap: 0.45rem; }
.loader-dots span { width: 0.85rem; height: 0.85rem; border-radius: 50%; animation: bounce 1s ease-in-out infinite; }
.loader-dots .d1 { background: var(--lavender); }
.loader-dots .d2 { background: var(--lime); animation-delay: 0.15s; }
.loader-dots .d3 { background: var(--ink); animation-delay: 0.3s; }
.loader-text { font-weight: 700; }

.verdict-card { animation: rise 0.5s cubic-bezier(0.2, 0.8, 0.2, 1) both; }
.verdict-card .icon-heading > svg { animation: pop 0.55s cubic-bezier(0.2, 0.8, 0.2, 1) 0.25s both; }
.verdict-orbit { animation: orbit 30s linear infinite; }
.verdict-badge { animation: rise 0.4s ease both; }
.verdict-badge:nth-child(2) { animation-delay: 0.1s; }
.verdict-badge:nth-child(3) { animation-delay: 0.2s; }
.steps-card { margin-bottom: 0.5rem; animation: rise 0.5s cubic-bezier(0.2, 0.8, 0.2, 1) 0.12s both; }
.steps-card li { animation: rise 0.4s ease both; }
.steps-card li:nth-child(1) { animation-delay: 0.25s; }
.steps-card li:nth-child(2) { animation-delay: 0.35s; }
.steps-card li:nth-child(3) { animation-delay: 0.45s; }
.steps-card li:nth-child(4) { animation-delay: 0.55s; }
.steps-card li:nth-child(n+5) { animation-delay: 0.65s; }
[data-testid="stTabs"] { animation: rise 0.5s cubic-bezier(0.2, 0.8, 0.2, 1) 0.3s both; }
[data-testid="stTabPanel"] { margin-top: 1.25rem; box-shadow: 0 10px 28px rgba(29, 31, 33, 0.07); animation: fade 0.35s ease both; }

[data-testid="stButton"] button { transition: background-color 0.18s ease, color 0.18s ease, border-color 0.18s ease,
  transform 0.18s ease, box-shadow 0.18s ease; }
[data-testid="stButton"] button:hover { transform: translateY(-2px); box-shadow: 0 8px 18px rgba(29, 31, 33, 0.14); }
[data-testid="stButton"] button:active { transform: translateY(0) scale(0.97); box-shadow: none; }
[data-testid="stTextAreaRootElement"] { transition: border-color 0.2s ease, box-shadow 0.2s ease; }
[data-testid="stTextAreaRootElement"]:focus-within { border-color: var(--ink); box-shadow: 0 0 0 3px var(--lavender); }
[data-testid="stTabs"] [role="tab"] { transition: background-color 0.2s ease, color 0.2s ease, transform 0.15s ease; }
[data-testid="stTabs"] [role="tab"]:active { transform: scale(0.96); }
[data-testid="stTabs"] [role="tab"] p::before { transition: background-color 0.2s ease; }
[data-testid="stExpander"] summary { transition: background-color 0.2s ease; }
[data-testid="stExpander"] summary:hover { background: var(--lavender-soft); }
.how-card { transition: transform 0.2s ease, box-shadow 0.2s ease; }
.how-card:hover { transform: translateY(-4px); box-shadow: 0 14px 30px rgba(29, 31, 33, 0.14); }

@media (max-width: 480px) {
  [data-testid="stMainBlockContainer"] { padding: 1.5rem 1rem; }
  .hero { padding: 1.5rem 1.25rem; }
  [data-testid="stTabPanel"], .verdict-card, .steps-card, .empty-state, .how-card,
  [data-testid="stVerticalBlock"]:has(> [data-testid="stElementContainer"] .input-card-marker) { padding: 1.25rem; }
  [data-testid="stButton"] button { width: 100%; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: 0.01ms !important; animation-iteration-count: 1 !important;
    animation-delay: 0s !important; transition-duration: 0.01ms !important; scroll-behavior: auto !important; }
}
</style>
"""

HERO = (
    '<div class="hero"><span class="hero-orbs" aria-hidden="true"><span class="o1"></span><span class="o2"></span></span>'
    f'<h1 class="icon-heading">{ICON_SHIELD}<span>Scam Message <span class="accent">Checker</span></span></h1>'
    '<p class="hero-tag">Got a message that feels off? Paste it below for a quick check: what looks '
    'suspicious, and what to do next.</p>'
    '<div class="hero-chips"><span class="chip lime">Rules + AI</span><span class="chip lav">Live web lookups</span>'
    '<span class="chip">Never opens links</span></div></div>'
)

EMPTY_STATE = (
    '<div class="empty-state"><div class="empty-state-art" aria-hidden="true">'
    '<span class="empty-state-circle lavender"></span><span class="empty-state-circle lime"></span>'
    '<span class="empty-state-circle white"></span></div>'
    '<h2>Your result appears here</h2>'
    '<p>Paste a message and press Check message to see its warning signs and your next steps.</p></div>'
)

LOADER = (
    '<div class="loader" role="status" aria-live="polite"><span class="loader-dots" aria-hidden="true">'
    '<span class="d1"></span><span class="d2"></span><span class="d3"></span></span>'
    '<span class="loader-text">Checking the message...</span></div>'
)

HOW_IT_WORKS = (
    '<div class="how-grid">'
    '<div class="how-card lime"><div class="how-num">1</div><div class="how-title">Spot</div>'
    '<p class="how-text">We pick out links, phone numbers and handles. We never open them.</p></div>'
    '<div class="how-card lav"><div class="how-num">2</div><div class="how-title">Check</div>'
    '<p class="how-text">Rule checks look for classic scam signs, and we see how new each website is.</p></div>'
    '<div class="how-card ink"><div class="how-num">3</div><div class="how-title">Explain</div>'
    '<p class="how-text">An AI model (NVIDIA Nemotron on Nebius) reads everything and tells you what to do.</p></div>'
    '</div>'
)

# css class, icon, risk label, default sentence. The icon and the words carry the meaning, not just colour.
VERDICTS = {
    "Likely scam": ("v-scam", ICON_SCAM, "High risk",
                    "This message has several signs of a scam. Do not click links, reply, or send anything."),
    "Suspicious": ("v-sus", ICON_SUSPICIOUS, "Use caution",
                   "Some things look off. Check before you click, reply, or pay."),
    "Probably safe": ("v-safe", ICON_SAFE, "Low risk",
                      "We found no common scam signs. No check is perfect, so stay careful."),
}

QUICK_EXAMPLES = [
    ("Delivery fee", "scam_01_delivery_fee"),
    ("Code request", "scam_03_otp_request"),
    ("Friend chat", "safe_03_friend_dinner"),
    ("Real login code", "safe_04_real_otp"),
]


@st.cache_data
def load_examples():
    """Read the sample messages so people can try the app in one click."""
    path = Path(__file__).parent / "samples" / "messages.json"
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return {item["id"]: item["text"] for item in json.load(f)}


@st.cache_resource
def get_daily_limit():
    return DailyLimit(MAX_AI_CHECKS_PER_DAY)


EXAMPLES = load_examples()


def use_example(example_id):
    st.session_state.message = EXAMPLES[example_id]


def clear_all():
    st.session_state.message = ""
    st.session_state.pop("result", None)
    st.session_state.pop("checked_input", None)


def code_safe(text):
    """Show text as code so it can never become a clickable link."""
    return "`" + str(text).replace("`", "'") + "`"


def plain(text):
    """Make AI-written text safe for markdown: no clickable links, no markup tricks."""
    text = re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1://", str(text))
    text = re.sub(r"(?i)\bwww\.", "www[.]", text)
    return re.sub(r"([\\`*_\[\]()<>#~|])", r"\\\1", text)


def safe_html(text, domains=()):
    """Make untrusted text safe for our own HTML: links defanged, everything escaped."""
    return html.escape(defang(text, domains), quote=True)


def run_check(message):
    """Run one check and remember the result. Never shows technical details to the visitor."""
    # AI and web lookups cost credits, so they have limits. Past a limit the app keeps
    # working with the free rule checks only.
    ai_ok = (
        bool(message.strip())
        and st.session_state.get("ai_checks", 0) < MAX_CHECKS_PER_SESSION
        and get_daily_limit().take()
    )
    loader = st.empty()
    if message.strip():
        loader.markdown(LOADER, unsafe_allow_html=True)  # animated by CSS, so it moves while we wait
    try:
        result = analyze(message, use_ai=ai_ok)
    except ValueError as error:
        st.warning(str(error))
        return
    except Exception as error:  # never show a stack trace, never log the message
        log.error("check failed: %s", type(error).__name__)
        st.error("Sorry, something went wrong while checking. Please try again in a moment.")
        return
    finally:
        loader.empty()

    if ai_ok:
        st.session_state.ai_checks = st.session_state.get("ai_checks", 0) + 1
    result["paused"] = not ai_ok
    st.session_state.result = result
    st.session_state.checked_input = message


def render_result(result):
    facts = result["facts"]
    domains = facts["domains"]

    # 1. The verdict card (every piece of untrusted text goes through safe_html)
    css, icon, risk_label, default_text = VERDICTS[result["verdict"]]
    text = result["guard_note"] or result["summary"] or default_text
    badges = f'<span class="verdict-badge risk">{risk_label}</span>'
    if result["confidence"]:
        badges += f'<span class="verdict-badge">Confidence: {safe_html(result["confidence"], domains)}</span>'
    badges += f'<span class="verdict-badge">Checked by: {safe_html(result["source"], domains)}</span>'
    st.markdown(
        f'<div class="verdict-card {css}" role="status">'
        '<span class="verdict-orbit" aria-hidden="true"></span>'
        '<div class="verdict-eyebrow">Your message check</div>'
        f'<h2 class="icon-heading">{icon}<span>{html.escape(result["verdict"])}</span></h2>'
        f'<p class="verdict-text">{safe_html(text, domains)}</p>'
        f'<div class="verdict-badges">{badges}</div></div>',
        unsafe_allow_html=True,
    )

    # 2. Short notes about how this result was made
    if result.get("paused"):
        st.info("AI analysis and web lookups are paused right now to protect free usage credits. "
                "This result uses the rule checks only.")
    elif result["ai_error"]:
        st.caption("AI analysis was unavailable just now, so this result uses the rule checks only.")
    if result["search_error"]:
        st.caption("Web lookup was unavailable just now.")
    if result["was_truncated"]:
        st.caption(f"The message was long, so only the first {MAX_CHARS} characters were checked.")
    hidden = result["privacy"]["cards_masked"] + result["privacy"]["ids_masked"]
    if hidden:
        st.info(f"We hid {hidden} card or ID number(s) before checking, so they were never sent anywhere.")

    # 3. What to do: always visible, first
    st.subheader("What to do now")
    steps = "".join(f"<li><span>{safe_html(step, domains)}</span></li>" for step in result["next_steps"])
    st.markdown(f'<div class="steps-card"><ol>{steps}</ol></div>', unsafe_allow_html=True)

    # 4. Everything else, in tabs
    report = build_report(result)
    labels = ["What stood out"] + (["Report it"] if report else []) + ["Details"]
    tabs = dict(zip(labels, st.tabs(labels)))

    with tabs["What stood out"]:
        if result["ai_used"] and result["red_flags"]:
            for flag in result["red_flags"]:
                line = "- **" + plain(flag["title"]) + "**"
                if flag["explanation"]:
                    line += ": " + plain(flag["explanation"])
                st.markdown(line)
        elif result["signals"]:
            for s in result["signals"]:
                st.markdown(f"- **{s['label']}**: {code_safe(s['evidence'])}")
        else:
            st.write("No common scam red flags were found.")

        marked = highlight_html(result["message"], result["signals"], domains)
        if marked:
            st.caption("Highlighted words matched one of our rule checks. Links are made harmless.")
            st.markdown(marked, unsafe_allow_html=True)
        if result["ai_used"] and result["signals"]:
            with st.expander("Rule checks that fired"):
                for s in result["signals"]:
                    st.markdown(f"- **{s['label']}**: {code_safe(s['evidence'])}")

    if report:
        with tabs["Report it"]:
            st.caption("Copy this and send it to the company being imitated, your bank, or the app where "
                       "it arrived. Links are made harmless so nobody clicks them by accident.")
            st.code(report, language=None)
            st.caption("Also use the report button inside the app you received it in, and look for "
                       "your country's official scam-reporting service.")

    with tabs["Details"]:
        if domains or facts["phones"] or facts["handles"]:
            st.caption("Shown as plain text on purpose. Do not visit these.")
            ages = {a["domain"]: a for a in result["domain_ages"]}
            for domain in domains:
                line = "- Website: " + code_safe(domain)
                age = ages.get(registrable(domain))
                if age:
                    line += f", registered {age['days']} days ago"
                st.markdown(line)
            for phone in facts["phones"]:
                st.markdown("- Phone number: " + code_safe(phone))
            for handle in facts["handles"]:
                st.markdown("- Handle: " + code_safe(handle))
        else:
            st.write("No websites, phone numbers or handles were found in this message.")

        if result["search_results"]:
            st.markdown("**Related warnings from the web (via Tavily)**")
            st.caption("These are search results. They may describe similar scams, not this exact message.")
            for r in result["search_results"]:
                line = "- **" + plain(r["title"] or "Result") + "**"
                if r["snippet"]:
                    line += ": " + plain(r["snippet"])
                st.markdown(line)

        t = result["timing"]
        st.caption(f"Checked in {t['total']} s (lookups {t['lookups']} s, AI {t['ai']} s).")


# ---------------------------------------------------------------- page

st.markdown(STYLE, unsafe_allow_html=True)
st.markdown(HERO, unsafe_allow_html=True)

left_column, right_column = st.columns([1, 1.05], gap="large")

with left_column:
    available = [(label, ex_id) for label, ex_id in QUICK_EXAMPLES if ex_id in EXAMPLES]
    if available:
        st.caption("Not sure what to paste? Try an example:")
        with st.container():
            st.markdown('<span class="example-pills-marker" aria-hidden="true"></span>', unsafe_allow_html=True)
            for label, ex_id in available:
                st.button(label, key=f"ex_{ex_id}", on_click=use_example, args=(ex_id,))

    with st.container():
        st.markdown('<span class="input-card-marker" aria-hidden="true"></span>', unsafe_allow_html=True)
        st.session_state.setdefault("message", "")
        message = st.text_area(
            "Paste the message here",
            key="message",
            height=180,
            max_chars=MAX_CHARS,
            placeholder="Example: Your parcel is on hold. Pay a small fee within 24 hours...",
        )
        st.caption("Please do not paste passwords. Card numbers are hidden automatically before the check.")
        check_col, clear_col, _spacer = st.columns([1.4, 1, 1.6], gap="small")
        check = check_col.button("Check message", type="primary", key="check")
        clear_col.button("Clear", key="clear", on_click=clear_all)

with right_column:
    if check:
        run_check(message)

    result = st.session_state.get("result")
    if result:
        if message != st.session_state.get("checked_input"):
            st.info("You changed the message. Press **Check message** to update the result.")
        render_result(result)
    else:
        st.markdown(EMPTY_STATE, unsafe_allow_html=True)

st.markdown(HOW_IT_WORKS, unsafe_allow_html=True)
st.divider()
with st.expander("Privacy: what happens to your message"):
    st.markdown(
        "This app does not store your message. When AI analysis is on, the message text is sent to "
        "Nebius Token Factory. Websites, phone numbers and handles found in it are looked up with "
        "Tavily, and website names are checked against public domain registration records (RDAP). "
        "Card and ID numbers are hidden before anything is sent. We never open any link in a message."
    )
st.caption(
    "This tool gives a quick estimate, not a guarantee. If you are unsure, contact the company "
    f"using an official website or a number you already trust. [Source code]({SOURCE_URL})"
)
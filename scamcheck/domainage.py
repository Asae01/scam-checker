"""Check how new a website is, using public domain registration records (RDAP).

A website registered a few days ago is a classic scam sign.

SAFETY
- We never visit the website. We only ask the public RDAP service (rdap.org) when
  the name was registered.
- The website name comes from an untrusted message, so it is strictly checked
  before it goes into a request, the request always goes to one fixed host over
  HTTPS, redirects are checked, and replies are size-limited.
- If anything fails, the check is silently skipped (no flag, no error).
"""

import ipaddress
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .extract import get_domain
from .signals import BRANDS, FLAG_LABELS, SHORTENERS

RDAP_URL = "https://rdap.org/domain/"
TIMEOUT_SECONDS = 5
MAX_BYTES = 200_000
MAX_DOMAINS = 2
NEW_DAYS = 90

# Names that can never be real public websites.
SKIP_ENDINGS = (".example", ".test", ".invalid", ".localhost", ".local", ".internal", ".onion")

# Endings made of two parts, so "evil.co.uk" is looked up, not "co.uk".
TWO_PART_ENDINGS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "co.in", "com.sg", "com.my", "org.my", "net.my", "edu.my", "gov.my",
    "com.br", "co.za", "com.cn", "com.hk", "com.tw",
}

DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})$"
)

_cache = {}
_cache_lock = threading.Lock()


def clear_cache():
    with _cache_lock:
        _cache.clear()


def registrable(domain):
    """Reduce 'login.secure.evil.com' to 'evil.com' (a close approximation)."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_ENDINGS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def should_lookup(domain):
    """Only look up real-looking public websites that are worth checking."""
    domain = domain.lower().strip(".")
    if not DOMAIN_RE.match(domain) or domain.endswith(SKIP_ENDINGS):
        return False
    reg = registrable(domain)
    if domain in SHORTENERS or reg in SHORTENERS:
        return False  # shorteners are old; their age says nothing about the hidden link
    for _pattern, official in BRANDS.values():
        if any(reg == o or reg.endswith("." + o) or domain == o or domain.endswith("." + o) for o in official):
            return False  # the real company's own website
    return True


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Only follow redirects to https websites that are not IP addresses or localhost."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not host or host == "localhost" or _is_ip(host):
            raise urllib.error.URLError("unsafe redirect blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _parse_date(value):
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def fetch_registration(domain, opener=None):
    """Return (registration datetime, None) or (None, short reason)."""
    opener = opener or urllib.request.build_opener(_SafeRedirect)
    url = RDAP_URL + urllib.parse.quote(domain, safe="")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "scam-message-checker/1.0",
        },
    )
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_BYTES)
    except urllib.error.HTTPError as error:
        return None, f"http {error.code}"
    except Exception as error:
        return None, type(error).__name__

    try:
        data = json.loads(raw)
    except ValueError:
        return None, "bad reply"
    events = data.get("events", []) if isinstance(data, dict) else []
    for event in events if isinstance(events, list) else []:
        if isinstance(event, dict) and str(event.get("eventAction", "")).lower() == "registration":
            when = _parse_date(event.get("eventDate"))
            if when:
                return when, None
    return None, "no registration date"


def _cached_registration(domain, opener):
    with _cache_lock:
        if domain in _cache:
            return _cache[domain]
    when, _error = fetch_registration(domain, opener)
    if when is not None:  # only keep successes, so a failed lookup is retried later
        with _cache_lock:
            _cache[domain] = when
    return when


def _find_url_span(message, facts, reg):
    for url in facts["urls"]:
        if registrable(get_domain(url)) == reg:
            start = message.find(url)
            if start >= 0:
                return (start, start + len(url))
    return None


def domain_age_signals(facts, message="", opener=None, now=None):
    """Return (signals, ages). A signal is only raised for a website under NEW_DAYS old."""
    try:
        now = now or datetime.now(timezone.utc)
        regs = []
        for domain in facts["domains"]:
            reg = registrable(domain)
            if should_lookup(domain) and reg not in regs:
                regs.append(reg)
            if len(regs) >= MAX_DOMAINS:
                break
        if not regs:
            return [], []

        with ThreadPoolExecutor(max_workers=len(regs)) as pool:
            found = list(pool.map(lambda r: (r, _cached_registration(r, opener)), regs))

        ages = []
        for reg, when in found:
            if when is not None:
                ages.append({
                    "domain": reg,
                    "registered": when.date().isoformat(),
                    "days": max((now - when).days, 0),
                })

        signals = []
        if ages:
            newest = min(ages, key=lambda a: a["days"])
            if newest["days"] < NEW_DAYS:
                days = newest["days"]
                unit = "day" if days == 1 else "days"
                signals.append({
                    "flag": "new_domain",
                    "label": FLAG_LABELS["new_domain"],
                    "evidence": f"{newest['domain']} was registered {days} {unit} ago",
                    "span": _find_url_span(message, facts, newest["domain"]),
                })
        return signals, ages
    except Exception:
        return [], []
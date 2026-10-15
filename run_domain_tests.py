"""Offline tests for the website-age check. A pretend RDAP service is used: no internet needed."""

import testenv  # noqa: F401  (offline test environment: must come first)
import io
import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from scamcheck.domainage import (
    _SafeRedirect, clear_cache, domain_age_signals, registrable, should_lookup,
)
from scamcheck.extract import extract_facts
from scamcheck.pipeline import analyze

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeOpener:
    """Pretends to be the RDAP service. table maps domain -> registration date text."""

    def __init__(self, table):
        self.table, self.calls, self.urls = table, [], []

    def open(self, request, timeout=None):
        self.urls.append(request.full_url)
        domain = request.full_url.rsplit("/", 1)[-1]
        self.calls.append(domain)
        if domain not in self.table:
            raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, None)
        body = {"events": [
            {"eventAction": "registration", "eventDate": self.table[domain]},
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
        ]}
        return io.BytesIO(json.dumps(body).encode())


# 1. Reducing a name to the part that is registered.
assert registrable("www.evil.com") == "evil.com"
assert registrable("login.secure.evil.com") == "evil.com"
assert registrable("a.b.evil.co.uk") == "evil.co.uk"
assert registrable("shop.evil.com.my") == "evil.com.my"
print("1. Names reduced correctly: OK")

# 2. Which names are looked up at all.
for good in ["fresh-promo.com", "login.fresh-promo.com", "evil.co.uk"]:
    assert should_lookup(good), good
for bad in ["dhl-parcel.example", "site.test", "127.0.0.1", "localhost", "bit.ly", "a_b.com",
            "evil..com", "evil.com/../x", "x@evil.com", "amazon.com", "tools.usps.com", "a.co"]:
    assert not should_lookup(bad), bad
print("2. Only real public websites are looked up: OK")

# 3. New site -> flag with the right wording and the link highlighted.
clear_cache()
msg = "Big sale on my new store: https://fresh-promo.com/sale"
facts = extract_facts(msg)
signals, ages = domain_age_signals(facts, msg, opener=FakeOpener({"fresh-promo.com": iso(5)}), now=NOW)
assert len(signals) == 1 and signals[0]["flag"] == "new_domain"
assert signals[0]["evidence"] == "fresh-promo.com was registered 5 days ago"
start, end = signals[0]["span"]
assert msg[start:end] == "https://fresh-promo.com/sale"
assert ages == [{"domain": "fresh-promo.com", "registered": iso(5)[:10], "days": 5}]
print("3. New website flagged: OK")

# 4. Old site -> age is known but no flag. 60 days -> flagged. Unknown -> nothing.
clear_cache()
old_msg = "see https://old-shop.com/x"
signals, ages = domain_age_signals(extract_facts(old_msg), old_msg, FakeOpener({"old-shop.com": iso(4000)}), NOW)
assert signals == [] and ages[0]["days"] == 4000
clear_cache()
signals, _ = domain_age_signals(extract_facts(old_msg), old_msg, FakeOpener({"old-shop.com": iso(60)}), NOW)
assert len(signals) == 1
clear_cache()
assert domain_age_signals(extract_facts(old_msg), old_msg, FakeOpener({}), NOW) == ([], [])
print("4. Old, fairly new and unknown sites: OK")

# 5. Answers are cached; failed lookups are not.
clear_cache()
spy = FakeOpener({"fresh-promo.com": iso(5)})
domain_age_signals(facts, msg, spy, NOW)
domain_age_signals(facts, msg, spy, NOW)
assert spy.calls == ["fresh-promo.com"]
clear_cache()
missing = FakeOpener({})
domain_age_signals(facts, msg, missing, NOW)
domain_age_signals(facts, msg, missing, NOW)
assert len(missing.calls) == 2
print("5. Caching: OK")

# 6. The request always goes to the one fixed host, over https.
clear_cache()
spy = FakeOpener({"fresh-promo.com": iso(5)})
domain_age_signals(facts, msg, spy, NOW)
assert spy.urls == ["https://rdap.org/domain/fresh-promo.com"]
print("6. Fixed host and https: OK")

# 7. Redirects are only followed to https websites that are not IPs or localhost.
handler = _SafeRedirect()
req = urllib.request.Request("https://rdap.org/domain/x.com")
for bad_url in ["http://rdap.verisign.com/x", "https://169.254.169.254/latest", "https://localhost/x",
                "https://[::1]/x", "ftp://example.org/x"]:
    try:
        handler.redirect_request(req, None, 302, "Found", {}, bad_url)
        raise AssertionError("redirect should have been blocked: " + bad_url)
    except urllib.error.URLError:
        pass
ok = handler.redirect_request(req, None, 302, "Found", {}, "https://rdap.verisign.com/com/v1/domain/x.com")
assert ok.full_url == "https://rdap.verisign.com/com/v1/domain/x.com"
print("7. Unsafe redirects blocked: OK")

# 8. Whole pipeline: a message with only a brand-new site becomes Suspicious,
#    and nothing touches the network when lookups are off.
clear_cache()
fresh = datetime.now(timezone.utc) - timedelta(days=3)
opener = FakeOpener({"fresh-promo.com": fresh.strftime("%Y-%m-%dT%H:%M:%SZ")})
r = analyze(msg, use_ai=False, use_domain_age=True, age_opener=opener)
assert [s["flag"] for s in r["signals"]] == ["new_domain"] and r["risk_score"] == 2
assert r["verdict"] == "Suspicious" and r["domain_ages"][0]["days"] == 3
clear_cache()
quiet = FakeOpener({"fresh-promo.com": fresh.strftime("%Y-%m-%dT%H:%M:%SZ")})
r = analyze(msg, use_ai=False, age_opener=quiet)
assert quiet.calls == [] and r["domain_ages"] == [] and r["verdict"] == "Probably safe"
print("8. Pipeline integration and offline mode: OK")

print("\nAll website-age tests passed.")
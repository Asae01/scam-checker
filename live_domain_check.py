"""Check the REAL website-age lookup (needs internet; it never visits the websites).

  python live_domain_check.py                  -> checks a few well-known sites
  python live_domain_check.py some-domain.com  -> checks the ones you type
"""

import sys

from scamcheck.domainage import fetch_registration, registrable, should_lookup

domains = sys.argv[1:] or ["wikipedia.org", "github.com", "bbc.co.uk"]
for domain in domains:
    reg = registrable(domain)
    if not should_lookup(domain):
        print(f"{domain}: skipped (reserved, shortener, IP or an official brand site)")
        continue
    when, error = fetch_registration(reg)
    print(f"{domain} -> {reg}: registered {when.date() if when else 'unknown'} ({error or 'ok'})")
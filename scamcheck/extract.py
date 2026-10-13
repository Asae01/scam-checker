"""Pull useful facts (links, domains, phone numbers, handles) out of a message.

SAFETY: this file only reads text. It never opens or visits a link.
"""

import re
from urllib.parse import urlparse

# A link starts with http://, https:// or www. and runs until the next space.
URL_RE = re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE)

# A phone number: optional +, then digits mixed with spaces, dashes, dots, brackets.
PHONE_RE = re.compile(r"\+?\d[\d\- ().]{6,}\d")

# A social handle like @quickcashjobs01 (but not the @ inside an email address).
HANDLE_RE = re.compile(r"(?<![\w.])@[A-Za-z0-9_]{4,}")

# Punctuation that often sticks to the end of a link, like "...pay." or "(link)".
TRAILING_PUNCT = ".,;:!?)]}\"'"


def _unique(items):
    """Remove duplicates but keep the original order."""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def extract_urls(text):
    urls = [match.rstrip(TRAILING_PUNCT) for match in URL_RE.findall(text)]
    return _unique(urls)


def get_domain(url):
    """Return just the website name, e.g. 'secure-bank.example'."""
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def extract_phones(text):
    phones = []
    for match in PHONE_RE.findall(text):
        digit_count = len(re.sub(r"\D", "", match))
        # Real phone numbers have 8 to 15 digits. This skips prices and short codes.
        if 8 <= digit_count <= 15:
            phones.append(match.strip())
    return _unique(phones)


def extract_handles(text):
    return _unique(HANDLE_RE.findall(text))


def extract_facts(text):
    """Run every extractor and return the results in one dictionary."""
    urls = extract_urls(text)
    domains = [get_domain(url) for url in urls]

    # Remove links first so numbers or @ signs inside a link are not mistaken
    # for phone numbers or handles.
    text_without_urls = URL_RE.sub(" ", text)

    return {
        "urls": urls,
        "domains": _unique([d for d in domains if d]),
        "phones": extract_phones(text_without_urls),
        "handles": extract_handles(text_without_urls),
    }
"""Look up the websites, phone numbers and handles found in a message using Tavily.

Privacy: only the extracted details are searched, never the whole message.
Cost: at most MAX_QUERIES searches per check (1 Tavily credit each, basic depth).
If Tavily is not set up or fails, we return no results and the app carries on.
"""

import re
import threading
from concurrent.futures import ThreadPoolExecutor

from .llm import NOT_CONFIGURED, get_setting
from .signals import SHORTENERS

MAX_QUERIES = 3
MAX_RESULTS_PER_QUERY = 3
SNIPPET_CHARS = 300


_client_lock = threading.Lock()
_client_cache = {"key": None, "client": None}


def get_client():
    """Return the shared Tavily client, or None if no key is set."""
    key = get_setting("TAVILY_API_KEY")
    if not key:
        return None
    with _client_lock:
        if _client_cache["client"] is None or _client_cache["key"] != key:
            from tavily import TavilyClient

            _client_cache["client"] = TavilyClient(api_key=key)
            _client_cache["key"] = key
        return _client_cache["client"]


def build_queries(facts):
    """Turn extracted details into short search queries (never the full message)."""
    queries = []
    for domain in facts["domains"][:2]:
        is_ip = re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain)
        if domain in SHORTENERS or is_ip:
            continue  # searching these tells us nothing
        queries.append(f"is {domain} a scam")
    for phone in facts["phones"][:1]:
        queries.append(f"{phone} phone number scam reports")
    for handle in facts["handles"][:1]:
        queries.append(f"{handle} scam")
    return queries[:MAX_QUERIES]


def _run_one(client, query):
    try:
        response = client.search(
            query=query, search_depth="basic", max_results=MAX_RESULTS_PER_QUERY
        )
    except Exception as error:
        return query, None, type(error).__name__

    items = []
    for item in (response or {}).get("results", [])[:MAX_RESULTS_PER_QUERY]:
        items.append({
            "query": query,
            "title": str(item.get("title", ""))[:120],
            "url": str(item.get("url", "")),
            "snippet": " ".join(str(item.get("content", "")).split())[:SNIPPET_CHARS],
        })
    return query, items, None


def search_entities(facts, client=None):
    """Return (results, error). Results is a list of {query, title, url, snippet}."""
    queries = build_queries(facts)
    if not queries:
        return [], None

    if client is None:
        client = get_client()
    if client is None:
        return [], NOT_CONFIGURED

    with ThreadPoolExecutor(max_workers=len(queries)) as pool:
        outputs = list(pool.map(lambda q: _run_one(client, q), queries))

    results, failures = [], []
    for _query, items, error in outputs:
        if items is None:
            failures.append(error)
        else:
            results.extend(items)

    if failures and len(failures) == len(outputs):
        return [], f"web search failed ({failures[0]})"
    return results, None
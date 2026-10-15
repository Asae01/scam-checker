"""Show the user's message with the words that triggered a rule check highlighted.

The result is a small piece of HTML. Everything from the message is escaped, links
are made harmless, and there are no blank lines, so nothing in a scam message can
inject markup or become a clickable link.
"""

import html

from .report import defang


def merge_spans(signals):
    """Sort the highlight ranges and merge overlapping ones."""
    items = sorted((s["span"][0], s["span"][1], s["label"]) for s in signals if s.get("span"))
    merged = []
    for start, end, label in items:
        if merged and start < merged[-1][1]:
            prev_start, prev_end, labels = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end), labels if label in labels else labels + [label])
        else:
            merged.append((start, end, [label]))
    return merged


def _safe(text, domains):
    return html.escape(defang(text, domains), quote=True)


def highlight_html(message, signals, domains=()):
    """Return HTML with highlighted matches, or None when there is nothing to highlight."""
    spans = merge_spans(signals)
    if not spans:
        return None

    parts, pos = [], 0
    for start, end, labels in spans:
        parts.append(_safe(message[pos:start], domains))
        tip = html.escape("; ".join(labels), quote=True)
        parts.append(
            f'<mark title="{tip}" style="background-color:#ffd54f;color:#1a1a1a;'
            f'padding:1px 3px;border-radius:3px;">{_safe(message[start:end], domains)}</mark>'
        )
        pos = end
    parts.append(_safe(message[pos:], domains))

    body = "".join(parts).replace("\r", "").replace("\n", "<br>")
    return f'<div style="line-height:1.8;word-break:break-word;">{body}</div>'

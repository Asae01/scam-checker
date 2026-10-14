"""A shared daily limit on how many checks may use the AI and web search.

Why: your free credits must last through the judging period. When the limit is
reached the app keeps working using the free rule checks only.
"""

import threading
from datetime import datetime, timezone


class DailyLimit:
    def __init__(self, max_per_day, today=None):
        self.max_per_day = max_per_day
        self._today = today or (lambda: datetime.now(timezone.utc).date())
        self._day = None
        self._count = 0
        self._lock = threading.Lock()

    def take(self):
        """Use one slot. Returns True if the AI may run, False if today's limit is reached."""
        with self._lock:
            day = self._today()
            if day != self._day:
                self._day, self._count = day, 0
            if self._count >= self.max_per_day:
                return False
            self._count += 1
            return True
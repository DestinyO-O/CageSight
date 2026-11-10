"""Shared detector helpers."""

from __future__ import annotations

from typing import Dict, Hashable, List, Optional

from cagesight.config import Context
from cagesight.model import Event, Finding


class BaseDetector:
    name = "base"

    def __init__(self) -> None:
        self._seen: Dict[Hashable, float] = {}

    def feed(self, event: Event, ctx: Context) -> List[Finding]:  # pragma: no cover
        raise NotImplementedError

    def dedupe(self, key: Hashable, ts: float, window: float = 60.0) -> bool:
        """Return True if this key was already reported inside the window."""
        last = self._seen.get(key)
        if last is not None and ts - last < window:
            return True
        self._seen[key] = ts
        return False

    @staticmethod
    def make(
        ctx: Context,
        rule_id: str,
        event: Event,
        evidence: str,
        **kwargs,
    ) -> Optional[Finding]:
        return ctx.finding(rule_id, event, evidence, **kwargs)

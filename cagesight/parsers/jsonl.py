"""Parser for CageSight's normalized JSONL event format."""

from __future__ import annotations

import json
from typing import Iterable, List

from cagesight.model import Event

MAX_BUFFER = 1 << 20  # 1 MiB: 单条事件不应超过此大小，避免畸形输入把内存吃满


def parse_lines(lines: Iterable[str]) -> List[Event]:
    events: List[Event] = []
    buffer = ""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("\ufeff"):  # Windows 记事本/Excel 导出的 UTF-8 BOM
            line = line[1:]
        if not line:
            continue
        if line.startswith("{"):
            buffer = line
        elif not buffer:
            buffer = line
        elif len(buffer) + len(line) <= MAX_BUFFER:
            buffer += line
        else:
            buffer = ""
            continue
        try:
            data = json.loads(buffer)
        except (json.JSONDecodeError, RecursionError):
            continue
        buffer = ""
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    try:
                        events.append(Event.from_dict(item))
                    except Exception:
                        continue
        elif isinstance(data, dict):
            try:
                events.append(Event.from_dict(data))
            except Exception:
                continue
    events.sort(key=lambda e: e.ts)
    return events


def parse_file(path: str) -> List[Event]:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return parse_lines(handle)

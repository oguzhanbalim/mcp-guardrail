"""Append-only JSONL audit log.

Each record is one ``write`` on an ``O_APPEND`` descriptor followed by ``fsync``.
The descriptor is write-only, so this code has no way to rewrite history. That is
a discipline, not a tamper-proof store: anyone with file access can still edit it.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fd: int | None = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)

    def write(self, event: str, call_id: str, **fields: Any) -> None:
        """Append one record. Raises OSError on failure; callers decide how to fail."""
        if self._fd is None:
            raise OSError("audit log is closed")
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "event": event,
            "call_id": call_id,
            **fields,
        }
        line = json.dumps(record, ensure_ascii=False, sort_keys=True, default=repr) + "\n"
        os.write(self._fd, line.encode("utf-8"))
        os.fsync(self._fd)

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

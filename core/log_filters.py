from __future__ import annotations

import logging
import re
from typing import Any

_INVITATION_TOKEN = re.compile(r"(?<=/invite/)[^/?\s]+")


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        return _INVITATION_TOKEN.sub("<redacted>", value)
    if isinstance(value, tuple):
        return tuple(_redact(item) for item in value)
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    return value


class RedactInvitationTokenFilter(logging.Filter):
    """Prevent one-time invitation credentials from reaching application logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _redact(record.msg)
        record.args = _redact(record.args)
        return True

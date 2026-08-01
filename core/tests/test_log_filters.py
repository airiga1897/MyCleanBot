from __future__ import annotations

import logging

from core.log_filters import RedactInvitationTokenFilter


def test_invitation_token_is_redacted_from_positional_log_arguments() -> None:
    token = "sensitive-token_123"
    record = logging.LogRecord(
        name="django.security.csrf",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="Forbidden (%s): %s",
        args=("CSRF token incorrect", f"/invite/{token}/"),
        exc_info=None,
    )

    assert RedactInvitationTokenFilter().filter(record)
    rendered = record.getMessage()
    assert token not in rendered
    assert "/invite/<redacted>/" in rendered


def test_invitation_token_is_redacted_from_message_and_mapping_arguments() -> None:
    token = "another-sensitive-token"
    direct = logging.LogRecord(
        name="app",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg=f"request failed at /invite/{token}/",
        args=(),
        exc_info=None,
    )
    mapping = logging.LogRecord(
        name="app",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="request failed at %(path)s",
        args=({"path": f"https://mycleanbot.mine-craft.su/invite/{token}/"},),
        exc_info=None,
    )

    log_filter = RedactInvitationTokenFilter()
    assert log_filter.filter(direct)
    assert log_filter.filter(mapping)
    assert token not in direct.getMessage()
    assert token not in mapping.getMessage()

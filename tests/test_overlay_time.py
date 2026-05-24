from __future__ import annotations

from datetime import datetime, timezone

import overlay


def test_format_time_fallback_uses_utc_timezone(monkeypatch) -> None:
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            assert tz is timezone.utc
            return cls(2026, 4, 4, 12, 34, 56, tzinfo=tz)

    monkeypatch.setattr(overlay, "datetime", FixedDateTime)

    assert overlay._format_time(None) == "12:34:56"

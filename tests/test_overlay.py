from datetime import timezone

import overlay


class _FakeClock:
    def strftime(self, format_string: str) -> str:
        assert format_string == "%H:%M:%S"
        return "12:34:56"


class _FakeDateTime:
    timezone_argument = None

    @classmethod
    def now(cls, timezone_argument):
        cls.timezone_argument = timezone_argument
        return _FakeClock()


def test_format_time_uses_an_aware_utc_clock_when_timestamp_is_missing(monkeypatch) -> None:
    monkeypatch.setattr(overlay, "datetime", _FakeDateTime)

    assert overlay._format_time(None) == "12:34:56"
    assert _FakeDateTime.timezone_argument is timezone.utc


def test_format_time_preserves_journal_timestamp_time_component() -> None:
    assert overlay._format_time("2026-09-03T14:40:18Z") == "14:40:18"

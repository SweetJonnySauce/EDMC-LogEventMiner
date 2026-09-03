# Issue #1 context

## Scope

GitHub issue #1 reports a `DeprecationWarning` from `overlay._format_time()`
when an overlay event does not include a timestamp.  The replacement must use a
timezone-aware UTC datetime and preserve the existing `HH:MM:SS` output.

## Existing implementation

- `overlay.py` owns journal-overlay line formatting.  `OverlayLine.format()`
  calls `_format_time(timestamp)`.
- Timestamped journal events are parsed with `datetime.fromisoformat()` and
  retain their time component.
- The no-timestamp fallback on the current `fix-utcnow` branch already calls
  `datetime.now(timezone.utc)`.  Commit `db85811` introduced that production
  change, but it has no direct regression test.
- `tests/test_logeventminer_status.py` uses plain pytest functions.  Importing
  `overlay` is safe outside EDMC because its overlay integrations are optional.

## Requirements and acceptance criteria

1. A missing timestamp returns an `HH:MM:SS` value generated from an aware UTC
   clock.
2. The fallback must not call `datetime.utcnow()`.
3. Timestamped journal lines retain their existing formatting behavior.
4. The focused and full headless pytest suites pass.

## Dependency map

`OverlayLine.format()` -> `overlay._format_time()` -> `datetime.now(timezone.utc)`

The test will replace only `overlay.datetime` with a small deterministic fake;
it will assert the timezone argument and returned display text.  No EDMC API,
configuration, UI, worker thread, or network behavior is in scope.

## Existing documentation

- `README.md` describes the plugin's journal logging and optional overlay.
- No `CODEASSIST.md` exists.  The repository's `AGENTS.md` instructions and
  existing pytest conventions govern this work.

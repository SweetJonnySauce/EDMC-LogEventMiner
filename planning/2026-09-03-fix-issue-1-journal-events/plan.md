# Issue #1 plan

## Test strategy

| Scenario | Input | Expected output / observation |
| --- | --- | --- |
| Fallback clock | `None` timestamp; deterministic fake clock | Calls `now(timezone.utc)` and returns the fake `HH:MM:SS` text. |
| Journal timestamp | `"2026-09-03T14:40:18Z"` | Returns `"14:40:18"`, unchanged. |

The first test is intentionally a regression test for the production fix
already in `db85811`; it would fail if the implementation returned to
`datetime.utcnow()` or used a naive clock.

## Implementation approach

1. Add `tests/test_overlay.py` following the repository's simple pytest style.
2. Monkeypatch only `overlay.datetime` for the fallback test, keeping the
   assertion independent of system time.
3. Restore the required `1.6.1` changelog entry if the release validation
   identifies it as missing.
4. Run the focused test, then the complete headless suite.
5. Review the small change, validate the relevant project check where
   available, and commit only after green results.

## Phase status

| Phase | Status |
| --- | --- |
| 1. Explore and plan | Completed |
| 2. Test and implementation | Completed |
| 3. Validation and commit | Validation completed; commit blocked |

## Stage checklist

| Stage | Description | Status |
| --- | --- | --- |
| 1.1 | Read issue #1 and identify the affected fallback path. | Completed |
| 1.2 | Inspect existing source, tests, and baseline test result. | Completed |
| 1.3 | Define deterministic regression scenarios and acceptance criteria. | Completed |
| 2.1 | Add regression tests before implementation changes. | Completed |
| 2.2 | Verify or minimally adjust production code to satisfy the tests. | Completed |
| 2.3 | Restore the release-note invariant required by the validation script. | Completed |
| 3.1 | Run focused and full headless pytest validation. | Completed |
| 3.2 | Review compliance and record validation results. | Completed |
| 3.3 | Commit the verified change. | Blocked: `.git` is read-only in this environment. |

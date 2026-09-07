# CAPI Monitor implementation plan

## Phase overview
| Phase | Description | Status |
| --- | --- | --- |
| 1 | Establish callback and window contracts | Completed |
| 2 | Tests and implementation | Completed |
| 3 | Validation and documentation | Completed |

## Phase 1
| Stage | Description | Status |
| --- | --- | --- |
| 1.1 | Inspect hooks, preferences, runtime baseline, and test setup | Completed |
| 1.2 | Record scope, lifecycle, bounded history, and test plan | Completed |

## Phase 2
| Stage | Description | Status |
| --- | --- | --- |
| 2.1 | Add failing formatting, callback, and lifecycle tests | Completed |
| 2.2 | Implement isolated monitor module and wire button/hooks/shutdown | Completed |

Tests: dict-like payload with unknown nested keys yields intact JSON and labelled
receipt metadata; closed monitor never serializes data; callbacks route live,
beta, legacy, and carrier updates regardless of journal filtering; shutdown
closes viewer and prevents subsequent dispatch. GUI checks cover singleton,
resize, scrollbars, read-only output, Close/WM close, reopen, preferences teardown,
root destruction, and history retention. No existing settings are altered.

## Phase 3
| Stage | Description | Status |
| --- | --- | --- |
| 3.1 | Run focused/full pytest, GUI checks where possible, and release validation | Completed |
| 3.2 | Update README/changelog and record results/compliance | Completed |

Commands: `python3 -m pytest -q tests/test_logeventminer_capi.py`,
`python3 -m pytest -q`, `python3 scripts/verify_semver.py`, `git diff --check`.
GUI tests use real Tk when a display is available and explicitly skip otherwise.
Makefile, requirements-dev.txt, baseline checker, and GUI-specific project command
are absent. Do not install unrelated dependencies. Keep the version unchanged.

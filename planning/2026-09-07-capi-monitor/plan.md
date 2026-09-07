# CAPI Monitor implementation plan

## Phase overview
| Phase | Description | Status |
| --- | --- | --- |
| 1 | Establish callback and window contracts | Completed |
| 2 | Tests and implementation | Completed |
| 3 | Validation and documentation | Completed |
| 4 | Fix scrolling through large CAPI reports | Completed |
| 5 | Stop unsolicited scrolling and expose explicit follow control | Completed |
| 6 | JSON syntax colors and viewport breadcrumb | Completed |

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

## Phase 4
The current tail-follow test accepts the bottom 1% of the document as the end.
For large CAPI responses this can include many lines the user is reading.
Reproduce with a large report and a one-line upward scroll, then make following
depend on the actual end. Verify both wheel and scrollbar movement through real
Tk events, including new data arriving while scrolled up. Preserve native Tk
selection/copy, bounded history, and following when actually at the end.

| Stage | Description | Status |
| --- | --- | --- |
| 4.1 | Reproduce near-bottom snap with a real Tk regression test | Completed |
| 4.2 | Fix follow detection and validate wheel/scrollbar behavior | Completed |
| 4.3 | Run full headless/GUI suites and record results | Completed |

Commands: focused scrolling tests with display access, full headless and GUI
pytest suites, `python3 scripts/verify_semver.py`, and `git diff --check`.

## Phase 5
User now reports slow upward movement without input. Our own code has no idle
timer. Tk's native Text selection binding starts a repeating TextAutoScan on
B1-Leave; a lost release can keep scrolling without CAPI updates. Reproduce this
path with real Tk events; do not assume it is proven to be the user's exact cause.

Add a per-window `Follow latest` checkbox, off by default, as an explicit escape
hatch. When off, incoming data must preserve the viewed text; when on, follow
only from the actual bottom (retain phase 4's manual-scroll protection). Enabling
it jumps to the latest data. Reopening starts with following off.
Disable only this viewer's out-of-bounds drag auto-scan, preserving text selection,
copy, wheel, keyboard and scrollbar navigation. Do not change global Tk bindings.
Ensure cursor/selection cannot create periodic redraw work in this read-only view.

| Stage | Description | Status |
| --- | --- | --- |
| 5.1 | Add failing idle-selection and explicit-follow regression tests | Completed |
| 5.2 | Implement local selection guard and per-window follow control | Completed |
| 5.3 | Run real Tk/full suites, update usage and validation notes | Completed |

Validation: GUI tests with a large report, simulated selection leaving its bounds,
an actual idle event loop, explicit checkbox transitions, repeated data appends,
selection preservation, and existing wheel/scrollbar tests. Full headless and GUI
pytest, SemVer, syntax, and diff checks. Existing missing project tools remain skipped.

## Phase 6
Add syntax colors for JSON keys, string values, numbers, booleans/null and
punctuation. A fixed-height breadcrumb above the text reports the callback and
JSON path at the first visible line, including array indexes. It updates only
on scrolling, resize, or received data; no idle polling or new automatic scrolling.
Multiple reports retain separate source labels. Keys with escaping/Unicode and
truncated history must preserve accurate paths and colors. Error/waiting text
stays readable without being parsed as JSON. Keep selection, copy, Close,
Follow latest defaults, and all earlier scrolling fixes.

Use a new pure `logeventminer_json.py` module to scan already formatted JSON,
producing token spans and a per-line path index. Crop presentation metadata along
with text so deleted parents do not lose retained child paths. Tk applies tags
only to appended text, in batches, and retains a bounded per-line breadcrumb
index. Convert Python character positions for Tk's Unicode column convention.
Performance probe: indexing/coloring 1.5 MB initially took 1.7 seconds; eliminating
duplicate spans and redundant punctuation tags reduced it to about one second.
Prepare reports over 250,000 characters on one worker using the already serialized,
immutable text. Poll only while work is pending; all Tk operations stay on the
main thread. Preserve report order, cancel pending work on close and join on plugin
shutdown. Test deferred delivery and cancellation explicitly.
The breadcrumb is a readonly single-line field with fixed requested width so
long paths cannot resize the window or cause redraw/scroll feedback.

| Stage | Description | Status |
| --- | --- | --- |
| 6.1 | Add pure lexer/path/cropping and GUI breadcrumb/color tests | Completed |
| 6.2 | Implement pure JSON presentation module and Tk integration | Completed |
| 6.3 | Verify full suites, large-payload responsiveness and docs | Completed |

Tests: nested objects/arrays, empty containers, escaped keys, booleans/null,
negative/exponent numbers, non-BMP Unicode tag offsets, viewport movement,
multiple callbacks, cropping through a token/line, and close/reopen reset.
Run focused pure tests and GUI tests, then full headless/GUI suites, SemVer and
syntax/diff checks. Probe large-payload processing and prevent per-token Tcl calls.

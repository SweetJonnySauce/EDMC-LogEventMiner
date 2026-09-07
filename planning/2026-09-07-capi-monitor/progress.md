# CAPI Monitor progress

## Phase 1 — Completed
- [x] 1.1 Inspected repository, callback signatures, and upstream Python baseline.
- [x] 1.2 Created context and implementation/test plan before source edits.

## Phase 2 — Completed
- [x] 2.1 Added tests before implementation. Initial focused run failed collection
  because `logeventminer_capi` did not yet exist (logs/red.txt).
- [x] 2.2 Added isolated CAPIMonitor and formatter; wired Settings button, three
  CAPI callbacks, and shutdown. Closed callbacks return without inspecting data.
  No network calls, threads, scheduled callbacks, disk output, or config keys added.
  Independent root-owned window temporarily releases the preferences modal grab;
  close restores it only when its owner still exists and no newer grab is active.

## Phase 3 — Completed
- [x] 3.1 Validated focused tests, full suite, real Tk lifecycle/integration,
  release SemVer alignment, Python syntax, and ZIP payload inclusion.
- [x] 3.2 Updated README and Unreleased changelog; updated AGENTS.md's stale
  runtime baseline as explicitly required there. VERSION remains 1.6.1.

### Validation
- Focused suite before display access: 4 passed, 3 skipped.
- Real Tk focused suite after correcting fixture to call plugin_start3: 7 passed.
- Added oversized/error-report and scroll-follow tests before final validation.
- Full sandboxed headless suite: **12 passed, 5 skipped** (display access).
- Full suite with local display access: **17 passed**, no skips, 0.62 seconds.
  Includes actual preferences button invocation, resize/layout, both scrollbars,
  read-only output, grab restoration, settings destruction, WM/Close actions,
  reopen, shutdown/root destruction, oversized history, and scrolling behavior.
- `python3 scripts/verify_semver.py`: passed.
- `git diff --check`: passed.
- Compiled source in memory (no runtime import); passed.
- Built/checked `/tmp/logeventminer-capi-monitor-validation.zip` using the existing
  release payload layout; the new root Python module is included automatically.
- Makefile targets, baseline checker, requirements-dev.txt and CI test workflow
  are absent. No dependency installation performed. Used existing Python 3.12.3,
  pytest 7.4.4, and Tk 8.6; Windows/Python 3.13.9 validation remains unperformed.
- Live authenticated CAPI traffic was not exercised; payloads are synthetic.

### EDMC compliance (this change)
| Requirement group | Yes/No | Evidence / remaining requirement |
| --- | --- | --- |
| Core alignment | No (not fully verified) | Official baseline checked and documented; entry point retained. Windows 3.13.9 runtime testing and release/discussion monitoring remain to be verified before release. |
| Supported APIs/settings | Yes | Uses documented CAPI callbacks, mapping data/source_host and config.shutting_down property. No configuration persistence or player detection added. |
| Logging/versioning | Yes | Diagnostic errors use existing EDMC logger with logger.exception/debug(exc_info=True). No runtime print or version-specific branch added. |
| Responsive/Tk-safe | Yes for this change | Main-thread callbacks and UI only; no I/O, network, threads or timers. Text history bounded; GUI lifecycle tested. |
| Preferences/UI | Yes | Button uses myNotebook; separate Tk/ttk viewer resizes. No numeric preferences or config keys added. |
| Dependencies/debug HTTP | No (existing packaging rule) | New module uses only standard library and is included in ZIP. Existing hyphenated plugin directory still fails AGENTS.md's namespace rule; resolve that separately with compatibility checks. No HTTP/debug routing applies. |

### Commit
Implementation and verification complete. Local commit:
`feat: add CAPI monitor window`. No remote push requested.

## Phase 4 — Completed
- [x] 4.1 Reproduced the user's scrolling failure with a 20,000-row report,
  using both a real Tk scrollbar command and a Linux wheel event. Both tests
  failed when new data arrived: the top visible line jumped to the bottom.
- [x] 4.2 Changed tail-follow detection from the bottom 1% of the buffer to
  the actual end (`yview()[1] == 1.0`). Even a one-line upward scroll now
  preserves the viewport through repeated updates. Scrolling back to the end
  resumes following. Targeted scrolling tests: 3 passed.
- [x] 4.3 Full headless suite: 12 passed, 7 display-dependent skips. Full suite
  with local Tk display access: 19 passed. SemVer and git diff checks passed.
  Updated Unreleased changelog. No new runtime dependencies or UI hooks.

Compliance: core Windows baseline remains untested here (No); supported API,
logging/versioning, main-thread responsiveness, and preferences/UI comply for
this change (Yes). Existing directory-naming packaging exception remains (No).
No network, config, lifecycle, or payload-format behavior changed.

Local fix commit: `fix: preserve CAPI monitor scroll position near the bottom`.

## Phase 5 — Completed
- [x] 5.1 Reproduced independent upward movement in a real Tk window by selecting
  text and generating Leave with button 1 held. Tk's TextAutoScan moved the
  viewport immediately and continued through an idle event loop without CAPI
  updates. This demonstrates a cause of the reported symptom; it does not prove
  the exact input sequence in the user's running session.
- [x] 5.2 Scoped a B1-Leave guard to this viewer only, preserving normal selection
  within the text and wheel/scrollbar/keyboard navigation. No global bindings or
  Tk internal state modified. Disabled cursor blinking and implicit X11 PRIMARY
  selection export so external selection ownership does not clear the viewer's
  highlight; explicit copy shortcuts remain native Tk behavior.
  Added Follow latest, off on every open. Enabling it jumps to the end and follows
  new data only while actually at the bottom. Disabling it keeps reading position.
- [x] 5.3 Targeted regression tests passed; full headless suite: 12 passed,
  9 display-dependent skips. Full real Tk suite: **21 passed**, no skips.
  Tests cover an idle event loop, preserved selection/viewport, opt-in following,
  stop/resume, reopening defaults, and prior near-bottom/manual navigation.
  SemVer and diff checks passed. README and Unreleased changelog updated.

Compliance for phase 5: supported APIs, logging, main-thread responsiveness and
preferences/UI are Yes for this change; no persistence or background work added.
Core Windows baseline remains untested (No), and the existing hyphenated plugin
directory still conflicts with the repository packaging rule (No). These existing
release checks require separate validation; this is a development fix.

Local commit: `fix: stop idle selection scrolling in CAPI monitor`.

## Phase 6 — Completed
- [x] 6.1 Added pure JSON token/path/cropping tests before implementation, and
  real Tk tests for syntax colors, viewport breadcrumbs, multi-report sources,
  Unicode tag columns, history trimming, deferred delivery and close cancellation.
- [x] 6.2 Added `logeventminer_json.py` with an iterative scanner over serialized
  JSON. Unknown fields and field order are preserved. Per-line paths survive
  prefix removal, including when an ancestor no longer appears in retained text.
  Tk tags color keys, strings, numbers and literals; punctuation uses the default
  text color. Headers are dimmed. The fixed-height readonly breadcrumb follows
  the top visible line, includes callback source and array indexes, and can be
  horizontally scrolled/selected for long paths. No idle polling or scroll moves
  are caused by breadcrumb updates. Existing Follow latest behavior is preserved.
- [x] 6.3 Validated tests, performance, syntax and release payload inclusion;
  updated README and Unreleased changelog. User explicitly requested **no commit**.

### Phase 6 validation
- Full headless suite with warnings as errors: **17 passed, 13 skipped** because
  sandboxed Tk cannot access the display.
- Full GUI-enabled suite with warnings as errors: **30 passed**, no skips or
  warnings, 1.84 seconds (logs/json-full-gui.txt).
- Large synthetic report: 1,499,536 retained characters. Initial synchronous
  processing took 1.7 seconds; after batching/avoiding duplicate work and moving
  large-report indexing to a data-only worker, the callback took **0.084 seconds**
  and main-thread display insertion/coloring took **0.282 seconds**. The completion
  timer was absent after delivery. Worker input is immutable serialized text;
  all widget operations occur on the main thread. Reports retain arrival order.
- Test fixture now collects destroyed Tk objects on the main thread between tests
  to prevent worker-triggered GC from disposing of old Tcl variables off-thread.
- SemVer and diff checks passed. Native screenshot capture of a synthetic preview
  failed with X11 GetImage error 8; real Tk widget/layout/color assertions passed.
- No live authenticated CAPI payloads were used for validation.

### Phase 6 compliance
| Requirement group | Yes/No | Evidence / remaining work |
| --- | --- | --- |
| Core alignment | No (release verification incomplete) | Documented baseline was verified earlier in this session; Windows 3.13.9 runtime and release/discussion monitoring still require release checks. |
| Supported API/settings | Yes for this change | No new EDMC imports, HTTP usage, config keys, or private CAPI properties. |
| Logging/versioning | Yes for this change | Worker failures use logger.exception; VERSION unchanged with Unreleased notes. |
| Responsive/Tk-safe | Yes for this change | Heavy JSON indexing uses one worker for large reports; completion and all Tk calls stay on main thread; pending timers cancelled on close and active worker joined on plugin stop. |
| Preferences/UI | Yes for this change | Existing myNotebook preferences button preserved; viewer-only Tk/ttk changes, no settings persistence or numeric preferences. |
| Dependencies/debug HTTP | No (existing directory convention) | Standard-library module included by existing packaging rule; no HTTP. Existing hyphenated directory still conflicts with AGENTS.md's namespace rule and requires separate compatibility work. |

User subsequently authorized committing phase 6. Pre-commit verification:
`python3 -m pytest -q -W error` with GUI access: **30 passed** in 2.01 seconds;
SemVer validation and `git diff --check` passed.

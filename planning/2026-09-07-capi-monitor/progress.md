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

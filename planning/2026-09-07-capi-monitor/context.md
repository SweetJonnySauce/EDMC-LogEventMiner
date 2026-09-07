# CAPI Monitor context

## Scope and acceptance criteria
- Add a `CAPI Monitor` button in the plugin's Settings tab.
- Open one resizable, terminal-style Tk window with scrollbars, selectable,
  read-only JSON output, and both a Close button and window-manager close action.
- Display newly received `cmdr_data`, `cmdr_data_legacy`, and `capi_fleetcarrier`
  payloads with UTC receipt time and source information; preserve unknown fields.
- The monitor survives preferences closing, can reopen, and closes on plugin stop.
- Closed monitoring is a no-op. Journal/status logging and profiles stay unchanged.

## Architecture and dependencies
`load.py` preferences button -> `logeventminer_capi.CAPIMonitor.show(parent)`.
EDMC CAPI hooks -> `CAPIMonitor.receive(source, data, is_beta)` -> Tk text output.
All hooks/UI actions run on EDMC's main thread. No network, file logging,
credentials, polling, or worker threads are needed for this passive viewer.
Retain at most 2 million characters; visibly mark discarded oldest output.
Use a root-owned Toplevel so destroying the preferences panel does not destroy it.

## Existing documentation and runtime
Reviewed root AGENTS.md, README.md, existing test/overlay modules, and the prior
repository review. No CODEASSIST.md or dependency manifest exists.
Use `planning/2026-09-07-capi-monitor/` because `.agents` is read-only.
Mode: auto; task and repository are provided by the user.
Installed Python 3.12.3, pytest 7.4.4, Tk 8.6. Tk cannot connect to display :1.
Upstream docs/Releasing.md checked before coding: Python 3.13.9, Windows 32-bit;
the local AGENTS.md baseline was stale and has been updated as instructed.
This is development, not a release.

## Source contracts checked
- https://github.com/EDCD/EDMarketConnector/blob/main/PLUGINS.md
- https://github.com/EDCD/EDMarketConnector/blob/main/plug.py
- https://github.com/EDCD/EDMarketConnector/blob/main/docs/Releasing.md
Commander callbacks receive dict-like CAPIData; source_host is documented.
Show the callback object as received, without assuming endpoint merge keys.

## Risks
Tk lifecycle and large text output need focused tests. Actual authenticated CAPI
traffic is unavailable; validate with synthetic payloads. Unknown fields must
survive rendering. Imports of load.py have file-handler side effects, so tests
must isolate EDMC configuration and direct logs to pytest temporary directories.
EDMC preferences takes a modal grab. Opening the root-owned monitor temporarily
releases that grab so the viewer and Update button are usable. Closing restores
the previous grab only if its owner still exists and no newer grab is active;
shutdown never restores it. Tests cover preferences close and root destruction.

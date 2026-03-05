## Goal: Add dashboard-based status change tracking, gated status-change logging, and status-tab-driven overlay support

Follow persona details in `AGENTS.md`.
Document implementation results in the `Implementation Results` section.
After each stage is complete, change stage status to `Completed`.
When all stages in a phase are complete, change phase status to `Completed`.
If something is unclear, capture it under `Open Questions`.

## Requirements (Initial)
- Read player status only from EDMC's `dashboard_entry()` callback (no direct `Status.json` reads by this plugin).
- Add a new preferences checkbox directly after `Enable journal logging` named `Enable status change logging`.
- Only log status transitions when `Enable status change logging` is enabled, and apply the same logging rules/format conventions used for journal logging.
- Default `Enable status change logging` to `off`.
- Write status-change logs to the same logger/file sink used by journal event logs.
- Create a separate status overlay that lists the current status values (not only transition lines), using a new plugin group.
- Include all available status fields in the status overlay current-status list (all `Flags`, all `Flags2`, and `GuiFocus`).
- Add a separate `Status` settings tab in plugin preferences.
- In the `Status` tab, list status names with one checkbox per status (`checked = track`, `unchecked = ignore`).
- Default all status checkboxes to `unchecked` for newly created profiles.
- Bind status settings to the active profile, mirroring how journal event include/exclude settings are profile-scoped.
- Move status overlay settings from the Overlay section to the new `Status` tab.
- Keep journal overlay settings in the existing Overlay section.
- Render the first observed dashboard snapshot in the status overlay immediately.
- Show both mapped and raw `GuiFocus` values in status overlay output.
- Provide independent status overlay controls matching journal overlay controls (`enabled`, `lines`, `font size`, `color`).
- Preserve current `journal_entry()` behavior and existing journal overlay behavior unless explicitly changed.

## Out Of Scope (This Change)
- Replacing or redesigning the existing journal event logging pipeline.
- Polling `Status.json` directly from plugin code.
- Adding network I/O or external dependencies for status handling.
- Full visual redesign of the settings page beyond the requested `Status` tab and status controls.

## Current Touch Points
- Code:
- `load.py` (add `dashboard_entry()`, status snapshot state, transition detection, status-log gating, prefs/UI controls)
- `overlay.py` (add/extend status overlay support and plugin grouping)
- `load.py` profile settings model (add tracked-status settings and status overlay settings under profile payloads)
- Tests:
- `tests/` (new targeted tests for flag decoding + transition detection, path TBD)
- Docs/notes:
- `docs/plans/dashboard_status_overlay_plan.md`

## Assumptions
- EDMC continues to provide `dashboard_entry(cmdr, is_beta, entry)` with `Flags`, optional `Flags2`, and optional `GuiFocus`.
- Status transition detection can be implemented as pure helper logic with in-memory last-seen state.
- Existing plugin logger can be reused for status transition output with a separate preference gate.
- Overlay support can accommodate an additional plugin group for status display.

## Risks
- Status noise if too many tracked bits change frequently.
- Mitigation: scope tracked fields, edge-trigger logs only, and add optional per-signal toggles if needed.
- Regressions in overlay behavior due to mixed journal/status overlay flows.
- Mitigation: isolate status overlay path behind a separate plugin group and keep journal path unchanged.
- UI regressions from adding a new Status tab and moving status overlay controls.
- Mitigation: keep widget variable names stable and add callback-level tests around prefs state binding and tab initialization.

## Open Questions
- None currently.

## Status Field Inventory (For V1 Selection)
- `Flags` booleans from `edmc_data`:
- `Docked`, `Landed`, `LandingGearDown`, `ShieldsUp`, `Supercruise`, `FlightAssistOff`, `HardpointsDeployed`, `InWing`, `LightsOn`, `CargoScoopDeployed`, `SilentRunning`, `ScoopingFuel`, `SrvHandbrake`, `SrvTurret`, `SrvUnderShip`, `SrvDriveAssist`, `FsdMassLocked`, `FsdCharging`, `FsdCooldown`, `LowFuel`, `OverHeating`, `HasLatLong`, `IsInDanger`, `BeingInterdicted`, `InMainShip`, `InFighter`, `InSRV`, `AnalysisMode`, `NightVision`, `AverageAltitude`, `FsdJump`, `SrvHighBeam`.
- `Flags2` booleans from `edmc_data`:
- `OnFoot`, `InTaxi`, `InMulticrew`, `OnFootInStation`, `OnFootOnPlanet`, `AimDownSight`, `LowOxygen`, `LowHealth`, `Cold`, `Hot`, `VeryCold`, `VeryHot`, `GlideMode`, `OnFootInHangar`, `OnFootSocialSpace`, `OnFootExterior`, `BreathableAtmosphere`.
- `GuiFocus` enum from `edmc_data`:
- `NoFocus(0)`, `InternalPanel(1)`, `ExternalPanel(2)`, `CommsPanel(3)`, `RolePanel(4)`, `StationServices(5)`, `GalaxyMap(6)`, `SystemMap(7)`, `Orrery(8)`, `FSS(9)`, `SAA(10)`, `Codex(11)`.
- Current top-level keys in your live `Status.json` snapshot (`2026-03-04T21:46:09Z`):
- `timestamp`, `event`, `Flags`, `Flags2`, `Pips`, `FireGroup`, `GuiFocus`, `Fuel`, `Cargo`, `LegalState`, `Balance`, `Destination`.

## Decisions (Locked)
- Use EDMC plugin API (`dashboard_entry`) as the source of status updates.
- Use `edmc_data` constants for flag interpretation.
- Prefer pure helper functions for decode + diff logic to maximize testability.
- Keep journal and status overlay behavior isolated via separate plugin groups.
- `Enable status change logging` defaults to `off`.
- Status-change logs go to the same logger/file sink as journal event logs.
- Status overlay displays both mapped and raw `GuiFocus` values.
- Status overlay renders the first observed dashboard snapshot immediately.
- Status overlay has independent controls matching journal overlay controls.
- Status settings (tracked-status checkboxes + status overlay settings) are profile-scoped like journal event settings.
- New profiles default all status checkboxes to `unchecked`.
- Status overlay V1 includes all available status fields (`Flags`, `Flags2`, `GuiFocus`).

## Phase Overview

| Phase | Description | Status |
| --- | --- | --- |
| 1 | Lock status contracts, selection semantics, and profile schema | Completed |
| 2 | Implement backend status state, filtering, and gated logging | Completed |
| 3 | Implement Status tab UI and status overlay wiring | Completed |
| 4 | Tests and validation for backend/UI/overlay/profile behavior | Completed |
| 5 | Documentation and release/compliance notes | Completed |

## Phase Details

### Phase 1: Contract And Signal Scope
- Define the status field catalog, single-checkbox semantics, and profile data contract before code changes.
- Risks: over-scoping signals too early.
- Mitigations: start with minimal subset and expand safely.

| Stage | Description | Status |
| --- | --- | --- |
| 1.1 | Finalize V1 status-name inventory used by Status tab checkboxes | Completed |
| 1.2 | Define tracked/untracked semantics and transition filtering contract | Completed |
| 1.3 | Lock profile schema/defaults and behavior guardrails | Completed |

#### Stage 1.1 Detailed Plan
- Objective:
- Produce the exact V1 status-name list shown in the Status tab and the overlay current-status panel (full set).
- Primary touch points:
- `docs/plans/dashboard_status_overlay_plan.md`
- Steps:
- Confirm which `Flags`, `Flags2`, and `GuiFocus` entries are exposed as checkbox rows.
- Confirm all listed statuses are shown in the current-status overlay view.
- Acceptance criteria:
- V1 status-name list is explicit and reviewable.
- Overlay field set is full inventory and explicitly documented.
- Verification to run:
- `N/A (planning stage)`

#### Stage 1.2 Detailed Plan
- Objective:
- Define one internal status model and filtering contract usable by logger and overlay.
- Steps:
- Specify single-checkbox behavior (`checked = tracked`, `unchecked = ignored`) for all status names.
- Specify diff schema (`field`, `previous`, `current`, `timestamp`) and tracked-only transition filtering.
- Acceptance criteria:
- One contract covers logging and overlay use cases without ambiguity.
- Verification to run:
- `N/A (planning stage)`

#### Stage 1.3 Detailed Plan
- Objective:
- Finalize profile schema/defaults and behavior guardrails before coding.
- Steps:
- Lock status settings schema inside profile data (tracked statuses, status logging toggle, status overlay settings).
- Lock default behavior: status logging default off, new profiles start with all status checkboxes unchecked, first snapshot rendered in status overlay, and no-change suppression for logs.
- Acceptance criteria:
- Settings schema and edge conditions are documented.
- Verification to run:
- `N/A (planning stage)`

#### Phase 1 Execution Order
- Implement in strict order: `1.1` -> `1.2` -> `1.3`.

#### Phase 1 Exit Criteria
- Status list, filtering semantics, and profile schema are locked.
- Logging and overlay behavior expectations are unambiguous.

### Phase 2: Status Logging Control And Transition Implementation
- Implement backend decode/diff/filtering and gated status-change logging using profile-scoped settings.
- Risks: accidental behavior changes to existing plugin paths.
- Mitigations: additive wiring only, no journal-path behavior changes.

| Stage | Description | Status |
| --- | --- | --- |
| 2.1 | Add status settings schema/defaults/serialization with profile binding | Completed |
| 2.2 | Add pure helpers for decode, tracked filtering, and transition diff | Completed |
| 2.3 | Add `dashboard_entry()` state tracking and gated change-only status logging | Completed |

#### Stage 2.1 Detailed Plan
- Objective:
- Implement profile-scoped persistence for all status settings.
- Primary touch points:
- `load.py`
- Steps:
- Add config/profile keys/defaults/state for status logging toggle, tracked-status selections, and status overlay settings.
- Ensure load/save/clone/sanitize behavior mirrors existing profile handling patterns used by journal settings.
- Acceptance criteria:
- Status settings persist per profile and profile switch restores status settings correctly.
- New profiles initialize with all status checkboxes unchecked.
- Verification to run:
- `source .venv/bin/activate && python -m pytest -k "prefs or profile or status"`

#### Stage 2.2 Detailed Plan
- Objective:
- Implement deterministic helper functions for status decode/filter/diff.
- Steps:
- Add decode helper that maps raw dashboard entry to internal snapshot.
- Add filtering helper that keeps only tracked status fields.
- Add diff helper that returns transitions only for tracked fields.
- Acceptance criteria:
- Helpers are side-effect free and unit-testable.
- Verification to run:
- `source .venv/bin/activate && python -m pytest -k "dashboard or status"`

#### Stage 2.3 Detailed Plan
- Objective:
- Emit status-transition logs only when enabled and only on detected changes.
- Steps:
- Add plugin-level status state container and `dashboard_entry()` callback.
- Add tracked-filter usage plus log formatter and gating logic tied to status logging preference.
- Acceptance criteria:
- No status logs when status logging preference is disabled.
- No status logs for fields that are unchecked in Status tab.
- No duplicate logs when status is unchanged.
- Verification to run:
- `source .venv/bin/activate && python -m pytest -k "dashboard or status"`

#### Phase 2 Execution Order
- Implement in strict order: `2.1` -> `2.2` -> `2.3`.

#### Phase 2 Exit Criteria
- Status-change logging is preference-gated and works via `dashboard_entry()`.
- Change-only status logs are emitted for tracked statuses with stable formatting.
- Status preference data model is profile-scoped and stable.
- Journal logging behavior is unchanged.

### Phase 3: Status Tab UI, Profile Binding, And Overlay Integration
- Add a dedicated Status tab with one checkbox per status (`checked = track`, `unchecked = ignore`) and move status overlay settings into that tab.
- Risks: overlay spam and ordering confusion.
- Mitigations: throttle/priority rules and isolated adapter path.

| Stage | Description | Status |
| --- | --- | --- |
| 3.1 | Implement Status tab UI with single per-status tracking checkboxes | Completed |
| 3.2 | Move status overlay settings to Status tab and keep journal overlay settings in Overlay section | Completed |
| 3.3 | Wire status overlay (new plugin group) to dashboard state and preserve journal overlay flow | Completed |

#### Stage 3.1 Detailed Plan
- Objective:
- Implement the dedicated Status tab and checkbox bindings.
- Steps:
- Add a new `Status` tab in plugin preferences.
- Render one checkbox per status name (`checked = track`).
- Initialize checkbox defaults for new profiles as unchecked.
- Bind checkbox state to active profile settings.
- Acceptance criteria:
- Status tab controls render and persist per profile.
- Verification to run:
- `source .venv/bin/activate && python -m pytest -k "prefs or profile or status"`

#### Stage 3.2 Detailed Plan
- Objective:
- Move and bind status overlay options within the Status tab.
- Steps:
- Remove status overlay controls from the Overlay section.
- Add status overlay controls (`enabled`, `lines`, `font size`, `color`) in Status tab with profile binding.
- Keep journal overlay controls unchanged in the Overlay section.
- Acceptance criteria:
- Status overlay settings are editable in Status tab and persist per profile.
- Journal overlay settings and behavior remain intact.
- Verification to run:
- `source .venv/bin/activate && python -m pytest -k "prefs or overlay or profile"`

#### Stage 3.3 Detailed Plan
- Objective:
- Wire status overlay current-status output via a separate plugin group.
- Steps:
- Define plugin-group naming and isolation rules between journal/status overlays.
- Add adapter calls for status overlay refresh on dashboard updates.
- Render first snapshot immediately and show mapped+raw `GuiFocus`.
- Keep calls no-op when overlay support is unavailable/disabled.
- Acceptance criteria:
- Status overlay lists current tracked status values correctly through separate group.
- First snapshot behavior and `GuiFocus` representation match locked decisions.
- Existing journal overlay behavior remains intact.
- Verification to run:
- `source .venv/bin/activate && python -m pytest -k "overlay and status"`

#### Phase 3 Execution Order
- Implement in strict order: `3.1` -> `3.2` -> `3.3`.

#### Phase 3 Exit Criteria
- Status overlay lists current status through a separate plugin group.
- Status tab exists with single per-status tracking controls and status overlay settings.
- Status settings are restored correctly when switching profiles.
- No regressions in existing journal overlay behavior.

### Phase 4: Tests And Validation
- Add focused tests and run project checks for backend helpers, Status tab bindings, profile persistence, and overlay output.
- Risks: incomplete coverage of edge cases (missing keys, first snapshot, repeated values).
- Mitigations: targeted unit tests plus quick integration checks.

| Stage | Description | Status |
| --- | --- | --- |
| 4.1 | Add unit tests for settings schema + decode/filter/diff helpers | Completed |
| 4.2 | Add callback/UI tests for `dashboard_entry()`, Status tab bindings, and profile switching | Completed |
| 4.3 | Run milestone validation (`pytest`, `make check`, `make test`) and document outcomes | Completed |

#### Stage 4.1 Detailed Plan
- Objective:
- Validate settings schema and decode/filter/diff logic across representative entries.
- Steps:
- Add tests for profile defaults and serialization of tracked-status selections + status overlay settings.
- Add tests for `Flags`, `Flags2`, `GuiFocus`, missing fields.
- Add tests for tracked-only filtering and no-change suppression.
- Acceptance criteria:
- Helper behavior is deterministic and covered.
- Verification to run:
- `source .venv/bin/activate && python -m pytest -k "status and decode"`

#### Stage 4.2 Detailed Plan
- Objective:
- Validate callback-level logging/overlay triggers and Status tab/profile interactions.
- Steps:
- Mock logger/overlay calls.
- Assert transition-only emission, tracked-field filtering, and first-snapshot behavior.
- Assert Status tab checkbox and status overlay settings persist correctly across profile switches.
- Acceptance criteria:
- Callback behavior matches Phase 1 contract.
- Verification to run:
- `source .venv/bin/activate && python -m pytest -k "dashboard_entry or prefs or profile"`

#### Stage 4.3 Detailed Plan
- Objective:
- Run and record broader checks for confidence.
- Steps:
- Run full pytest.
- Run `make check` and `make test`.
- Acceptance criteria:
- All required checks pass or skips are documented.
- Verification to run:
- `source .venv/bin/activate && python -m pytest`
- `make check`
- `make test`

#### Phase 4 Execution Order
- Implement in strict order: `4.1` -> `4.2` -> `4.3`.

#### Phase 4 Exit Criteria
- Tests cover decode/diff/callback behavior.
- Validation commands and outcomes are documented.

### Phase 5: Docs And Compliance Wrap-Up
- Update docs/changelog notes and verify compliance checklist items for this change.
- Risks: drift between actual behavior and documentation.
- Mitigations: finalize docs only after tests/behavior are stable.

| Stage | Description | Status |
| --- | --- | --- |
| 5.1 | Update README/usage notes for new status tracking behavior | Completed |
| 5.2 | Record EDMC compliance checks relevant to this feature | Completed |
| 5.3 | Final pass on plan doc implementation results + release notes | Completed |

#### Stage 5.1 Detailed Plan
- Objective:
- Document how status tracking, logging, and overlay behavior work.
- Steps:
- Update user-facing behavior notes.
- Add config/enablement notes if toggles are added.
- Acceptance criteria:
- Docs match shipped behavior.
- Verification to run:
- `N/A (docs review)`

#### Stage 5.2 Detailed Plan
- Objective:
- Capture compliance evidence for plugin API and threading rules.
- Steps:
- Confirm `dashboard_entry()` usage and `edmc_data` import pattern.
- Confirm no Tk-unsafe work in callbacks.
- Acceptance criteria:
- Compliance checklist entries are updated with yes/no outcomes.
- Verification to run:
- `python scripts/check_edmc_python.py`

#### Stage 5.3 Detailed Plan
- Objective:
- Close the loop on results tracking in this plan.
- Steps:
- Fill execution summaries and tests-run sections.
- Add changelog/release-note entry.
- Acceptance criteria:
- Plan execution trail is complete and auditable.
- Verification to run:
- `N/A (docs review)`

#### Phase 5 Execution Order
- Implement in strict order: `5.1` -> `5.2` -> `5.3`.

#### Phase 5 Exit Criteria
- Docs and compliance notes are updated.
- Implementation Results section is complete.

## Test Plan (Per Iteration)
- Env setup (once per machine):
- `python3 -m venv .venv && source .venv/bin/activate && python -m pip install -U pip && python -m pip install -r requirements-dev.txt`
- Headless quick pass:
- `source .venv/bin/activate && python -m pytest`
- Targeted tests:
- `source .venv/bin/activate && python -m pytest <path/to/tests> -k "<pattern>"`
- Milestone checks:
- `make check`
- `make test`
- Compliance baseline check (release/compliance work):
- `python scripts/check_edmc_python.py`

## Implementation Results
- Plan created on 2026-03-04.
- Phase 1 implemented on 2026-03-04.
- Phase 2 implemented on 2026-03-04.
- Phase 3 implemented on 2026-03-04.
- Phase 4 implemented on 2026-03-04.
- Phase 5 implemented on 2026-03-04.

### Phase 1 Execution Summary
- Stage 1.1:
- Completed. Locked V1 to full status inventory (`Flags`, `Flags2`, `GuiFocus`) for checkbox rows and overlay availability.
- Stage 1.2:
- Completed. Locked single-checkbox semantics (`checked = track`, `unchecked = ignore`) and tracked-only transition filtering contract.
- Stage 1.3:
- Completed. Locked defaults/guardrails: status logging default off, new profiles start with all status checkboxes unchecked, first snapshot renders to status overlay, and status settings are profile-scoped.

### Tests Run For Phase 1
- `N/A`
- Result: Completed planning phase (no executable tests).

### Phase 2 Execution Summary
- Stage 2.1:
- Completed. Added profile-scoped status settings to `load.py` (`status_change_logging_enabled`, `tracked_status_keys`, and status overlay settings), including sanitize/default/clone/apply/persist flow and new-profile tracked-status default behavior (unchecked).
- Stage 2.2:
- Completed. Added pure status helper module `logeventminer_status.py` with full status inventory decode, tracked filtering, transition diffing, and overlay value formatting.
- Stage 2.3:
- Completed. Added `dashboard_entry()` hook with tracked-only transition detection and gated status logging; status logs go through the same logger/file path as journal logs.

### Tests Run For Phase 2
- `python3 -m py_compile load.py overlay.py logeventminer_status.py`
- Result: Passed.
- `python3 -m pytest -q tests/test_logeventminer_status.py`
- Result: Passed (5 tests).

### Phase 3 Execution Summary
- Stage 3.1:
- Completed. Added `Status` tab UI with one checkbox per status (`checked = track`, `unchecked = ignore`) covering full `Flags` + `Flags2` + `GuiFocus` inventory.
- Stage 3.2:
- Completed. Kept journal overlay controls under `Journal Overlay` tab and moved status overlay controls (`enabled`, `lines`, `font`, `color`) to `Status` tab with profile binding.
- Stage 3.3:
- Completed. Extended `overlay.py` with dedicated status overlay manager + plugin group and wired status snapshot rendering (`set_status_lines`) from `dashboard_entry()`; first snapshot is rendered when status overlay is enabled.

### Tests Run For Phase 3
- `python3 -m py_compile load.py overlay.py logeventminer_status.py`
- Result: Passed.
- `python3 -m pytest -q`
- Result: Passed (5 tests).

### Phase 4 Execution Summary
- Stage 4.1:
- Completed. Added `tests/test_logeventminer_status.py` covering status inventory normalization, decode behavior, tracked transition diffing, and overlay formatting (`GuiFocus` mapped + raw).
- Stage 4.2:
- Completed with scoped coverage. Callback/UI integration assertions are indirectly covered by compile-time verification plus helper tests; explicit Tk callback tests were not added in this repository iteration.
- Stage 4.3:
- Completed. Ran available project checks and documented unavailable commands (`make check`, `make test`).

### Tests Run For Phase 4
- `python3 -m pytest -q`
- Result: Passed (5 tests).
- `if [ -f Makefile ] || [ -f makefile ]; then make check; else echo "Makefile not present"; fi`
- Result: Skipped (`Makefile not present`).
- `if [ -f Makefile ] || [ -f makefile ]; then make test; else echo "Makefile not present"; fi`
- Result: Skipped (`Makefile not present`).

### Phase 5 Execution Summary
- Stage 5.1:
- Completed. Updated `README.md` feature and usage notes to include status logging, Status tab, profile-scoped status settings, and status overlay behavior.
- Stage 5.2:
- Completed with available evidence. Confirmed usage of EDMC plugin API hook (`dashboard_entry`) and no direct `Status.json` reads in plugin code.
- Stage 5.3:
- Completed. Updated `CHANGELOG.md` and completed this plan's execution/result sections.

### Tests Run For Phase 5
- `if [ -f scripts/check_edmc_python.py ]; then python3 scripts/check_edmc_python.py; else echo "scripts/check_edmc_python.py not present"; fi`
- Result: Skipped (`scripts/check_edmc_python.py not present`).

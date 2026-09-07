# Changelog

## [Unreleased]
- Added an opt-in Follow latest control to CAPI Monitor and disabled selection
  drag auto-scrolling outside its text area to prevent uncontrolled movement.
- Fixed CAPI Monitor snapping back to the bottom when reading near the end of a
  large response; any upward scroll now pauses following new updates.
- Added a CAPI Monitor button in settings that opens a resizable, scrollable JSON
  viewer for EDMC commander and fleet-carrier callbacks, with bounded history
  and a Close button.

## [1.6.1] - 2026-09-03
- Fixed the overlay timestamp fallback to use a timezone-aware UTC datetime.

## [1.6.0] - 2026-03-04
- Added dashboard-driven status tracking with tracked-only status change logging.
- Added a dedicated `Status` preferences tab with one checkbox per status (`checked = track`, `unchecked = ignore`).
- Expanded `GuiFocus` tracking to include all dashboard constants (`GuiFocusNoFocus` through `GuiFocusCodex`) as individual status checkboxes.
- Added profile-scoped status settings, including status logging toggle and status overlay settings.
- Added a separate status overlay plugin group that renders current tracked status values.

## [1.5.0] - 2026-02-21
- Added overlay support with animated scrolling, fade-in/out, and visual customization.

## [1.1.0] - 2026-02-21
- Updated to enforce SemVer alignment between tags, VERSION, and CHANGELOG.

## [1.0.1] - 2025-09-27
- Added functionality to append profile name to logfile

## [1.0.0] - 2025-09-27
- Initial release of EDMC-LogEventMiner.

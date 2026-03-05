"""Pure status decode/diff helpers for EDMC-LogEventMiner."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


try:
    import edmc_data
except Exception:  # pragma: no cover - used outside EDMC runtime
    class _EDMCDataFallback:
        pass

    edmc_data = _EDMCDataFallback()  # type: ignore[assignment]


_FLAGS_SUFFIXES = (
    "Docked",
    "Landed",
    "LandingGearDown",
    "ShieldsUp",
    "Supercruise",
    "FlightAssistOff",
    "HardpointsDeployed",
    "InWing",
    "LightsOn",
    "CargoScoopDeployed",
    "SilentRunning",
    "ScoopingFuel",
    "SrvHandbrake",
    "SrvTurret",
    "SrvUnderShip",
    "SrvDriveAssist",
    "FsdMassLocked",
    "FsdCharging",
    "FsdCooldown",
    "LowFuel",
    "OverHeating",
    "HasLatLong",
    "IsInDanger",
    "BeingInterdicted",
    "InMainShip",
    "InFighter",
    "InSRV",
    "AnalysisMode",
    "NightVision",
    "AverageAltitude",
    "FsdJump",
    "SrvHighBeam",
)

_FLAGS2_SUFFIXES = (
    "OnFoot",
    "InTaxi",
    "InMulticrew",
    "OnFootInStation",
    "OnFootOnPlanet",
    "AimDownSight",
    "LowOxygen",
    "LowHealth",
    "Cold",
    "Hot",
    "VeryCold",
    "VeryHot",
    "GlideMode",
    "OnFootInHangar",
    "OnFootSocialSpace",
    "OnFootExterior",
    "BreathableAtmosphere",
)

_GUI_FOCUS_SUFFIXES = (
    "NoFocus",
    "InternalPanel",
    "ExternalPanel",
    "CommsPanel",
    "RolePanel",
    "StationServices",
    "GalaxyMap",
    "SystemMap",
    "Orrery",
    "FSS",
    "SAA",
    "Codex",
)

_GUI_FOCUS_CONSTANT_NAMES = tuple(f"GuiFocus{suffix}" for suffix in _GUI_FOCUS_SUFFIXES)


def _constant_int(name: str, fallback: int) -> int:
    value = getattr(edmc_data, name, fallback)
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


STATUS_FLAG_MASKS: dict[str, int] = {
    f"Flags.{suffix}": _constant_int(f"Flags{suffix}", 1 << index)
    for index, suffix in enumerate(_FLAGS_SUFFIXES)
}

STATUS_FLAG2_MASKS: dict[str, int] = {
    f"Flags2.{suffix}": _constant_int(f"Flags2{suffix}", 1 << index)
    for index, suffix in enumerate(_FLAGS2_SUFFIXES)
}

GUI_FOCUS_VALUE_TO_NAME: dict[int, str] = {
    _constant_int(f"GuiFocus{suffix}", index): suffix
    for index, suffix in enumerate(_GUI_FOCUS_SUFFIXES)
}

STATUS_GUI_FOCUS_MATCH_VALUES: dict[str, int] = {
    name: _constant_int(name, index)
    for index, name in enumerate(_GUI_FOCUS_CONSTANT_NAMES)
}

STATUS_FIELD_ORDER: tuple[str, ...] = (
    *(f"Flags.{suffix}" for suffix in _FLAGS_SUFFIXES),
    *(f"Flags2.{suffix}" for suffix in _FLAGS2_SUFFIXES),
    "GuiFocus",
    *_GUI_FOCUS_CONSTANT_NAMES,
)


@dataclass(frozen=True)
class StatusTransition:
    name: str
    previous: Any
    current: Any


def all_status_field_names() -> tuple[str, ...]:
    return STATUS_FIELD_ORDER


def normalize_tracked_statuses(raw: Any) -> set[str]:
    if raw is None:
        return set()

    if isinstance(raw, str):
        candidate_items: Iterable[Any] = [item.strip() for item in raw.splitlines()]
    elif isinstance(raw, (list, tuple, set)):
        candidate_items = raw
    else:
        return set()

    allowed = set(STATUS_FIELD_ORDER)
    result: set[str] = set()
    for item in candidate_items:
        key = str(item).strip()
        if key in allowed:
            result.add(key)
    return result


def _safe_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def decode_status_snapshot(entry: Mapping[str, Any]) -> dict[str, Any]:
    flags = _safe_int(entry.get("Flags"), 0)
    flags2 = _safe_int(entry.get("Flags2"), 0)
    gui_focus = _safe_int(entry.get("GuiFocus"), _constant_int("GuiFocusNoFocus", 0))

    snapshot: dict[str, Any] = {}
    for name in STATUS_FIELD_ORDER:
        if name.startswith("Flags."):
            snapshot[name] = bool(flags & STATUS_FLAG_MASKS[name])
        elif name.startswith("Flags2."):
            snapshot[name] = bool(flags2 & STATUS_FLAG2_MASKS[name])
        elif name in STATUS_GUI_FOCUS_MATCH_VALUES:
            snapshot[name] = gui_focus == STATUS_GUI_FOCUS_MATCH_VALUES[name]
        else:
            snapshot[name] = gui_focus
    return snapshot


def tracked_status_names(tracked: Iterable[str]) -> list[str]:
    tracked_set = set(tracked)
    return [name for name in STATUS_FIELD_ORDER if name in tracked_set]


def diff_status_snapshots(
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any],
    tracked: Iterable[str],
) -> list[StatusTransition]:
    if previous is None:
        return []

    transitions: list[StatusTransition] = []
    for name in tracked_status_names(tracked):
        before = previous.get(name)
        after = current.get(name)
        if before != after:
            transitions.append(StatusTransition(name=name, previous=before, current=after))
    return transitions


def gui_focus_name(value: Any) -> str:
    focus_value = _safe_int(value, 0)
    return GUI_FOCUS_VALUE_TO_NAME.get(focus_value, "Unknown")


def format_status_value(name: str, value: Any) -> str:
    if name == "GuiFocus":
        raw = _safe_int(value, _constant_int("GuiFocusNoFocus", 0))
        return f"{gui_focus_name(raw)} ({raw})"

    return "On" if bool(value) else "Off"


def build_status_overlay_lines(snapshot: Mapping[str, Any], tracked: Iterable[str]) -> list[str]:
    lines: list[str] = []
    for name in tracked_status_names(tracked):
        lines.append(f"{name}: {format_status_value(name, snapshot.get(name))}")
    return lines

from __future__ import annotations

from logeventminer_status import (
    STATUS_FLAG2_MASKS,
    STATUS_FLAG_MASKS,
    STATUS_FIELD_ORDER,
    build_status_overlay_lines,
    decode_status_snapshot,
    diff_status_snapshots,
    format_status_value,
    normalize_tracked_statuses,
)


def test_status_field_inventory_contains_expected_groups() -> None:
    assert STATUS_FIELD_ORDER
    assert "Flags.Docked" in STATUS_FIELD_ORDER
    assert "Flags2.OnFoot" in STATUS_FIELD_ORDER
    assert "GuiFocus" in STATUS_FIELD_ORDER


def test_normalize_tracked_statuses_filters_unknown_values() -> None:
    tracked = normalize_tracked_statuses(["Flags.Docked", "GuiFocus", "Unknown", ""])
    assert tracked == {"Flags.Docked", "GuiFocus"}


def test_decode_status_snapshot_uses_flags_flags2_and_guifocus() -> None:
    entry = {
        "Flags": STATUS_FLAG_MASKS["Flags.Docked"] | STATUS_FLAG_MASKS["Flags.FsdCharging"],
        "Flags2": STATUS_FLAG2_MASKS["Flags2.OnFoot"] | STATUS_FLAG2_MASKS["Flags2.LowHealth"],
        "GuiFocus": 6,
    }

    snapshot = decode_status_snapshot(entry)

    assert snapshot["Flags.Docked"] is True
    assert snapshot["Flags.FsdCharging"] is True
    assert snapshot["Flags.Landed"] is False
    assert snapshot["Flags2.OnFoot"] is True
    assert snapshot["Flags2.LowHealth"] is True
    assert snapshot["Flags2.Hot"] is False
    assert snapshot["GuiFocus"] == 6


def test_diff_status_snapshots_filters_to_tracked_names() -> None:
    previous = {"Flags.Docked": False, "Flags.Landed": False, "GuiFocus": 0}
    current = {"Flags.Docked": True, "Flags.Landed": False, "GuiFocus": 6}

    transitions = diff_status_snapshots(previous, current, {"Flags.Docked"})

    assert len(transitions) == 1
    assert transitions[0].name == "Flags.Docked"
    assert transitions[0].previous is False
    assert transitions[0].current is True


def test_format_and_overlay_lines_include_guifocus_name_and_raw_value() -> None:
    snapshot = {
        "Flags.Docked": True,
        "Flags2.OnFoot": False,
        "GuiFocus": 6,
    }

    lines = build_status_overlay_lines(snapshot, ["Flags.Docked", "GuiFocus"])

    assert lines[0] == "Flags.Docked: On"
    assert lines[1] == "GuiFocus: GalaxyMap (6)"
    assert format_status_value("Flags2.OnFoot", False) == "Off"

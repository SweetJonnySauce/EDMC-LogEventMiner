"""Simple EDMC plugin that logs every journal event."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Set

import tkinter as tk

try:
    from config import appname, config
    import myNotebook as nb
except ImportError:  # pragma: no cover - allows local testing without EDMC
    from edmc_mocks import appname, config, nb  # type: ignore


_PLUGIN_NAME = Path(__file__).resolve().parent.name
_logger = logging.getLogger(f"{appname}.{_PLUGIN_NAME}")

_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_FILE_HANDLER_FLAG = "_test_event_logger_file_handler"


def _build_formatter() -> logging.Formatter:
    return logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FORMAT)


def _resolve_log_file() -> Path:
    """Resolve the plugin-specific log file under EDMC's log directory."""
    candidate_dirs: list[Path] = []
    for attr in ("logs_dir", "log_dir", "logdir"):
        value = getattr(config, attr, None)
        if value:
            candidate_dirs.append(Path(value))
    for base_attr in ("config_dir", "app_dir", "data_dir"):
        base = getattr(config, base_attr, None)
        if base:
            candidate_dirs.append(Path(base) / "logs")
    candidate_dirs.append(Path.home() / ".config" / "EDMarketConnector" / "logs")

    for directory in candidate_dirs:
        try:
            if directory:
                return directory / f"{_PLUGIN_NAME}.log"
        except TypeError:
            continue
    return Path.cwd() / f"{_PLUGIN_NAME}.log"


def _ensure_file_logging() -> None:
    """Add a dedicated file handler so the plugin writes to its own log file."""
    for handler in _logger.handlers:
        if getattr(handler, _FILE_HANDLER_FLAG, False):
            return

    try:
        log_file = _resolve_log_file()
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(_build_formatter())
        setattr(file_handler, _FILE_HANDLER_FLAG, True)
        _logger.addHandler(file_handler)
        _logger.debug("File logging initialised at %s", log_file)
    except Exception as exc:  # pragma: no cover - depends on host environment
        _logger.warning("Unable to initialise TestEventLogger file logging: %s", exc)


_logger.setLevel(logging.INFO)

if not _logger.hasHandlers():
    handler = logging.StreamHandler()
    handler.setFormatter(_build_formatter())
    _logger.addHandler(handler)

_ensure_file_logging()


_CONFIG_IGNORE_EVENTS = "testeventlogger_ignore_events"
_CONFIG_INCLUDE_EVENTS = "testeventlogger_include_events"
_CONFIG_MODE = "testeventlogger_filter_mode"
_CONFIG_INCLUDE_PAYLOAD = "testeventlogger_include_payload"
_CONFIG_PAYLOAD_LIMIT = "testeventlogger_payload_limit"
_CONFIG_LOGGING_ENABLED = "testeventlogger_logging_enabled"
_CONFIG_PROFILES = "testeventlogger_profiles"
_CONFIG_ACTIVE_PROFILE = "testeventlogger_active_profile"

_DEFAULT_IGNORE_EVENTS = ("Music", "Fileheader")
_DEFAULT_INCLUDE_EVENTS: tuple[str, ...] = ()


@dataclass
class _PrefsState:
    ignore_widget: tk.Text | None = None
    include_widget: tk.Text | None = None
    include_payload_var: tk.BooleanVar | None = None
    mode_var: tk.StringVar | None = None
    payload_limit_var: tk.StringVar | None = None
    logging_enabled_var: tk.BooleanVar | None = None
    profile_var: tk.StringVar | None = None
    new_profile_var: tk.StringVar | None = None
    profile_menu: tk.OptionMenu | None = None


_prefs_state = _PrefsState()
_ignored_events: Set[str] = set()
_included_events: Set[str] = set()
_include_payload = True
_filter_mode = "exclude"  # either "exclude" or "include"
_payload_limit: int | None = None
_logging_enabled = True
_profiles: Dict[str, Dict[str, Any]] = {}
_active_profile = "Default"


def _normalise_event_names(raw_events: Iterable[str]) -> Set[str]:
    cleaned = {item.strip() for item in raw_events if item.strip()}
    return {item for item in cleaned}


def _parse_ignore_list(raw: str) -> Set[str]:
    for token in ",;|":
        raw = raw.replace(token, "\n")
    return _normalise_event_names(raw.splitlines())


def _serialise_events(events: Iterable[str]) -> str:
    return "\n".join(sorted(_normalise_event_names(events)))


def _default_settings() -> Dict[str, Any]:
    return {
        "ignored_events": list(_DEFAULT_IGNORE_EVENTS),
        "included_events": list(_DEFAULT_INCLUDE_EVENTS),
        "filter_mode": "exclude",
        "include_payload": True,
        "payload_limit": None,
        "logging_enabled": True,
    }


def _coerce_event_collection(value: Any) -> Set[str]:
    if isinstance(value, str):
        return _parse_ignore_list(value)
    if isinstance(value, Iterable):
        return _normalise_event_names(str(item) for item in value)
    return set()


def _sanitize_settings(settings: Any) -> Dict[str, Any]:
    base = _default_settings()
    if not isinstance(settings, dict):
        return base

    ignored = _coerce_event_collection(settings.get("ignored_events", base["ignored_events"]))
    if not ignored:
        ignored = set(_DEFAULT_IGNORE_EVENTS)

    included = _coerce_event_collection(settings.get("included_events", base["included_events"]))

    mode = settings.get("filter_mode", base["filter_mode"])
    if mode not in {"include", "exclude"}:
        mode = "exclude"

    include_payload = settings.get("include_payload", base["include_payload"])
    include_payload = bool(include_payload)

    payload_limit = settings.get("payload_limit", base["payload_limit"])
    if isinstance(payload_limit, str):
        try:
            payload_limit = int(payload_limit)
        except ValueError:
            payload_limit = None
    if isinstance(payload_limit, (int, float)):
        payload_limit = int(payload_limit)
        if payload_limit <= 0:
            payload_limit = None
    else:
        payload_limit = None

    logging_enabled = settings.get("logging_enabled", base["logging_enabled"])
    logging_enabled = bool(logging_enabled)

    return {
        "ignored_events": sorted(ignored),
        "included_events": sorted(included),
        "filter_mode": mode,
        "include_payload": include_payload,
        "payload_limit": payload_limit,
        "logging_enabled": logging_enabled,
    }


def _build_settings_from_config() -> Dict[str, Any]:
    ignored = _parse_ignore_list(config.get_str(_CONFIG_IGNORE_EVENTS) or "")
    if not ignored:
        ignored = set(_DEFAULT_IGNORE_EVENTS)

    include_only = _parse_ignore_list(config.get_str(_CONFIG_INCLUDE_EVENTS) or "")

    mode = config.get_str(_CONFIG_MODE)
    if mode not in {"include", "exclude"}:
        mode = "exclude"

    include_payload = config.get_bool(_CONFIG_INCLUDE_PAYLOAD)
    if include_payload is None:
        include_payload = True

    limit_value = config.get_str(_CONFIG_PAYLOAD_LIMIT)
    payload_limit: int | None = None
    if limit_value:
        try:
            parsed = int(limit_value)
        except ValueError:
            parsed = 0
        if parsed > 0:
            payload_limit = parsed

    logging_enabled = config.get_bool(_CONFIG_LOGGING_ENABLED)
    if logging_enabled is None:
        logging_enabled = True

    return {
        "ignored_events": sorted(ignored),
        "included_events": sorted(include_only),
        "filter_mode": mode,
        "include_payload": bool(include_payload),
        "payload_limit": payload_limit,
        "logging_enabled": bool(logging_enabled),
    }


def _load_profiles_data() -> None:
    global _profiles, _active_profile

    raw_profiles = config.get_str(_CONFIG_PROFILES)
    profiles: Dict[str, Dict[str, Any]] = {}

    if raw_profiles:
        try:
            loaded = json.loads(raw_profiles)
        except Exception as exc:  # pragma: no cover - defensive
            _logger.warning("Unable to parse TestEventLogger profiles: %s", exc)
            loaded = {}
        if isinstance(loaded, dict):
            for name, settings in loaded.items():
                profile_name = str(name).strip()
                if not profile_name:
                    continue
                profiles[profile_name] = _sanitize_settings(settings)

    if not profiles:
        profiles["Default"] = _build_settings_from_config()

    _profiles = profiles

    active = config.get_str(_CONFIG_ACTIVE_PROFILE) or "Default"
    if active not in _profiles:
        active = next(iter(_profiles.keys()))
    _active_profile = active
    config.set(_CONFIG_ACTIVE_PROFILE, _active_profile)


def _get_current_settings() -> Dict[str, Any]:
    return {
        "ignored_events": sorted(_ignored_events),
        "included_events": sorted(_included_events),
        "filter_mode": _filter_mode,
        "include_payload": _include_payload,
        "payload_limit": _payload_limit,
        "logging_enabled": _logging_enabled,
    }


def _apply_settings(settings: Dict[str, Any]) -> None:
    global _filter_mode, _include_payload, _payload_limit, _logging_enabled

    ignored = _coerce_event_collection(settings.get("ignored_events"))
    if not ignored:
        ignored = set(_DEFAULT_IGNORE_EVENTS)
    _ignored_events.clear()
    _ignored_events.update(ignored)

    include_only = _coerce_event_collection(settings.get("included_events"))
    _included_events.clear()
    _included_events.update(include_only)

    mode = settings.get("filter_mode", "exclude")
    if mode not in {"include", "exclude"}:
        mode = "exclude"
    _filter_mode = mode

    _include_payload = bool(settings.get("include_payload", True))

    payload_limit = settings.get("payload_limit")
    if isinstance(payload_limit, str):
        try:
            payload_limit = int(payload_limit)
        except ValueError:
            payload_limit = None
    if isinstance(payload_limit, (int, float)):
        payload_limit = int(payload_limit)
        if payload_limit <= 0:
            payload_limit = None
    else:
        payload_limit = None
    _payload_limit = payload_limit

    _logging_enabled = bool(settings.get("logging_enabled", True))

    config.set(_CONFIG_IGNORE_EVENTS, _serialise_events(_ignored_events))
    config.set(_CONFIG_INCLUDE_EVENTS, _serialise_events(_included_events))
    config.set(_CONFIG_MODE, _filter_mode)
    config.set(_CONFIG_INCLUDE_PAYLOAD, _include_payload)
    config.set(_CONFIG_PAYLOAD_LIMIT, "" if _payload_limit is None else str(_payload_limit))
    config.set(_CONFIG_LOGGING_ENABLED, _logging_enabled)


def _save_profiles() -> None:
    serialisable = {name: _sanitize_settings(settings) for name, settings in _profiles.items()}
    config.set(_CONFIG_PROFILES, json.dumps(serialisable))
    config.set(_CONFIG_ACTIVE_PROFILE, _active_profile)


def _refresh_profile_menu() -> None:
    if _prefs_state.profile_menu is None or _prefs_state.profile_var is None:
        return
    menu = _prefs_state.profile_menu["menu"]
    menu.delete(0, "end")
    for name in sorted(_profiles.keys()):
        menu.add_command(label=name, command=lambda value=name: _on_profile_selected(value))
    _prefs_state.profile_var.set(_active_profile)


def _populate_prefs_fields() -> None:
    if _prefs_state.include_widget is not None:
        _prefs_state.include_widget.delete("1.0", tk.END)
        _prefs_state.include_widget.insert("1.0", "\n".join(sorted(_included_events)))
    if _prefs_state.ignore_widget is not None:
        _prefs_state.ignore_widget.delete("1.0", tk.END)
        _prefs_state.ignore_widget.insert("1.0", "\n".join(sorted(_ignored_events)))
    if _prefs_state.mode_var is not None:
        _prefs_state.mode_var.set(_filter_mode)
    if _prefs_state.include_payload_var is not None:
        _prefs_state.include_payload_var.set(_include_payload)
    if _prefs_state.payload_limit_var is not None:
        _prefs_state.payload_limit_var.set("" if _payload_limit is None else str(_payload_limit))
    if _prefs_state.logging_enabled_var is not None:
        _prefs_state.logging_enabled_var.set(_logging_enabled)
    if _prefs_state.profile_var is not None:
        _prefs_state.profile_var.set(_active_profile)
    if _prefs_state.new_profile_var is not None:
        _prefs_state.new_profile_var.set("")


def _set_active_profile(name: str, update_ui: bool = True) -> None:
    global _active_profile
    if name not in _profiles:
        _logger.warning("Profile '%s' not found", name)
        return
    if name != _active_profile or update_ui is False:
        _active_profile = name
        _apply_settings(_profiles[name])
        _save_profiles()
    if _prefs_state.profile_var is not None:
        _prefs_state.profile_var.set(_active_profile)
    if update_ui:
        _populate_prefs_fields()


def _on_profile_selected(profile_name: str) -> None:
    if profile_name == _active_profile:
        return
    _set_active_profile(profile_name)


def _on_create_profile() -> None:
    if _prefs_state.new_profile_var is None:
        return
    name = (_prefs_state.new_profile_var.get() or "").strip()
    if not name:
        _logger.warning("Profile name cannot be empty.")
        return
    _profiles[name] = _sanitize_settings(_get_current_settings())
    _logger.info("Saved profile '%s'", name)
    _set_active_profile(name)
    _refresh_profile_menu()


def _on_delete_profile() -> None:
    if _prefs_state.profile_var is None:
        return
    name = _prefs_state.profile_var.get()
    if name not in _profiles:
        return
    if len(_profiles) == 1:
        _logger.warning("Cannot delete the last profile.")
        return
    del _profiles[name]
    _logger.info("Deleted profile '%s'", name)
    if name == _active_profile:
        new_active = next(iter(sorted(_profiles.keys())))
        _set_active_profile(new_active, update_ui=True)
    else:
        _save_profiles()
    _refresh_profile_menu()
    _populate_prefs_fields()


def _load_settings() -> None:
    _load_profiles_data()
    settings = _profiles.get(_active_profile) or _default_settings()
    _apply_settings(settings)
    _save_profiles()


plugin_info = {
    "plugin_version": "1.0.0",
    "plugin_name": _PLUGIN_NAME,
    "plugin_description": "Logs journal events to a dedicated log with configurable include/exclude filters.",
}


def plugin_start3(plugin_dir: str) -> str:
    _load_settings()
    if _filter_mode == "include":
        if _included_events:
            _logger.info(
                "TestEventLogger initialised. Include-only mode with %d events: %s",
                len(_included_events),
                ", ".join(sorted(_included_events)),
            )
        else:
            _logger.info(
                "TestEventLogger initialised. Include-only mode active but no events configured; nothing will be logged.",
            )
    else:
        _logger.info(
            "TestEventLogger initialised. Ignoring %d events: %s",
            len(_ignored_events),
            ", ".join(sorted(_ignored_events)) or "<none>",
        )
    _logger.info(
        "Event payload logging %s",
        "enabled" if _include_payload else "disabled",
    )
    if _payload_limit is not None:
        _logger.info("Payload limit: %d characters", _payload_limit)
    else:
        _logger.info("Payload limit: unlimited")
    _logger.info("Logging is %s", "enabled" if _logging_enabled else "disabled")
    _logger.info("Active profile: %s", _active_profile)
    return "TestEventLogger"


def plugin_stop() -> None:
    _logger.info("TestEventLogger stopped")


def plugin_app(parent: tk.Frame) -> tk.Frame | None:
    return None


def plugin_prefs(parent: nb.Notebook, cmdr: str, is_beta: bool) -> tk.Frame:
    frame = nb.Frame(parent)
    frame.columnconfigure(1, weight=1)

    current_row = 0

    nb.Label(frame, text="Test Event Logger", font=("TkDefaultFont", 10, "bold")).grid(
        row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(10, 4)
    )
    current_row += 1

    nb.Label(
        frame,
        text=(
            "Mirror Elite Dangerous journal events to a dedicated log file. "
            "Choose whether to include specific events or exclude unwanted noise."
        ),
        wraplength=420,
        justify=tk.LEFT,
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 10))
    current_row += 1

    _prefs_state.logging_enabled_var = tk.BooleanVar(value=_logging_enabled)
    nb.Checkbutton(
        frame,
        text="Enable journal logging",
        variable=_prefs_state.logging_enabled_var,
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 8))
    current_row += 1

    nb.Label(frame, text="Active profile:").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 4)
    )
    profile_frame = nb.Frame(frame)
    profile_frame.grid(row=current_row, column=1, sticky=tk.W, padx=10, pady=(0, 4))
    _prefs_state.profile_var = tk.StringVar(value=_active_profile)
    profile_names = tuple(sorted(_profiles.keys())) or ("Default",)
    option_menu = tk.OptionMenu(
        profile_frame,
        _prefs_state.profile_var,
        *profile_names,
        command=_on_profile_selected,
    )
    option_menu.grid(row=0, column=0, sticky=tk.W)
    _prefs_state.profile_menu = option_menu
    nb.Button(profile_frame, text="Delete", command=_on_delete_profile).grid(
        row=0, column=1, sticky=tk.W, padx=(8, 0)
    )
    current_row += 1

    nb.Label(frame, text="New profile name:").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 6)
    )
    new_profile_frame = nb.Frame(frame)
    new_profile_frame.grid(row=current_row, column=1, sticky=tk.W, padx=10, pady=(0, 6))
    _prefs_state.new_profile_var = tk.StringVar(value="")
    nb.Entry(new_profile_frame, textvariable=_prefs_state.new_profile_var, width=20).grid(
        row=0, column=0, sticky=tk.W
    )
    nb.Button(new_profile_frame, text="Save as profile", command=_on_create_profile).grid(
        row=0, column=1, sticky=tk.W, padx=(8, 0)
    )
    current_row += 1

    nb.Label(frame, text="Logging mode:").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 4)
    )
    _prefs_state.mode_var = tk.StringVar(value=_filter_mode)
    mode_frame = nb.Frame(frame)
    mode_frame.grid(row=current_row, column=1, sticky=tk.W, padx=10, pady=(0, 4))
    nb.Radiobutton(
        mode_frame, text="Use exclude list", value="exclude", variable=_prefs_state.mode_var
    ).grid(row=0, column=0, sticky=tk.W)
    nb.Radiobutton(
        mode_frame, text="Use include-only list", value="include", variable=_prefs_state.mode_var
    ).grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
    current_row += 1

    nb.Label(frame, text="Include-only events:").grid(
        row=current_row, column=0, sticky=tk.NW, padx=10, pady=(6, 6)
    )
    include_box = tk.Text(frame, width=40, height=6)
    include_box.insert("1.0", "\n".join(sorted(_included_events)))
    include_box.grid(row=current_row, column=1, sticky=tk.EW, padx=10, pady=(6, 6))
    _prefs_state.include_widget = include_box
    current_row += 1

    nb.Label(
        frame,
        text="When include-only mode is selected, only these events will be logged.",
        wraplength=420,
        justify=tk.LEFT,
        font=("TkDefaultFont", 8),
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 8))
    current_row += 1

    nb.Label(frame, text="Excluded events:").grid(
        row=current_row, column=0, sticky=tk.NW, padx=10, pady=(6, 6)
    )
    ignore_box = tk.Text(frame, width=40, height=6)
    ignore_box.insert("1.0", "\n".join(sorted(_ignored_events)))
    ignore_box.grid(row=current_row, column=1, sticky=tk.EW, padx=10, pady=(6, 6))
    _prefs_state.ignore_widget = ignore_box
    current_row += 1

    nb.Label(
        frame,
        text="When exclude mode is selected, these events will be skipped.",
        wraplength=420,
        justify=tk.LEFT,
        font=("TkDefaultFont", 8),
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 8))
    current_row += 1

    payload_limit_value = "" if _payload_limit is None else str(_payload_limit)
    nb.Label(
        frame,
        text="Payload character limit (leave blank for unlimited):",
    ).grid(row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 6))
    _prefs_state.payload_limit_var = tk.StringVar(value=payload_limit_value)
    nb.Entry(frame, textvariable=_prefs_state.payload_limit_var, width=10).grid(
        row=current_row, column=1, sticky=tk.W, padx=10, pady=(0, 6)
    )
    current_row += 1

    _prefs_state.include_payload_var = tk.BooleanVar(value=_include_payload)
    nb.Checkbutton(
        frame,
        text="Include full event payload in log entries",
        variable=_prefs_state.include_payload_var,
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 10))

    _refresh_profile_menu()
    _populate_prefs_fields()
    return frame


def prefs_changed(cmdr: str, is_beta: bool) -> None:
    global _include_payload, _filter_mode, _payload_limit, _logging_enabled

    if _prefs_state.ignore_widget is not None:
        raw_ignore = _prefs_state.ignore_widget.get("1.0", tk.END)
        ignore_events = _parse_ignore_list(raw_ignore)
        if not ignore_events:
            ignore_events = set(_DEFAULT_IGNORE_EVENTS)
        _ignored_events.clear()
        _ignored_events.update(ignore_events)
        config.set(_CONFIG_IGNORE_EVENTS, _serialise_events(ignore_events))
        _logger.info("Updated ignore list: %s", ", ".join(sorted(_ignored_events)))

    if _prefs_state.include_widget is not None:
        raw_include = _prefs_state.include_widget.get("1.0", tk.END)
        include_events = _parse_ignore_list(raw_include)
        _included_events.clear()
        _included_events.update(include_events)
        config.set(_CONFIG_INCLUDE_EVENTS, _serialise_events(include_events))
        if include_events:
            _logger.info(
                "Updated include list: %s",
                ", ".join(sorted(_included_events)),
            )
        else:
            _logger.info("Updated include list: <none>")

    if _prefs_state.mode_var is not None:
        mode_value = _prefs_state.mode_var.get() or "exclude"
        if mode_value not in {"include", "exclude"}:
            mode_value = "exclude"
        _filter_mode = mode_value
        config.set(_CONFIG_MODE, mode_value)
        _logger.info("Filter mode set to %s", mode_value)

    if _prefs_state.payload_limit_var is not None:
        raw_limit = (_prefs_state.payload_limit_var.get() or "").strip()
        new_limit = None
        if raw_limit:
            try:
                parsed = int(raw_limit)
            except ValueError:
                parsed = 0
            if parsed > 0:
                new_limit = parsed
        _payload_limit = new_limit
        if new_limit is not None:
            config.set(_CONFIG_PAYLOAD_LIMIT, str(new_limit))
            _prefs_state.payload_limit_var.set(str(new_limit))
            _logger.info("Payload limit set to %d characters", new_limit)
        else:
            config.set(_CONFIG_PAYLOAD_LIMIT, "")
            _prefs_state.payload_limit_var.set("")
            if raw_limit and not raw_limit.isdigit():
                _logger.warning("Invalid payload limit '%s'; disabled truncation.", raw_limit)
            else:
                _logger.info("Payload limit disabled")

    if _prefs_state.include_payload_var is not None:
        include_payload = bool(_prefs_state.include_payload_var.get())
        _include_payload = include_payload
        config.set(_CONFIG_INCLUDE_PAYLOAD, include_payload)
        _logger.info(
            "Event payload logging %s",
            "enabled" if include_payload else "disabled",
        )

    if _prefs_state.logging_enabled_var is not None:
        logging_enabled = bool(_prefs_state.logging_enabled_var.get())
        _logging_enabled = logging_enabled
        config.set(_CONFIG_LOGGING_ENABLED, logging_enabled)
        _logger.info("Logging %s", "enabled" if logging_enabled else "disabled")

    _profiles[_active_profile] = _sanitize_settings(_get_current_settings())
    _save_profiles()
    _refresh_profile_menu()
    _populate_prefs_fields()


def journal_entry(cmdr, is_beta, system, station, entry, state) -> None:
    if not _logging_enabled:
        return
    event_name = entry.get("event")
    if not event_name:
        _logger.debug("Received journal entry without event field: %s", entry)
        return
    if _filter_mode == "include":
        if _included_events:
            if event_name not in _included_events:
                return
        else:
            _logger.debug(
                "Include-only mode active but no events configured; skipping %s",
                event_name,
            )
            return
    else:
        if event_name in _ignored_events:
            return
    if _include_payload:
        try:
            payload = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
        except TypeError:
            payload = repr(entry)
            _logger.warning(
                "Could not serialise journal event %s to JSON, using repr instead.",
                event_name,
            )
        truncated = False
        if _payload_limit is not None and len(payload) > _payload_limit:
            truncated = True
            if _payload_limit > 3:
                payload = payload[: _payload_limit - 3] + "..."
            else:
                payload = payload[: _payload_limit]
        _logger.info("Journal event %s: %s", event_name, payload)
        if truncated:
            _logger.debug("Payload truncated to %d characters for %s", _payload_limit, event_name)
    else:
        _logger.info("Journal event %s", event_name)

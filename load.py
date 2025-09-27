"""Test Event Logger - EDMC plugin with profile support."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set

import tkinter as tk
from tkinter import filedialog

try:
    from config import appname, config
    import myNotebook as nb
except ImportError:  # pragma: no cover
    from edmc_mocks import appname, config, nb  # type: ignore


PLUGIN_NAME = Path(__file__).resolve().parent.name
LOG_KEY_PREFIX = "testeventlogger_"

CONFIG_IGNORE_EVENTS = f"{LOG_KEY_PREFIX}ignore_events"
CONFIG_INCLUDE_EVENTS = f"{LOG_KEY_PREFIX}include_events"
CONFIG_FILTER_MODE = f"{LOG_KEY_PREFIX}filter_mode"
CONFIG_INCLUDE_PAYLOAD = f"{LOG_KEY_PREFIX}include_payload"
CONFIG_PAYLOAD_LIMIT = f"{LOG_KEY_PREFIX}payload_limit"
CONFIG_LOGGING_ENABLED = f"{LOG_KEY_PREFIX}logging_enabled"
CONFIG_FORWARD_TO_EDMC_LOG = f"{LOG_KEY_PREFIX}forward_to_edmc_log"
CONFIG_LOG_FILE_PATH = f"{LOG_KEY_PREFIX}log_file_path"
CONFIG_PROFILES = f"{LOG_KEY_PREFIX}profiles"
CONFIG_ACTIVE_PROFILE = f"{LOG_KEY_PREFIX}active_profile"

DEFAULT_IGNORE_EVENTS = {"Music", "Fileheader"}
DEFAULT_INCLUDE_EVENTS: Set[str] = set()
DEFAULT_PROFILE_NAME = "Default"

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
FILE_HANDLER_FLAG = "_tel_file_handler"


logger = logging.getLogger(f"{appname}.{PLUGIN_NAME}")
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False


class _ForwardToEDMCHandler(logging.Handler):
    """Forwards plugin log records to the native EDMC logger."""

    def __init__(self) -> None:
        super().__init__()
        self._target = logging.getLogger(appname)

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - side-effect only
        try:
            self._target.handle(record)
        except Exception:
            # Avoid raising if EDMC logger handling fails
            pass


_edmc_forward_handler: Optional[logging.Handler] = None


class PrefsState:
    def __init__(self) -> None:
        self.ignore_widget: Optional[tk.Text] = None
        self.include_widget: Optional[tk.Text] = None
        self.mode_var: Optional[tk.StringVar] = None
        self.include_payload_var: Optional[tk.BooleanVar] = None
        self.forward_to_edmc_var: Optional[tk.BooleanVar] = None
        self.payload_limit_var: Optional[tk.StringVar] = None
        self.logging_enabled_var: Optional[tk.BooleanVar] = None
        self.profile_var: Optional[tk.StringVar] = None
        self.profile_menu: Optional[tk.OptionMenu] = None
        self.new_profile_var: Optional[tk.StringVar] = None
        self.log_path_var: Optional[tk.StringVar] = None
        self.marker_var: Optional[tk.StringVar] = None


prefs_state = PrefsState()

_ignored_events: Set[str] = set(DEFAULT_IGNORE_EVENTS)
_included_events: Set[str] = set(DEFAULT_INCLUDE_EVENTS)
_filter_mode: str = "exclude"
_include_payload: bool = True
_payload_limit: Optional[int] = None
_logging_enabled: bool = True
_forward_to_edmc_log: bool = False
_custom_log_path: Optional[Path] = None
_profiles: Dict[str, Dict[str, Any]] = {}
_active_profile: str = DEFAULT_PROFILE_NAME
_log_file_path: Optional[Path] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_event_names(raw_events: Iterable[str]) -> Set[str]:
    return {item.strip() for item in raw_events if item.strip()}


def _parse_event_list(raw: str) -> Set[str]:
    if not raw:
        return set()
    for token in ",;|":
        raw = raw.replace(token, "\n")
    return _normalise_event_names(raw.splitlines())


def _serialise_events(events: Iterable[str]) -> str:
    return "\n".join(sorted(_normalise_event_names(events)))


def _clone_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ignored_events": list(settings.get("ignored_events", [])),
        "included_events": list(settings.get("included_events", [])),
        "filter_mode": settings.get("filter_mode", "exclude"),
        "include_payload": bool(settings.get("include_payload", True)),
        "payload_limit": settings.get("payload_limit"),
        "logging_enabled": bool(settings.get("logging_enabled", True)),
        "forward_to_edmc_log": bool(settings.get("forward_to_edmc_log", False)),
        "log_file_path": settings.get("log_file_path"),
    }


def _default_settings() -> Dict[str, Any]:
    return {
        "ignored_events": sorted(DEFAULT_IGNORE_EVENTS),
        "included_events": sorted(DEFAULT_INCLUDE_EVENTS),
        "filter_mode": "exclude",
        "include_payload": True,
        "payload_limit": None,
        "logging_enabled": True,
        "forward_to_edmc_log": False,
        "log_file_path": None,
    }


def _sanitize_settings(settings: Any) -> Dict[str, Any]:
    base = _default_settings()
    if not isinstance(settings, dict):
        return base

    ignored = _parse_event_list("\n".join(settings.get("ignored_events", base["ignored_events"])))
    if not ignored:
        ignored = set(DEFAULT_IGNORE_EVENTS)

    included = _parse_event_list("\n".join(settings.get("included_events", base["included_events"])))

    mode = settings.get("filter_mode", "exclude")
    if mode not in {"include", "exclude"}:
        mode = "exclude"

    include_payload = bool(settings.get("include_payload", True))

    payload_limit = settings.get("payload_limit")
    try:
        payload_limit = int(payload_limit)
        if payload_limit <= 0:
            payload_limit = None
    except (TypeError, ValueError):
        payload_limit = None

    logging_enabled = bool(settings.get("logging_enabled", True))

    forward_to_edmc_log = bool(settings.get("forward_to_edmc_log", False))

    raw_log_path = settings.get("log_file_path")
    log_file_path: Optional[str]
    if isinstance(raw_log_path, str):
        cleaned = raw_log_path.strip()
        if cleaned:
            try:
                log_file_path = str(Path(cleaned).expanduser())
            except Exception:
                log_file_path = None
        else:
            log_file_path = None
    else:
        log_file_path = None

    return {
        "ignored_events": sorted(ignored),
        "included_events": sorted(included),
        "filter_mode": mode,
        "include_payload": include_payload,
        "payload_limit": payload_limit,
        "logging_enabled": logging_enabled,
        "forward_to_edmc_log": forward_to_edmc_log,
        "log_file_path": log_file_path,
    }


def _default_log_file() -> Path:
    candidates: list[Path] = []
    for attr in ("logs_dir", "log_dir", "logdir"):
        value = getattr(config, attr, None)
        if value:
            candidates.append(Path(value))
    for attr in ("config_dir", "app_dir", "data_dir"):
        value = getattr(config, attr, None)
        if value:
            candidates.append(Path(value) / "logs")
    candidates.append(Path.home() / ".config" / "EDMarketConnector" / "logs")

    for directory in candidates:
        try:
            if directory:
                return directory / f"{PLUGIN_NAME}.log"
        except TypeError:
            continue
    return Path.cwd() / f"{PLUGIN_NAME}.log"


def _active_log_file() -> Path:
    if _custom_log_path is not None:
        return _custom_log_path
    return _default_log_file()


def _ensure_file_logging() -> None:
    global _log_file_path, _custom_log_path

    desired_path = _active_log_file().expanduser()

    existing_handler: Optional[logging.Handler] = None
    for handler in logger.handlers:
        if getattr(handler, FILE_HANDLER_FLAG, False):
            existing_handler = handler
            break

    current_path: Optional[Path] = None
    if existing_handler is not None:
        base_filename = getattr(existing_handler, "baseFilename", None)
        if base_filename:
            current_path = Path(base_filename)

    if current_path is not None and current_path == desired_path:
        _log_file_path = desired_path
        return

    previous_path = current_path

    if existing_handler is not None and previous_path is not None and previous_path != desired_path:
        try:
            record = logger.makeRecord(
                logger.name,
                logging.INFO,
                __file__,
                0,
                "Log file path changed to %s",
                (str(desired_path),),
                None,
            )
            existing_handler.handle(record)
            existing_handler.flush()
        except Exception:
            pass

    if existing_handler is not None:
        logger.removeHandler(existing_handler)
        try:
            existing_handler.close()
        except Exception:
            pass

    try:
        desired_path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(desired_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
        setattr(handler, FILE_HANDLER_FLAG, True)
        logger.addHandler(handler)
        _log_file_path = desired_path
        logger.debug("File logging initialised at %s", desired_path)
        if previous_path is None or previous_path != desired_path:
            logger.info("Log file path changed to %s", desired_path)
    except Exception as exc:  # pragma: no cover
        logger.warning("Unable to initialise log file at %s: %s", desired_path, exc)
        if _custom_log_path is not None:
            logger.warning("Reverting to default log file location.")
            _custom_log_path = None
            _ensure_file_logging()
        else:
            _log_file_path = None


_ensure_file_logging()


def _sync_edmc_forwarding() -> None:
    global _edmc_forward_handler
    if _forward_to_edmc_log:
        if _edmc_forward_handler is None:
            handler = _ForwardToEDMCHandler()
            handler.setLevel(logging.NOTSET)
            logger.addHandler(handler)
            _edmc_forward_handler = handler
    else:
        if _edmc_forward_handler is not None:
            logger.removeHandler(_edmc_forward_handler)
            _edmc_forward_handler = None


def _log_marker(message: str) -> None:
    """Emit a custom marker message to the plugin log."""

    text = message.strip()
    if not text:
        text = "Manual marker"

    _ensure_file_logging()
    logger.info("===== MARKER: %s =====", text)


def _current_log_path() -> str:
    if _log_file_path is not None:
        return str(_log_file_path)
    try:
        return str(_active_log_file())
    except Exception:  # pragma: no cover
        return "Log file unavailable"


def _get_current_settings() -> Dict[str, Any]:
    return {
        "ignored_events": sorted(_ignored_events),
        "included_events": sorted(_included_events),
        "filter_mode": _filter_mode,
        "include_payload": _include_payload,
        "payload_limit": _payload_limit,
        "logging_enabled": _logging_enabled,
        "forward_to_edmc_log": _forward_to_edmc_log,
        "log_file_path": str(_custom_log_path) if _custom_log_path else None,
    }


def _apply_settings(settings: Dict[str, Any]) -> None:
    global _filter_mode, _include_payload, _payload_limit, _logging_enabled, _forward_to_edmc_log, _custom_log_path

    ignored = _parse_event_list("\n".join(settings.get("ignored_events", [])))
    if not ignored:
        ignored = set(DEFAULT_IGNORE_EVENTS)
    _ignored_events.clear()
    _ignored_events.update(ignored)

    included = _parse_event_list("\n".join(settings.get("included_events", [])))
    _included_events.clear()
    _included_events.update(included)

    mode = settings.get("filter_mode", "exclude")
    if mode not in {"include", "exclude"}:
        mode = "exclude"
    _filter_mode = mode

    _include_payload = bool(settings.get("include_payload", True))

    payload_limit = settings.get("payload_limit")
    if isinstance(payload_limit, (int, float)):
        payload_limit = int(payload_limit)
        if payload_limit <= 0:
            payload_limit = None
    else:
        payload_limit = None
    _payload_limit = payload_limit

    _logging_enabled = bool(settings.get("logging_enabled", True))
    _forward_to_edmc_log = bool(settings.get("forward_to_edmc_log", False))

    raw_log_path = settings.get("log_file_path")
    if isinstance(raw_log_path, str) and raw_log_path.strip():
        try:
            _custom_log_path = Path(raw_log_path).expanduser()
        except Exception:
            _custom_log_path = None
    else:
        _custom_log_path = None

    config.set(CONFIG_IGNORE_EVENTS, _serialise_events(_ignored_events))
    config.set(CONFIG_INCLUDE_EVENTS, _serialise_events(_included_events))
    config.set(CONFIG_FILTER_MODE, _filter_mode)
    config.set(CONFIG_INCLUDE_PAYLOAD, _include_payload)
    config.set(CONFIG_PAYLOAD_LIMIT, "" if _payload_limit is None else str(_payload_limit))
    config.set(CONFIG_LOGGING_ENABLED, _logging_enabled)
    config.set(CONFIG_FORWARD_TO_EDMC_LOG, _forward_to_edmc_log)
    config.set(CONFIG_LOG_FILE_PATH, str(_custom_log_path) if _custom_log_path else "")
    _ensure_file_logging()
    _sync_edmc_forwarding()


def _populate_prefs_fields() -> None:
    if prefs_state.include_widget is not None:
        prefs_state.include_widget.delete("1.0", tk.END)
        prefs_state.include_widget.insert("1.0", "\n".join(sorted(_included_events)))
    if prefs_state.ignore_widget is not None:
        prefs_state.ignore_widget.delete("1.0", tk.END)
        prefs_state.ignore_widget.insert("1.0", "\n".join(sorted(_ignored_events)))
    if prefs_state.mode_var is not None:
        prefs_state.mode_var.set(_filter_mode)
    if prefs_state.include_payload_var is not None:
        prefs_state.include_payload_var.set(_include_payload)
    if prefs_state.forward_to_edmc_var is not None:
        prefs_state.forward_to_edmc_var.set(_forward_to_edmc_log)
    if prefs_state.payload_limit_var is not None:
        prefs_state.payload_limit_var.set("" if _payload_limit is None else str(_payload_limit))
    if prefs_state.logging_enabled_var is not None:
        prefs_state.logging_enabled_var.set(_logging_enabled)
    if prefs_state.profile_var is not None:
        prefs_state.profile_var.set(_active_profile)
    if prefs_state.new_profile_var is not None:
        prefs_state.new_profile_var.set(_active_profile)
    if prefs_state.log_path_var is not None:
        prefs_state.log_path_var.set(_current_log_path())
    if prefs_state.marker_var is not None:
        prefs_state.marker_var.set("")


def _update_state_from_widgets() -> Dict[str, Any]:
    global _filter_mode, _include_payload, _payload_limit, _logging_enabled, _forward_to_edmc_log, _custom_log_path

    if prefs_state.ignore_widget is not None:
        raw_ignore = prefs_state.ignore_widget.get("1.0", tk.END)
        ignore_events = _parse_event_list(raw_ignore)
        if not ignore_events:
            ignore_events = set(DEFAULT_IGNORE_EVENTS)
        _ignored_events.clear()
        _ignored_events.update(ignore_events)
        config.set(CONFIG_IGNORE_EVENTS, _serialise_events(ignore_events))

    if prefs_state.include_widget is not None:
        raw_include = prefs_state.include_widget.get("1.0", tk.END)
        include_events = _parse_event_list(raw_include)
        _included_events.clear()
        _included_events.update(include_events)
        config.set(CONFIG_INCLUDE_EVENTS, _serialise_events(include_events))

    if prefs_state.log_path_var is not None:
        raw_path = (prefs_state.log_path_var.get() or "").strip()
        default_path = str(_default_log_file())
        if raw_path:
            try:
                candidate = Path(raw_path).expanduser()
            except Exception:
                candidate = None
            if candidate is not None and candidate != Path(default_path):
                _custom_log_path = candidate
            elif candidate is not None and candidate == Path(default_path):
                _custom_log_path = None
            else:
                _custom_log_path = None
        else:
            _custom_log_path = None
        config.set(CONFIG_LOG_FILE_PATH, str(_custom_log_path) if _custom_log_path else "")
        _ensure_file_logging()

    if prefs_state.mode_var is not None:
        mode_value = prefs_state.mode_var.get() or "exclude"
        if mode_value not in {"include", "exclude"}:
            mode_value = "exclude"
        _filter_mode = mode_value
        config.set(CONFIG_FILTER_MODE, mode_value)

    if prefs_state.payload_limit_var is not None:
        raw_limit = (prefs_state.payload_limit_var.get() or "").strip()
        new_limit: Optional[int] = None
        if raw_limit:
            try:
                parsed = int(raw_limit)
            except ValueError:
                parsed = 0
            if parsed > 0:
                new_limit = parsed
        _payload_limit = new_limit
        if new_limit is not None:
            config.set(CONFIG_PAYLOAD_LIMIT, str(new_limit))
            prefs_state.payload_limit_var.set(str(new_limit))
        else:
            config.set(CONFIG_PAYLOAD_LIMIT, "")
            prefs_state.payload_limit_var.set("")

    if prefs_state.include_payload_var is not None:
        include_payload = bool(prefs_state.include_payload_var.get())
        _include_payload = include_payload
        config.set(CONFIG_INCLUDE_PAYLOAD, include_payload)

    if prefs_state.forward_to_edmc_var is not None:
        forward_native = bool(prefs_state.forward_to_edmc_var.get())
        _forward_to_edmc_log = forward_native
        config.set(CONFIG_FORWARD_TO_EDMC_LOG, forward_native)

    if prefs_state.logging_enabled_var is not None:
        logging_enabled = bool(prefs_state.logging_enabled_var.get())
        _logging_enabled = logging_enabled
        config.set(CONFIG_LOGGING_ENABLED, logging_enabled)

    _sync_edmc_forwarding()

    return _sanitize_settings(_get_current_settings())


def _refresh_profile_menu() -> None:
    if prefs_state.profile_menu is None or prefs_state.profile_var is None:
        return
    menu = prefs_state.profile_menu["menu"]
    menu.delete(0, "end")
    for name in sorted(_profiles.keys()):
        menu.add_command(label=name, command=lambda value=name: _on_profile_selected(value))
    prefs_state.profile_var.set(_active_profile)


def _save_profiles() -> None:
    serialisable = {name: _sanitize_settings(settings) for name, settings in _profiles.items()}
    config.set(CONFIG_PROFILES, json.dumps(serialisable))
    config.set(CONFIG_ACTIVE_PROFILE, _active_profile)


def _load_profiles() -> None:
    global _profiles, _active_profile

    raw_profiles = config.get_str(CONFIG_PROFILES)
    loaded: Dict[str, Dict[str, Any]] = {}

    if raw_profiles:
        try:
            decoded = json.loads(raw_profiles)
        except Exception as exc:  # pragma: no cover
            logger.warning("Failed to parse profile data: %s", exc)
            decoded = {}
        if isinstance(decoded, dict):
            for name, settings in decoded.items():
                key = str(name).strip()
                if key:
                    loaded[key] = _sanitize_settings(settings)

    if not loaded:
        loaded[DEFAULT_PROFILE_NAME] = _sanitize_settings(_get_current_settings())

    _profiles = loaded

    active = config.get_str(CONFIG_ACTIVE_PROFILE) or DEFAULT_PROFILE_NAME
    if active not in _profiles:
        active = sorted(_profiles.keys())[0]
    _active_profile = active

    _apply_settings(_profiles[_active_profile])
    _save_profiles()


def _set_active_profile(name: str) -> None:
    global _active_profile
    if name not in _profiles:
        logger.warning("Profile '%s' not found", name)
        return
    if name != _active_profile:
        _active_profile = name
        _apply_settings(_profiles[name])
        _save_profiles()
    if prefs_state.profile_var is not None:
        prefs_state.profile_var.set(_active_profile)
    _populate_prefs_fields()
    _refresh_profile_menu()


def _on_profile_selected(profile_name: str) -> None:
    _set_active_profile(profile_name)


def _on_create_profile() -> None:
    if prefs_state.new_profile_var is None:
        return
    name = (prefs_state.new_profile_var.get() or "").strip()
    if not name:
        logger.warning("Profile name cannot be empty.")
        return

    snapshot = _update_state_from_widgets()
    _profiles[_active_profile] = _clone_settings(snapshot)
    _profiles[name] = _clone_settings(snapshot)
    _save_profiles()
    _refresh_profile_menu()
    _set_active_profile(name)


def _on_delete_profile() -> None:
    if prefs_state.profile_var is None:
        return
    name = prefs_state.profile_var.get()
    if name not in _profiles:
        return
    if len(_profiles) == 1:
        logger.warning("Cannot delete the last profile.")
        return
    del _profiles[name]
    logger.info("Deleted profile '%s'", name)
    fallback = sorted(_profiles.keys())[0]
    _set_active_profile(fallback)
    _save_profiles()
    _refresh_profile_menu()


def _current_payload_limit() -> Optional[int]:
    return _payload_limit


# ---------------------------------------------------------------------------
# EDMC plugin hooks
# ---------------------------------------------------------------------------


plugin_info = {
    "plugin_version": "1.0.0",
    "plugin_name": PLUGIN_NAME,
    "plugin_description": "Logs journal events with include/exclude filters and profiles.",
}


def plugin_start3(plugin_dir: str) -> str:
    _load_profiles()
    logger.info(
        "Initialised TestEventLogger with profile '%s' (ignored %d events)",
        _active_profile,
        len(_ignored_events),
    )
    logger.info("Logging %s", "enabled" if _logging_enabled else "disabled")
    logger.info(
        "Payload logging %s%s",
        "enabled" if _include_payload else "disabled",
        " (limit %d)" % _payload_limit if _payload_limit else "",
    )
    logger.info(
        "Forwarding to EDMC log %s",
        "enabled" if _forward_to_edmc_log else "disabled",
    )
    logger.info("Log file path: %s", _current_log_path())
    return "TestEventLogger"


def plugin_stop() -> None:
    global _edmc_forward_handler
    logger.info("TestEventLogger stopped")
    if _edmc_forward_handler is not None:
        logger.removeHandler(_edmc_forward_handler)
        _edmc_forward_handler = None
    for handler in list(logger.handlers):
        if getattr(handler, FILE_HANDLER_FLAG, False):
            logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass
    global _log_file_path
    _log_file_path = None


def plugin_app(parent: tk.Frame) -> Optional[tk.Frame]:
    return None


def plugin_prefs(parent: nb.Notebook, cmdr: str, is_beta: bool) -> tk.Frame:
    if _log_file_path is None:
        _ensure_file_logging()

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
            "Mirror journal events to a dedicated log file."
            " Configure include/exclude filters and store them as profiles."
        ),
        wraplength=420,
        justify=tk.LEFT,
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 10))
    current_row += 1

    prefs_state.logging_enabled_var = tk.BooleanVar(value=_logging_enabled)
    nb.Checkbutton(
        frame,
        text="Enable journal logging",
        variable=prefs_state.logging_enabled_var,
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 4))
    current_row += 1

    prefs_state.forward_to_edmc_var = tk.BooleanVar(value=_forward_to_edmc_log)
    nb.Checkbutton(
        frame,
        text="Also send log output to EDMC log",
        variable=prefs_state.forward_to_edmc_var,
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 8))
    current_row += 1

    nb.Label(frame, text="Active profile:").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 4)
    )
    profile_frame = nb.Frame(frame)
    profile_frame.grid(row=current_row, column=1, sticky=tk.W, padx=10, pady=(0, 4))
    prefs_state.profile_var = tk.StringVar(value=_active_profile)
    option_menu = tk.OptionMenu(
        profile_frame,
        prefs_state.profile_var,
        *sorted(_profiles.keys()),
        command=_on_profile_selected,
    )
    option_menu.grid(row=0, column=0, sticky=tk.W)
    prefs_state.profile_menu = option_menu
    nb.Button(profile_frame, text="Delete", command=_on_delete_profile).grid(
        row=0, column=1, sticky=tk.W, padx=(8, 0)
    )
    current_row += 1

    nb.Label(frame, text="Profile name:").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 6)
    )
    new_profile_frame = nb.Frame(frame)
    new_profile_frame.grid(row=current_row, column=1, sticky=tk.W, padx=10, pady=(0, 6))
    prefs_state.new_profile_var = tk.StringVar(value=_active_profile)
    nb.Entry(new_profile_frame, textvariable=prefs_state.new_profile_var, width=20).grid(
        row=0, column=0, sticky=tk.W
    )
    nb.Button(new_profile_frame, text="Save profile", command=_on_create_profile).grid(
        row=0, column=1, sticky=tk.W, padx=(8, 0)
    )
    current_row += 1

    nb.Label(frame, text="Log file location:").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 4)
    )
    log_path_frame = nb.Frame(frame)
    log_path_frame.grid(row=current_row, column=1, sticky=tk.W + tk.E, padx=10, pady=(0, 4))
    log_path_frame.columnconfigure(0, weight=1)
    prefs_state.log_path_var = tk.StringVar(value=_current_log_path())
    tk.Entry(log_path_frame, textvariable=prefs_state.log_path_var, width=50).grid(
        row=0, column=0, sticky=tk.EW
    )

    def _choose_log_path() -> None:
        current_value = prefs_state.log_path_var.get() if prefs_state.log_path_var else _current_log_path()
        try:
            current_path = Path(current_value).expanduser()
        except Exception:
            current_path = _active_log_file()
        initialdir = str(current_path.parent) if current_path.parent else str(Path.home())
        initialfile = current_path.name
        selected = filedialog.asksaveasfilename(
            parent=frame,
            title="Select log file",
            initialdir=initialdir,
            initialfile=initialfile,
            defaultextension=".log",
        )
        if selected:
            prefs_state.log_path_var.set(selected)

    def _reset_log_path() -> None:
        prefs_state.log_path_var.set(str(_default_log_file()))

    def _copy_log_path() -> None:
        path_value = prefs_state.log_path_var.get() if prefs_state.log_path_var else _current_log_path()
        try:
            log_dir = str(Path(path_value).parent)
            if not log_dir or log_dir == ".":
                log_dir = path_value
        except Exception:
            log_dir = path_value
        toplevel = frame.winfo_toplevel()
        try:
            toplevel.clipboard_clear()
            toplevel.clipboard_append(log_dir)
            logger.info("Copied log directory to clipboard: %s", log_dir)
        except Exception as exc:  # pragma: no cover
            logger.warning("Unable to copy log path to clipboard: %s", exc)

    nb.Button(log_path_frame, text="Browse...", command=_choose_log_path).grid(
        row=0, column=1, sticky=tk.W, padx=(8, 0)
    )
    nb.Button(log_path_frame, text="Reset", command=_reset_log_path).grid(
        row=0, column=2, sticky=tk.W, padx=(8, 0)
    )
    nb.Button(log_path_frame, text="Copy path", command=_copy_log_path).grid(
        row=0, column=3, sticky=tk.W, padx=(8, 0)
    )
    current_row += 1

    nb.Label(frame, text="Custom log marker:").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(4, 0)
    )
    marker_frame = nb.Frame(frame)
    marker_frame.grid(row=current_row, column=1, sticky=tk.W + tk.E, padx=10, pady=(4, 0))
    marker_frame.columnconfigure(0, weight=1)
    prefs_state.marker_var = tk.StringVar()
    tk.Entry(marker_frame, textvariable=prefs_state.marker_var, width=40).grid(
        row=0, column=0, sticky=tk.EW
    )

    def _post_marker() -> None:
        if prefs_state.marker_var is None:
            return
        message = prefs_state.marker_var.get()
        _log_marker(message)

    nb.Button(marker_frame, text="Post marker", command=_post_marker).grid(
        row=0, column=1, sticky=tk.W, padx=(8, 0)
    )
    current_row += 1

    nb.Label(frame, text="Logging mode:").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 4)
    )
    prefs_state.mode_var = tk.StringVar(value=_filter_mode)
    mode_frame = nb.Frame(frame)
    mode_frame.grid(row=current_row, column=1, sticky=tk.W, padx=10, pady=(0, 4))
    nb.Radiobutton(mode_frame, text="Use exclude list", value="exclude", variable=prefs_state.mode_var).grid(
        row=0, column=0, sticky=tk.W
    )
    nb.Radiobutton(mode_frame, text="Use include-only list", value="include", variable=prefs_state.mode_var).grid(
        row=0, column=1, sticky=tk.W, padx=(10, 0)
    )
    current_row += 1

    nb.Label(frame, text="Include-only events:").grid(
        row=current_row, column=0, sticky=tk.NW, padx=10, pady=(6, 6)
    )
    include_box = tk.Text(frame, width=40, height=6)
    include_box.grid(row=current_row, column=1, sticky=tk.EW, padx=10, pady=(6, 6))
    prefs_state.include_widget = include_box
    current_row += 1

    nb.Label(
        frame,
        text="When include-only mode is selected, only these events are logged.",
        wraplength=420,
        justify=tk.LEFT,
        font=("TkDefaultFont", 8),
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 6))
    current_row += 1

    nb.Label(frame, text="Excluded events:").grid(
        row=current_row, column=0, sticky=tk.NW, padx=10, pady=(6, 6)
    )
    ignore_box = tk.Text(frame, width=40, height=6)
    ignore_box.grid(row=current_row, column=1, sticky=tk.EW, padx=10, pady=(6, 6))
    prefs_state.ignore_widget = ignore_box
    current_row += 1

    nb.Label(
        frame,
        text="When exclude mode is selected, these events are skipped.",
        wraplength=420,
        justify=tk.LEFT,
        font=("TkDefaultFont", 8),
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 6))
    current_row += 1

    prefs_state.include_payload_var = tk.BooleanVar(value=_include_payload)
    nb.Checkbutton(
        frame,
        text="Include full event payload in log entries",
        variable=prefs_state.include_payload_var,
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 6))
    current_row += 1

    nb.Label(frame, text="Payload character limit (blank for unlimited):").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 10)
    )
    prefs_state.payload_limit_var = tk.StringVar(value="" if _payload_limit is None else str(_payload_limit))
    nb.Entry(frame, textvariable=prefs_state.payload_limit_var, width=10).grid(
        row=current_row, column=1, sticky=tk.W, padx=10, pady=(0, 10)
    )
    current_row += 1

    _populate_prefs_fields()
    _refresh_profile_menu()

    return frame


def prefs_changed(cmdr: str, is_beta: bool) -> None:
    settings_snapshot = _update_state_from_widgets()
    _profiles[_active_profile] = _clone_settings(settings_snapshot)
    _save_profiles()
    _refresh_profile_menu()
    _populate_prefs_fields()


def journal_entry(cmdr, is_beta, system, station, entry, state) -> None:
    if not _logging_enabled:
        return

    event_name = entry.get("event")
    if not event_name:
        logger.debug("Journal entry missing event field: %s", entry)
        return

    if _filter_mode == "include":
        if _included_events and event_name not in _included_events:
            return
        if not _included_events:
            logger.debug("Include-only mode set but no events defined; skipping %s", event_name)
            return
    else:
        if event_name in _ignored_events:
            return

    payload = None
    if _include_payload:
        try:
            payload = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
        except TypeError:
            payload = repr(entry)
            logger.warning("Failed to serialise event %s to JSON; using repr.", event_name)
        if payload and _payload_limit is not None and len(payload) > _payload_limit:
            if _payload_limit > 3:
                payload = payload[: _payload_limit - 3] + "..."
            else:
                payload = payload[: _payload_limit]
            logger.debug("Payload truncated to %d chars for %s", _payload_limit, event_name)

    if payload is not None:
        logger.info("Journal event %s: %s", event_name, payload)
    else:
        logger.info("Journal event %s", event_name)

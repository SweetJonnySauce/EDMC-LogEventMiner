"""EDMC-LogEventMiner - EDMC plugin with profile support."""

from __future__ import annotations

import json
import logging
import re
import webbrowser
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set

import tkinter as tk
from tkinter import filedialog

try:
    from config import appname, config
    import myNotebook as nb
except ImportError:  # pragma: no cover
    from edmc_mocks import appname, config, nb  # type: ignore

try:
    import overlay as overlay_support
except Exception:  # pragma: no cover - optional dependency
    overlay_support = None  # type: ignore


PLUGIN_DIR = Path(__file__).resolve().parent
PLUGIN_NAME = PLUGIN_DIR.name
VERSION_FILE = PLUGIN_DIR / "VERSION"


def _read_plugin_version() -> str:
    try:
        raw = VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0"
    return raw or "0.0.0"


PLUGIN_VERSION = _read_plugin_version()
plugin_info = {
    "plugin_version": PLUGIN_VERSION,
    "plugin_name": PLUGIN_NAME,
    "plugin_description": "Logs journal events with include/exclude filters and profiles.",
}
LOG_KEY_PREFIX = "edmc-logeventminer_"

CONFIG_IGNORE_EVENTS = f"{LOG_KEY_PREFIX}ignore_events"
CONFIG_INCLUDE_EVENTS = f"{LOG_KEY_PREFIX}include_events"
CONFIG_FILTER_MODE = f"{LOG_KEY_PREFIX}filter_mode"
CONFIG_INCLUDE_PAYLOAD = f"{LOG_KEY_PREFIX}include_payload"
CONFIG_PAYLOAD_LIMIT = f"{LOG_KEY_PREFIX}payload_limit"
CONFIG_LOGGING_ENABLED = f"{LOG_KEY_PREFIX}logging_enabled"
CONFIG_FORWARD_TO_EDMC_LOG = f"{LOG_KEY_PREFIX}forward_to_edmc_log"
CONFIG_LOG_FILE_PATH = f"{LOG_KEY_PREFIX}log_file_path"
CONFIG_ROTATION_ENABLED = f"{LOG_KEY_PREFIX}rotation_enabled"
CONFIG_ROTATION_MAX_BYTES = f"{LOG_KEY_PREFIX}rotation_max_bytes"
CONFIG_ROTATION_BACKUP_COUNT = f"{LOG_KEY_PREFIX}rotation_backup_count"
CONFIG_PROFILES = f"{LOG_KEY_PREFIX}profiles"
CONFIG_ACTIVE_PROFILE = f"{LOG_KEY_PREFIX}active_profile"
CONFIG_OVERLAY_ENABLED = f"{LOG_KEY_PREFIX}overlay_enabled"
CONFIG_OVERLAY_LINES = f"{LOG_KEY_PREFIX}overlay_lines"
CONFIG_OVERLAY_FONT_SIZE = f"{LOG_KEY_PREFIX}overlay_font_size"
CONFIG_OVERLAY_COLOR = f"{LOG_KEY_PREFIX}overlay_color"

DEFAULT_IGNORE_EVENTS = {"Music", "Fileheader"}
DEFAULT_INCLUDE_EVENTS: Set[str] = set()
DEFAULT_PROFILE_NAME = "Default"
DEFAULT_OVERLAY_LINES = 10
DEFAULT_OVERLAY_FONT_SIZE = "medium"
DEFAULT_OVERLAY_COLOR = "orange"
DEFAULT_OVERLAY_ENABLED = False
OVERLAY_FONT_SIZES = ("small", "medium", "large")

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
FILE_HANDLER_FLAG = "_tel_file_handler"


logger = logging.getLogger(f"{appname}.{PLUGIN_NAME}")
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False


def _debug(message: str, *args: Any) -> None:
    """Emit plugin diagnostics through EDMC's logger and level controls."""

    # Route diagnostics through EDMC's main logger so they always obey
    # EDMC's configured log level and appear in EDMarketConnector-debug.log.
    logging.getLogger(appname).debug(f"[{PLUGIN_NAME}] {message}", *args)


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
        self.rotation_enabled_var: Optional[tk.BooleanVar] = None
        self.rotation_max_bytes_var: Optional[tk.StringVar] = None
        self.rotation_backup_count_var: Optional[tk.StringVar] = None
        self.rotation_max_bytes_entry: Optional[tk.Entry] = None
        self.rotation_backup_count_entry: Optional[tk.Entry] = None
        self.profile_var: Optional[tk.StringVar] = None
        self.profile_menu: Optional[tk.OptionMenu] = None
        self.new_profile_var: Optional[tk.StringVar] = None
        self.profile_log_var: Optional[tk.BooleanVar] = None
        self.profile_log_check: Optional[tk.Checkbutton] = None
        self.log_path_var: Optional[tk.StringVar] = None
        self.marker_var: Optional[tk.StringVar] = None
        self.overlay_enabled_var: Optional[tk.BooleanVar] = None
        self.overlay_lines_var: Optional[tk.StringVar] = None
        self.overlay_lines_entry: Optional[tk.Entry] = None
        self.overlay_font_size_var: Optional[tk.StringVar] = None
        self.overlay_font_menu: Optional[tk.OptionMenu] = None
        self.overlay_color_var: Optional[tk.StringVar] = None
        self.overlay_color_entry: Optional[tk.Entry] = None


prefs_state = PrefsState()

_ignored_events: Set[str] = set(DEFAULT_IGNORE_EVENTS)
_included_events: Set[str] = set(DEFAULT_INCLUDE_EVENTS)
_filter_mode: str = "exclude"
_include_payload: bool = True
_payload_limit: Optional[int] = None
_logging_enabled: bool = True
_forward_to_edmc_log: bool = False
_log_rotation_enabled: bool = True
_log_rotation_max_bytes: int = 5 * 1024 * 1024
_log_rotation_backup_count: int = 5
_custom_log_path: Optional[Path] = None
_profiles: Dict[str, Dict[str, Any]] = {}
_active_profile: str = DEFAULT_PROFILE_NAME
_log_file_path: Optional[Path] = None
_overlay_enabled: bool = DEFAULT_OVERLAY_ENABLED
_overlay_line_count: int = DEFAULT_OVERLAY_LINES
_overlay_font_size: str = DEFAULT_OVERLAY_FONT_SIZE
_overlay_color: str = DEFAULT_OVERLAY_COLOR


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


def _config_missing(key: str) -> bool:
    try:
        raw = config.get_str(key)
    except Exception:
        return True
    return raw is None or raw == ""


def _ensure_config_defaults() -> None:
    defaults = _default_settings()
    default_map = {
        CONFIG_IGNORE_EVENTS: _serialise_events(DEFAULT_IGNORE_EVENTS),
        CONFIG_INCLUDE_EVENTS: _serialise_events(DEFAULT_INCLUDE_EVENTS),
        CONFIG_FILTER_MODE: defaults["filter_mode"],
        CONFIG_INCLUDE_PAYLOAD: defaults["include_payload"],
        CONFIG_PAYLOAD_LIMIT: "",
        CONFIG_LOGGING_ENABLED: defaults["logging_enabled"],
        CONFIG_FORWARD_TO_EDMC_LOG: defaults["forward_to_edmc_log"],
        CONFIG_LOG_FILE_PATH: "",
        CONFIG_ROTATION_ENABLED: defaults["rotation_enabled"],
        CONFIG_ROTATION_MAX_BYTES: str(defaults["rotation_max_bytes"]),
        CONFIG_ROTATION_BACKUP_COUNT: str(defaults["rotation_backup_count"]),
        CONFIG_OVERLAY_ENABLED: DEFAULT_OVERLAY_ENABLED,
        CONFIG_OVERLAY_LINES: str(DEFAULT_OVERLAY_LINES),
        CONFIG_OVERLAY_FONT_SIZE: DEFAULT_OVERLAY_FONT_SIZE,
        CONFIG_OVERLAY_COLOR: DEFAULT_OVERLAY_COLOR,
    }

    for key, value in default_map.items():
        if _config_missing(key):
            try:
                config.set(key, value)
            except Exception:
                pass



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
        "rotation_enabled": bool(settings.get("rotation_enabled", True)),
        "rotation_max_bytes": settings.get("rotation_max_bytes"),
        "rotation_backup_count": settings.get("rotation_backup_count"),
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
        "rotation_enabled": True,
        "rotation_max_bytes": 5 * 1024 * 1024,
        "rotation_backup_count": 5,
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

    rotation_enabled = bool(settings.get("rotation_enabled", True))

    rotation_max_bytes_raw = settings.get("rotation_max_bytes")
    try:
        rotation_max_bytes = int(rotation_max_bytes_raw)
        if rotation_max_bytes <= 0:
            rotation_max_bytes = base["rotation_max_bytes"]
    except (TypeError, ValueError):
        rotation_max_bytes = base["rotation_max_bytes"]

    rotation_backup_raw = settings.get("rotation_backup_count")
    try:
        rotation_backup_count = int(rotation_backup_raw)
        if rotation_backup_count < 1:
            rotation_backup_count = base["rotation_backup_count"]
    except (TypeError, ValueError):
        rotation_backup_count = base["rotation_backup_count"]

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
        "rotation_enabled": rotation_enabled,
        "rotation_max_bytes": rotation_max_bytes,
        "rotation_backup_count": rotation_backup_count,
    }


def _parse_bool_value(raw: Optional[str], default: bool) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _load_overlay_settings() -> None:
    global _overlay_enabled, _overlay_line_count, _overlay_font_size, _overlay_color

    _overlay_enabled = _parse_bool_value(
        config.get_str(CONFIG_OVERLAY_ENABLED),
        DEFAULT_OVERLAY_ENABLED,
    )

    raw_lines = config.get_str(CONFIG_OVERLAY_LINES)
    try:
        parsed_lines = int(str(raw_lines).strip())
    except (TypeError, ValueError):
        parsed_lines = DEFAULT_OVERLAY_LINES
    if parsed_lines < 1:
        parsed_lines = DEFAULT_OVERLAY_LINES
    _overlay_line_count = parsed_lines

    raw_size = (config.get_str(CONFIG_OVERLAY_FONT_SIZE) or "").strip().lower()
    if raw_size not in OVERLAY_FONT_SIZES:
        raw_size = DEFAULT_OVERLAY_FONT_SIZE
    _overlay_font_size = raw_size

    raw_color = (config.get_str(CONFIG_OVERLAY_COLOR) or "").strip()
    _overlay_color = raw_color or DEFAULT_OVERLAY_COLOR

    if overlay_support is not None:
        _debug(
            "Applying overlay settings: enabled=%s lines=%d font=%s color=%s",
            _overlay_enabled,
            _overlay_line_count,
            _overlay_font_size,
            _overlay_color,
        )
        overlay_support.configure(
            _overlay_enabled,
            _overlay_line_count,
            _overlay_font_size,
            _overlay_color,
        )
    else:
        _debug(
            "Overlay support module unavailable; loaded settings enabled=%s lines=%d font=%s color=%s",
            _overlay_enabled,
            _overlay_line_count,
            _overlay_font_size,
            _overlay_color,
        )


def _emit_overlay_started(reason: str) -> None:
    """Send a synthetic overlay event so overlay delivery can be verified quickly."""

    if overlay_support is None:
        _debug('OverlayStarted not sent (%s): overlay support unavailable.', reason)
        return
    if not _overlay_enabled:
        _debug('OverlayStarted not sent (%s): overlay disabled.', reason)
        return
    try:
        overlay_support.push_event("OverlayStarted", None)
        _debug('Sent synthetic overlay event "OverlayStarted" (%s).', reason)
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.warning('Failed to send synthetic overlay event "OverlayStarted": %s', exc)


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

    requires_rotation = _log_rotation_enabled

    if existing_handler is not None and current_path == desired_path:
        handler_matches = False
        if requires_rotation and isinstance(existing_handler, RotatingFileHandler):
            max_bytes = getattr(existing_handler, "maxBytes", None)
            backup_count = getattr(existing_handler, "backupCount", None)
            handler_matches = (
                max_bytes == _log_rotation_max_bytes
                and backup_count == _log_rotation_backup_count
            )
        elif not requires_rotation and not isinstance(existing_handler, RotatingFileHandler):
            handler_matches = True

        if handler_matches:
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
        if requires_rotation:
            handler = RotatingFileHandler(
                desired_path,
                encoding="utf-8",
                maxBytes=_log_rotation_max_bytes,
                backupCount=_log_rotation_backup_count,
            )
        else:
            handler = logging.FileHandler(desired_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
        handler.setLevel(logging.INFO)
        setattr(handler, FILE_HANDLER_FLAG, True)
        logger.addHandler(handler)
        _log_file_path = desired_path
        _debug("File logging initialised at %s", desired_path)
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
            _debug("Journal event forwarding to EDMC log enabled.")
    else:
        if _edmc_forward_handler is not None:
            logger.removeHandler(_edmc_forward_handler)
            _edmc_forward_handler = None
            _debug("Journal event forwarding to EDMC log disabled.")


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


def _apply_log_path_value(raw_path: Optional[str]) -> None:
    """Update the active log file path, persisting it to config immediately."""

    global _custom_log_path

    trimmed = (raw_path or "").strip()
    desired_default = _default_log_file().expanduser()

    candidate: Optional[Path]
    if trimmed:
        try:
            candidate = Path(trimmed).expanduser()
        except Exception:
            candidate = None
    else:
        candidate = None

    if candidate is not None and candidate != desired_default:
        _custom_log_path = candidate
    else:
        _custom_log_path = None

    config.set(CONFIG_LOG_FILE_PATH, str(_custom_log_path) if _custom_log_path else "")
    _ensure_file_logging()
    _debug("Configured journal log file path: %s", _current_log_path())
    _update_profile_log_controls()


def _apply_forward_to_edmc_value(raw_value: Optional[bool]) -> None:
    """Toggle forwarding to the EDMC log immediately."""

    global _forward_to_edmc_log

    forward_native = bool(raw_value)
    previous = _forward_to_edmc_log
    _forward_to_edmc_log = forward_native
    config.set(CONFIG_FORWARD_TO_EDMC_LOG, forward_native)
    if forward_native != previous:
        _sync_edmc_forwarding()
        _debug("Forward-to-EDMC setting changed to %s", "enabled" if forward_native else "disabled")


def _sanitise_profile_suffix(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9-_]+", "_", name.strip())
    cleaned = cleaned.strip("-_")
    return cleaned


def _is_default_profile(name: str) -> bool:
    return name.strip().lower() == DEFAULT_PROFILE_NAME.lower()


def _known_profile_suffixes() -> Set[str]:
    suffixes = {_sanitise_profile_suffix(name) for name in _profiles.keys()}
    suffixes.add(_sanitise_profile_suffix(DEFAULT_PROFILE_NAME))
    suffixes.discard("")
    return suffixes


def _current_profile_suffix_enabled(profile_name: str) -> bool:
    suffix = _sanitise_profile_suffix(profile_name)
    if not suffix or _is_default_profile(profile_name):
        return False
    try:
        raw_value = prefs_state.log_path_var.get() if prefs_state.log_path_var else _current_log_path()
    except Exception:
        raw_value = _current_log_path()
    try:
        current_path = Path(raw_value).expanduser()
    except Exception:
        current_path = _default_log_file().expanduser()
    return current_path.stem.endswith(f"-{suffix}")


def _set_profile_suffix_enabled(enabled: bool, profile_name: Optional[str] = None) -> None:
    if profile_name is None:
        profile_name = _active_profile

    if _is_default_profile(profile_name):
        enabled = False

    suffix = _sanitise_profile_suffix(profile_name)
    if not suffix:
        enabled = False

    try:
        raw_value = prefs_state.log_path_var.get() if prefs_state.log_path_var else _current_log_path()
    except Exception:
        raw_value = _current_log_path()

    try:
        current_path = Path(raw_value).expanduser()
    except Exception:
        current_path = _default_log_file().expanduser()

    stem = current_path.stem
    if enabled:
        for candidate_suffix in sorted(_known_profile_suffixes(), key=len, reverse=True):
            token = f"-{candidate_suffix}"
            if stem.endswith(token):
                stem = stem[: -len(token)]
                break
        new_stem = f"{stem}-{suffix}"
    else:
        token = f"-{suffix}"
        if stem.endswith(token):
            stem = stem[: -len(token)]
        new_stem = stem

    ext = current_path.suffix or ".log"
    new_path = current_path.with_name(new_stem + ext)

    _apply_log_path_value(str(new_path))
    if prefs_state.log_path_var is not None:
        prefs_state.log_path_var.set(str(new_path))

    if prefs_state.profile_log_var is not None:
        prefs_state.profile_log_var.set(enabled and not _is_default_profile(profile_name) and bool(suffix))

    _update_profile_log_controls()


def _update_profile_log_controls() -> None:
    if prefs_state.profile_log_var is None or prefs_state.profile_log_check is None:
        return

    if _is_default_profile(_active_profile):
        prefs_state.profile_log_var.set(False)
        prefs_state.profile_log_check.config(state=tk.DISABLED)
        return

    suffix = _sanitise_profile_suffix(_active_profile)
    if not suffix:
        prefs_state.profile_log_var.set(False)
        prefs_state.profile_log_check.config(state=tk.DISABLED)
        return

    is_enabled = _current_profile_suffix_enabled(_active_profile)
    prefs_state.profile_log_var.set(is_enabled)
    prefs_state.profile_log_check.config(state=tk.NORMAL)


def _refresh_rotation_inputs() -> None:
    if prefs_state.rotation_enabled_var is None:
        return
    enabled = bool(prefs_state.rotation_enabled_var.get())
    state = tk.NORMAL if enabled else tk.DISABLED
    if prefs_state.rotation_max_bytes_entry is not None:
        prefs_state.rotation_max_bytes_entry.config(state=state)
    if prefs_state.rotation_backup_count_entry is not None:
        prefs_state.rotation_backup_count_entry.config(state=state)


def _refresh_overlay_inputs() -> None:
    if prefs_state.overlay_enabled_var is None:
        return
    enabled = bool(prefs_state.overlay_enabled_var.get())
    state = tk.NORMAL if enabled else tk.DISABLED
    if prefs_state.overlay_lines_entry is not None:
        prefs_state.overlay_lines_entry.config(state=state)
    if prefs_state.overlay_font_menu is not None:
        prefs_state.overlay_font_menu.config(state=state)
    if prefs_state.overlay_color_entry is not None:
        prefs_state.overlay_color_entry.config(state=state)


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
        "rotation_enabled": _log_rotation_enabled,
        "rotation_max_bytes": _log_rotation_max_bytes,
        "rotation_backup_count": _log_rotation_backup_count,
    }


def _apply_settings(settings: Dict[str, Any]) -> None:
    global _filter_mode, _include_payload, _payload_limit, _logging_enabled, _forward_to_edmc_log, _custom_log_path
    global _log_rotation_enabled, _log_rotation_max_bytes, _log_rotation_backup_count

    defaults = _default_settings()

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

    _log_rotation_enabled = bool(settings.get("rotation_enabled", True))

    rotation_bytes = settings.get("rotation_max_bytes")
    if isinstance(rotation_bytes, (int, float)):
        rotation_bytes = int(rotation_bytes)
    else:
        try:
            rotation_bytes = int(str(rotation_bytes))
        except (TypeError, ValueError):
            rotation_bytes = defaults["rotation_max_bytes"]
    if rotation_bytes <= 0:
        rotation_bytes = defaults["rotation_max_bytes"]
    _log_rotation_max_bytes = rotation_bytes

    rotation_backups = settings.get("rotation_backup_count")
    if isinstance(rotation_backups, (int, float)):
        rotation_backups = int(rotation_backups)
    else:
        try:
            rotation_backups = int(str(rotation_backups))
        except (TypeError, ValueError):
            rotation_backups = defaults["rotation_backup_count"]
    if rotation_backups < 1:
        rotation_backups = defaults["rotation_backup_count"]
    _log_rotation_backup_count = rotation_backups

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
    config.set(CONFIG_ROTATION_ENABLED, _log_rotation_enabled)
    config.set(CONFIG_ROTATION_MAX_BYTES, str(_log_rotation_max_bytes))
    config.set(CONFIG_ROTATION_BACKUP_COUNT, str(_log_rotation_backup_count))
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
    _update_profile_log_controls()
    if prefs_state.rotation_enabled_var is not None:
        prefs_state.rotation_enabled_var.set(_log_rotation_enabled)
    if prefs_state.rotation_max_bytes_var is not None:
        prefs_state.rotation_max_bytes_var.set(str(_log_rotation_max_bytes))
    if prefs_state.rotation_backup_count_var is not None:
        prefs_state.rotation_backup_count_var.set(str(_log_rotation_backup_count))
    if prefs_state.overlay_enabled_var is not None:
        prefs_state.overlay_enabled_var.set(_overlay_enabled)
    if prefs_state.overlay_lines_var is not None:
        prefs_state.overlay_lines_var.set(str(_overlay_line_count))
    if prefs_state.overlay_font_size_var is not None:
        prefs_state.overlay_font_size_var.set(_overlay_font_size)
    if prefs_state.overlay_color_var is not None:
        prefs_state.overlay_color_var.set(_overlay_color)
    _refresh_overlay_inputs()
    _refresh_rotation_inputs()


def _update_state_from_widgets() -> Dict[str, Any]:
    global _filter_mode, _include_payload, _payload_limit, _logging_enabled, _forward_to_edmc_log, _custom_log_path
    global _log_rotation_enabled, _log_rotation_max_bytes, _log_rotation_backup_count
    global _overlay_enabled, _overlay_line_count, _overlay_font_size, _overlay_color

    overlay_was_enabled = _overlay_enabled

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
        _apply_log_path_value(prefs_state.log_path_var.get())

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
        _apply_forward_to_edmc_value(prefs_state.forward_to_edmc_var.get())

    if prefs_state.logging_enabled_var is not None:
        logging_enabled = bool(prefs_state.logging_enabled_var.get())
        _logging_enabled = logging_enabled
        config.set(CONFIG_LOGGING_ENABLED, logging_enabled)

    defaults = _default_settings()

    if prefs_state.rotation_enabled_var is not None:
        rotation_enabled = bool(prefs_state.rotation_enabled_var.get())
        _log_rotation_enabled = rotation_enabled
        config.set(CONFIG_ROTATION_ENABLED, rotation_enabled)

    if prefs_state.rotation_max_bytes_var is not None:
        raw_bytes = (prefs_state.rotation_max_bytes_var.get() or "").strip()
        try:
            parsed_bytes = int(raw_bytes)
        except ValueError:
            parsed_bytes = defaults["rotation_max_bytes"]
        if parsed_bytes <= 0:
            parsed_bytes = defaults["rotation_max_bytes"]
        _log_rotation_max_bytes = parsed_bytes
        prefs_state.rotation_max_bytes_var.set(str(parsed_bytes))
        config.set(CONFIG_ROTATION_MAX_BYTES, str(parsed_bytes))

    if prefs_state.rotation_backup_count_var is not None:
        raw_backups = (prefs_state.rotation_backup_count_var.get() or "").strip()
        try:
            parsed_backups = int(raw_backups)
        except ValueError:
            parsed_backups = defaults["rotation_backup_count"]
        if parsed_backups < 1:
            parsed_backups = defaults["rotation_backup_count"]
        _log_rotation_backup_count = parsed_backups
        prefs_state.rotation_backup_count_var.set(str(parsed_backups))
        config.set(CONFIG_ROTATION_BACKUP_COUNT, str(parsed_backups))

    if prefs_state.overlay_enabled_var is not None:
        overlay_enabled = bool(prefs_state.overlay_enabled_var.get())
        _overlay_enabled = overlay_enabled
        config.set(CONFIG_OVERLAY_ENABLED, overlay_enabled)

    if prefs_state.overlay_lines_var is not None:
        raw_lines = (prefs_state.overlay_lines_var.get() or "").strip()
        try:
            parsed_lines = int(raw_lines)
        except ValueError:
            parsed_lines = DEFAULT_OVERLAY_LINES
        if parsed_lines < 1:
            parsed_lines = DEFAULT_OVERLAY_LINES
        _overlay_line_count = parsed_lines
        prefs_state.overlay_lines_var.set(str(parsed_lines))
        config.set(CONFIG_OVERLAY_LINES, str(parsed_lines))

    if prefs_state.overlay_font_size_var is not None:
        size_value = (prefs_state.overlay_font_size_var.get() or "").strip().lower()
        if size_value not in OVERLAY_FONT_SIZES:
            size_value = DEFAULT_OVERLAY_FONT_SIZE
        _overlay_font_size = size_value
        prefs_state.overlay_font_size_var.set(size_value)
        config.set(CONFIG_OVERLAY_FONT_SIZE, size_value)

    if prefs_state.overlay_color_var is not None:
        color_value = (prefs_state.overlay_color_var.get() or "").strip()
        if not color_value:
            color_value = DEFAULT_OVERLAY_COLOR
        _overlay_color = color_value
        prefs_state.overlay_color_var.set(color_value)
        config.set(CONFIG_OVERLAY_COLOR, color_value)

    _ensure_file_logging()
    _refresh_rotation_inputs()
    _refresh_overlay_inputs()
    if prefs_state.profile_log_var is not None:
        desired_enabled = bool(prefs_state.profile_log_var.get())
        if desired_enabled != _current_profile_suffix_enabled(_active_profile):
            _set_profile_suffix_enabled(desired_enabled)
        else:
            _update_profile_log_controls()

    _sync_edmc_forwarding()
    if overlay_support is not None:
        overlay_support.configure(
            _overlay_enabled,
            _overlay_line_count,
            _overlay_font_size,
            _overlay_color,
        )
    if _overlay_enabled and not overlay_was_enabled:
        _emit_overlay_started("prefs-enabled")

    return _sanitize_settings(_get_current_settings())


def _refresh_profile_menu() -> None:
    if prefs_state.profile_menu is None or prefs_state.profile_var is None:
        return
    menu = prefs_state.profile_menu["menu"]
    menu.delete(0, "end")
    for name in sorted(_profiles.keys()):
        menu.add_command(label=name, command=lambda value=name: _on_profile_selected(value))
    prefs_state.profile_var.set(_active_profile)
    _update_profile_log_controls()


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
def plugin_start3(plugin_dir: str) -> str:
    if overlay_support is not None:
        overlay_support.init(PLUGIN_NAME, logging.getLogger(appname))
        _debug("Overlay support initialised.")
    else:
        _debug("Overlay support module not loaded; overlay events will be skipped.")
    _ensure_config_defaults()
    _load_profiles()
    _load_overlay_settings()
    _emit_overlay_started("startup")
    logger.info("Running %s version %s", PLUGIN_NAME, PLUGIN_VERSION)
    logger.info(
        "Initialised %s with profile '%s' (ignored %d events)",
        PLUGIN_NAME,
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
    _debug(
        "Startup settings profile=%s mode=%s ignored=%d included=%d payload=%s limit=%s journal_logging=%s overlay=%s",
        _active_profile,
        _filter_mode,
        len(_ignored_events),
        len(_included_events),
        _include_payload,
        _payload_limit if _payload_limit is not None else "none",
        _logging_enabled,
        _overlay_enabled,
    )
    return PLUGIN_NAME


def plugin_stop() -> None:
    global _edmc_forward_handler
    logger.info("%s stopped", PLUGIN_NAME)
    if overlay_support is not None:
        overlay_support.shutdown()
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

    nb.Label(frame, text="EDMC-LogEventMiner", font=("TkDefaultFont", 10, "bold")).grid(
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
    def _on_forward_toggle() -> None:
        if prefs_state.forward_to_edmc_var is None:
            return
        _apply_forward_to_edmc_value(prefs_state.forward_to_edmc_var.get())

    nb.Checkbutton(
        frame,
        text="Also send log output to EDMC log",
        variable=prefs_state.forward_to_edmc_var,
        command=_on_forward_toggle,
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
    nb.EntryMenu(new_profile_frame, textvariable=prefs_state.new_profile_var, width=20).grid(
        row=0, column=0, sticky=tk.W
    )
    nb.Button(new_profile_frame, text="Save profile", command=_on_create_profile).grid(
        row=0, column=1, sticky=tk.W, padx=(8, 0)
    )

    prefs_state.profile_log_var = tk.BooleanVar(value=False)

    def _on_profile_log_toggle() -> None:
        if prefs_state.profile_log_var is None:
            return
        _set_profile_suffix_enabled(bool(prefs_state.profile_log_var.get()))

    profile_log_check = nb.Checkbutton(
        new_profile_frame,
        text="Append profile name to log file",
        variable=prefs_state.profile_log_var,
        command=_on_profile_log_toggle,
    )
    profile_log_check.grid(row=0, column=2, sticky=tk.W, padx=(8, 0))
    prefs_state.profile_log_check = profile_log_check
    current_row += 1

    nb.Label(frame, text="Log file location:").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 4)
    )
    log_path_frame = nb.Frame(frame)
    log_path_frame.grid(row=current_row, column=1, sticky=tk.W + tk.E, padx=10, pady=(0, 4))
    log_path_frame.columnconfigure(0, weight=1)
    prefs_state.log_path_var = tk.StringVar(value=_current_log_path())
    log_path_entry = tk.Entry(log_path_frame, textvariable=prefs_state.log_path_var, width=50)
    log_path_entry.grid(row=0, column=0, sticky=tk.EW)

    def _apply_log_path_from_var() -> None:
        if prefs_state.log_path_var is None:
            return
        _apply_log_path_value(prefs_state.log_path_var.get())

    def _commit_log_path(_event=None):
        _apply_log_path_from_var()
        return None

    log_path_entry.bind("<FocusOut>", _commit_log_path)
    log_path_entry.bind("<Return>", _commit_log_path)

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
            _apply_log_path_from_var()

    def _reset_log_path() -> None:
        prefs_state.log_path_var.set(str(_default_log_file()))
        _apply_log_path_from_var()

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

    nb.Label(frame, text="Log rotation:").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 4)
    )
    rotation_frame = nb.Frame(frame)
    rotation_frame.grid(row=current_row, column=1, sticky=tk.W + tk.E, padx=10, pady=(0, 4))
    rotation_frame.columnconfigure(1, weight=1)

    prefs_state.rotation_enabled_var = tk.BooleanVar(value=_log_rotation_enabled)
    prefs_state.rotation_max_bytes_var = tk.StringVar(value=str(_log_rotation_max_bytes))
    prefs_state.rotation_backup_count_var = tk.StringVar(value=str(_log_rotation_backup_count))

    def _commit_rotation_settings(_event=None):
        _update_state_from_widgets()
        return None

    def _on_rotation_toggle() -> None:
        _update_state_from_widgets()

    rotation_check = nb.Checkbutton(
        rotation_frame,
        text="Enable log rotation",
        variable=prefs_state.rotation_enabled_var,
        command=_on_rotation_toggle,
    )
    rotation_check.grid(row=0, column=0, columnspan=3, sticky=tk.W)

    nb.Label(rotation_frame, text="Max size (bytes):").grid(
        row=1, column=0, sticky=tk.W, pady=(4, 0)
    )
    rotation_max_entry = nb.EntryMenu(
        rotation_frame,
        textvariable=prefs_state.rotation_max_bytes_var,
        width=12,
    )
    rotation_max_entry.grid(row=1, column=1, sticky=tk.W, padx=(8, 0), pady=(4, 0))
    rotation_max_entry.bind("<FocusOut>", _commit_rotation_settings)
    rotation_max_entry.bind("<Return>", _commit_rotation_settings)

    nb.Label(rotation_frame, text="Backups:").grid(
        row=1, column=2, sticky=tk.W, padx=(16, 0), pady=(4, 0))
    rotation_backup_entry = nb.EntryMenu(
        rotation_frame,
        textvariable=prefs_state.rotation_backup_count_var,
        width=6,
    )
    rotation_backup_entry.grid(row=1, column=3, sticky=tk.W, padx=(4, 0), pady=(4, 0))
    rotation_backup_entry.bind("<FocusOut>", _commit_rotation_settings)
    rotation_backup_entry.bind("<Return>", _commit_rotation_settings)

    prefs_state.rotation_max_bytes_entry = rotation_max_entry
    prefs_state.rotation_backup_count_entry = rotation_backup_entry

    current_row += 1
    _refresh_rotation_inputs()

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
        text="Include event payload in log entries",
        variable=prefs_state.include_payload_var,
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 6))
    current_row += 1

    nb.Label(frame, text="Payload character limit (blank for unlimited):").grid(
        row=current_row, column=0, sticky=tk.W, padx=10, pady=(0, 10)
    )
    prefs_state.payload_limit_var = tk.StringVar(value="" if _payload_limit is None else str(_payload_limit))
    nb.EntryMenu(frame, textvariable=prefs_state.payload_limit_var, width=10).grid(
        row=current_row, column=1, sticky=tk.W, padx=10, pady=(0, 10)
    )
    current_row += 1

    overlay_group = tk.LabelFrame(frame, text="Overlay")
    overlay_group.grid(row=current_row, column=0, columnspan=2, sticky=tk.W + tk.E, padx=10, pady=(6, 10))
    overlay_group.columnconfigure(0, weight=1)

    overlay_frame = nb.Frame(overlay_group)
    overlay_frame.grid(row=0, column=0, sticky=tk.W + tk.E, padx=8, pady=6)
    overlay_frame.columnconfigure(1, weight=1)

    prefs_state.overlay_enabled_var = tk.BooleanVar(value=_overlay_enabled)

    def _on_overlay_toggle() -> None:
        _refresh_overlay_inputs()

    nb.Checkbutton(
        overlay_frame,
        text="Enable overlay",
        variable=prefs_state.overlay_enabled_var,
        command=_on_overlay_toggle,
    ).grid(row=0, column=0, sticky=tk.W)

    overlay_link = nb.Label(
        overlay_frame,
        text="(Get EDMCModernOverlay here)",
        foreground="blue",
        cursor="hand2",
        font=("TkDefaultFont", 9, "underline"),
    )
    overlay_link.grid(row=0, column=1, sticky=tk.W, padx=(8, 0))
    overlay_link.bind(
        "<Button-1>",
        lambda _event: webbrowser.open_new_tab("https://github.com/SweetJonnySauce/EDMCModernOverlay"),
    )

    nb.Label(overlay_frame, text="Lines:").grid(row=1, column=0, sticky=tk.W, pady=(4, 0))
    prefs_state.overlay_lines_var = tk.StringVar(value=str(_overlay_line_count))
    overlay_lines_entry = nb.EntryMenu(overlay_frame, textvariable=prefs_state.overlay_lines_var, width=6)
    overlay_lines_entry.grid(row=1, column=1, sticky=tk.W, padx=(8, 0), pady=(4, 0))
    prefs_state.overlay_lines_entry = overlay_lines_entry

    nb.Label(overlay_frame, text="Font size:").grid(row=2, column=0, sticky=tk.W, pady=(4, 0))
    prefs_state.overlay_font_size_var = tk.StringVar(value=_overlay_font_size)
    overlay_size_menu = nb.OptionMenu(
        overlay_frame,
        prefs_state.overlay_font_size_var,
        _overlay_font_size,
        *OVERLAY_FONT_SIZES,
    )
    overlay_size_menu.grid(row=2, column=1, sticky=tk.W, padx=(8, 0), pady=(4, 0))
    prefs_state.overlay_font_menu = overlay_size_menu

    nb.Label(overlay_frame, text="Text color:").grid(row=3, column=0, sticky=tk.W, pady=(4, 0))
    prefs_state.overlay_color_var = tk.StringVar(value=_overlay_color)
    overlay_color_entry = nb.EntryMenu(overlay_frame, textvariable=prefs_state.overlay_color_var, width=12)
    overlay_color_entry.grid(row=3, column=1, sticky=tk.W, padx=(8, 0), pady=(4, 0))
    prefs_state.overlay_color_entry = overlay_color_entry

    current_row += 1
    _refresh_overlay_inputs()

    _populate_prefs_fields()
    _refresh_profile_menu()

    return frame


def prefs_changed(cmdr: str, is_beta: bool) -> None:
    settings_snapshot = _update_state_from_widgets()
    _profiles[_active_profile] = _clone_settings(settings_snapshot)
    _save_profiles()
    _refresh_profile_menu()
    _populate_prefs_fields()
    _debug(
        "Preferences updated profile=%s mode=%s ignored=%d included=%d payload=%s limit=%s journal_logging=%s forward_to_edmc=%s",
        _active_profile,
        settings_snapshot.get("filter_mode"),
        len(settings_snapshot.get("ignored_events", [])),
        len(settings_snapshot.get("included_events", [])),
        settings_snapshot.get("include_payload"),
        settings_snapshot.get("payload_limit"),
        settings_snapshot.get("logging_enabled"),
        settings_snapshot.get("forward_to_edmc_log"),
    )


def journal_entry(cmdr, is_beta, system, station, entry, state) -> None:
    if not _logging_enabled:
        _debug("Journal logging disabled; skipping event processing.")
        return

    event_name = entry.get("event")
    if not event_name:
        _debug("Journal entry missing event field: %s", entry)
        return

    if _filter_mode == "include":
        if _included_events and event_name not in _included_events:
            _debug("Skipping event %s because it is not in the include list.", event_name)
            return
        if not _included_events:
            _debug("Include-only mode set but no events defined; skipping %s", event_name)
            return
    else:
        if event_name in _ignored_events:
            _debug("Skipping event %s because it is in the ignore list.", event_name)
            return

    if overlay_support is not None:
        _debug("Queueing overlay event: %s (timestamp=%s)", event_name, entry.get("timestamp"))
        overlay_support.push_event(event_name, entry.get("timestamp"))

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
            _debug("Payload truncated to %d chars for %s", _payload_limit, event_name)

    if payload is not None:
        logger.info("Journal event %s: %s", event_name, payload)
    else:
        logger.info("Journal event %s", event_name)

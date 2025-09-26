"""Simple EDMC plugin that logs every journal event."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Set

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

_DEFAULT_IGNORE_EVENTS = ("Music", "Fileheader")
_DEFAULT_INCLUDE_EVENTS: tuple[str, ...] = ()


@dataclass
class _PrefsState:
    ignore_widget: tk.Text | None = None
    include_widget: tk.Text | None = None
    include_payload_var: tk.BooleanVar | None = None
    mode_var: tk.StringVar | None = None


_prefs_state = _PrefsState()
_ignored_events: Set[str] = set()
_included_events: Set[str] = set()
_include_payload = True
_filter_mode = "exclude"  # either "exclude" or "include"


def _normalise_event_names(raw_events: Iterable[str]) -> Set[str]:
    cleaned = {item.strip() for item in raw_events if item.strip()}
    return {item for item in cleaned}


def _parse_ignore_list(raw: str) -> Set[str]:
    for token in ",;|":
        raw = raw.replace(token, "\n")
    return _normalise_event_names(raw.splitlines())


def _load_ignore_events() -> None:
    saved = config.get_str(_CONFIG_IGNORE_EVENTS)
    if saved:
        events = _parse_ignore_list(saved)
    else:
        events = set(_DEFAULT_IGNORE_EVENTS)
    _ignored_events.clear()
    _ignored_events.update(events)


def _load_include_events() -> None:
    saved = config.get_str(_CONFIG_INCLUDE_EVENTS)
    if saved:
        events = _parse_ignore_list(saved)
    else:
        events = set(_DEFAULT_INCLUDE_EVENTS)
    _included_events.clear()
    _included_events.update(events)


def _serialise_events(events: Iterable[str]) -> str:
    return "\n".join(sorted(_normalise_event_names(events)))


def _load_settings() -> None:
    global _include_payload, _filter_mode
    _load_ignore_events()
    _load_include_events()
    include = config.get_bool(_CONFIG_INCLUDE_PAYLOAD)
    if include is None:
        include = True
    _include_payload = bool(include)
    mode = config.get_str(_CONFIG_MODE)
    if mode not in {"include", "exclude"}:
        mode = "exclude"
    _filter_mode = mode


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

    _prefs_state.include_payload_var = tk.BooleanVar(value=_include_payload)
    nb.Checkbutton(
        frame,
        text="Include full event payload in log entries",
        variable=_prefs_state.include_payload_var,
    ).grid(row=current_row, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 10))

    return frame


def prefs_changed(cmdr: str, is_beta: bool) -> None:
    global _include_payload, _filter_mode

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

    if _prefs_state.include_payload_var is not None:
        include_payload = bool(_prefs_state.include_payload_var.get())
        _include_payload = include_payload
        config.set(_CONFIG_INCLUDE_PAYLOAD, include_payload)
        _logger.info(
            "Event payload logging %s",
            "enabled" if include_payload else "disabled",
        )


def journal_entry(cmdr, is_beta, system, station, entry, state) -> None:
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
        _logger.info("Journal event %s: %s", event_name, payload)
    else:
        _logger.info("Journal event %s", event_name)

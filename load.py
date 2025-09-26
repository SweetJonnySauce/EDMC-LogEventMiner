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
_DEFAULT_IGNORE_EVENTS = ("Music", "Fileheader")


@dataclass
class _PrefsState:
    ignore_widget: tk.Text | None = None


_prefs_state = _PrefsState()
_ignored_events: Set[str] = set()


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


def _serialise_ignore_events(events: Iterable[str]) -> str:
    return "\n".join(sorted(_normalise_event_names(events)))


plugin_info = {
    "plugin_version": "1.0.0",
    "plugin_name": _PLUGIN_NAME,
    "plugin_description": "Logs journal events to the EDMC log with optional event ignore list.",
}


def plugin_start3(plugin_dir: str) -> str:
    _load_ignore_events()
    _logger.info(
        "TestEventLogger initialised. Ignoring %d events: %s",
        len(_ignored_events),
        ", ".join(sorted(_ignored_events)) or "<none>",
    )
    return "TestEventLogger"


def plugin_stop() -> None:
    _logger.info("TestEventLogger stopped")


def plugin_app(parent: tk.Frame) -> tk.Frame | None:
    return None


def plugin_prefs(parent: nb.Notebook, cmdr: str, is_beta: bool) -> tk.Frame:
    frame = nb.Frame(parent)
    frame.columnconfigure(1, weight=1)

    nb.Label(frame, text="Test Event Logger", font=("TkDefaultFont", 10, "bold")).grid(
        row=0, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(10, 4)
    )
    nb.Label(
        frame,
        text=(
            "Logs incoming Elite Dangerous journal events to the EDMC log. "
            "Provide events to ignore (one per line)."
        ),
        wraplength=400,
        justify=tk.LEFT,
    ).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 10))

    nb.Label(frame, text="Ignored events:").grid(row=2, column=0, sticky=tk.NW, padx=10, pady=(0, 6))

    ignore_box = tk.Text(frame, width=40, height=8)
    ignore_box.insert("1.0", "\n".join(sorted(_ignored_events)))
    ignore_box.grid(row=2, column=1, sticky=tk.EW, padx=10, pady=(0, 6))
    _prefs_state.ignore_widget = ignore_box

    nb.Label(
        frame,
        text="Events listed here will not be written to the log.",
        wraplength=400,
        justify=tk.LEFT,
        font=("TkDefaultFont", 8),
    ).grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 10))

    return frame


def prefs_changed(cmdr: str, is_beta: bool) -> None:
    if _prefs_state.ignore_widget is None:
        return
    raw = _prefs_state.ignore_widget.get("1.0", tk.END)
    events = _parse_ignore_list(raw)
    if not events:
        events = set(_DEFAULT_IGNORE_EVENTS)
    _ignored_events.clear()
    _ignored_events.update(events)
    config.set(_CONFIG_IGNORE_EVENTS, _serialise_ignore_events(events))
    _logger.info("Updated ignore list: %s", ", ".join(sorted(_ignored_events)))


def journal_entry(cmdr, is_beta, system, station, entry, state) -> None:
    event_name = entry.get("event")
    if not event_name:
        _logger.debug("Received journal entry without event field: %s", entry)
        return
    if event_name in _ignored_events:
        return
    try:
        payload = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
    except TypeError:
        payload = repr(entry)
        _logger.warning(
            "Could not serialise journal event %s to JSON, using repr instead.",
            event_name,
        )
    _logger.info("Journal event %s: %s", event_name, payload)

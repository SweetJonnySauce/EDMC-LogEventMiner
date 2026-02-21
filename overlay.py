"""Overlay support for EDMC-LogEventMiner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import logging
import re
import threading
from typing import Optional

try:
    from overlay_plugin.overlay_api import PluginGroupingError, define_plugin_group  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    PluginGroupingError = Exception  # type: ignore[misc,assignment]
    define_plugin_group = None  # type: ignore[assignment]

try:
    from EDMCOverlay import edmcoverlay  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    try:
        from edmcoverlay import edmcoverlay  # type: ignore
    except Exception:  # pragma: no cover - optional dependency
        edmcoverlay = None  # type: ignore[assignment]


FONT_SIZE_OPTIONS = ("small", "medium", "large")
_OVERLAY_SIZE_MAP = {
    "small": "small",
    "medium": "normal",
    "large": "large",
}
_LINE_HEIGHT = {
    "small": 12,
    "medium": 16,
    "large": 26,
}
_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_DISPLAY_TTL_SECONDS = 60
_REDRAW_INTERVAL_SECONDS = 30.0


@dataclass
class OverlayConfig:
    enabled: bool = False
    max_lines: int = 10
    font_size: str = "medium"
    color: str = "orange"


@dataclass
class OverlayLine:
    event_name: str
    timestamp: Optional[str]
    count: int = 1

    def format(self) -> str:
        time_text = _format_time(self.timestamp)
        suffix = f" ({self.count})" if self.count >= 2 else ""
        return f"{time_text} {self.event_name}{suffix}"


class OverlayManager:
    def __init__(self, plugin_name: str, logger: logging.Logger) -> None:
        self._plugin_name = plugin_name
        self._logger = logger
        self._overlay = None
        self._config = OverlayConfig()
        self._lines: list[OverlayLine] = []
        self._last_rendered = 0
        self._group_registered = False
        self._redraw_stop = threading.Event()
        self._redraw_thread = threading.Thread(target=self._redraw_loop, daemon=True)
        self._redraw_thread.start()
        safe_prefix = plugin_name.lower().replace(" ", "").replace("-", "")
        self._id_prefix = f"{safe_prefix}-overlay-"

    def register_group(self) -> None:
        if self._group_registered or define_plugin_group is None:
            return
        try:
            define_plugin_group(
                plugin_group=self._plugin_name,
                matching_prefixes=[self._id_prefix],
                id_prefix_group=self._plugin_name,
                id_prefixes=[self._id_prefix],
                id_prefix_group_anchor="nw",
            )
            self._group_registered = True
        except PluginGroupingError as exc:  # pragma: no cover - runtime specific
            self._logger.debug("Overlay plugin group registration failed: %s", exc)
        except Exception as exc:  # pragma: no cover - defensive guard
            self._logger.debug("Overlay plugin group registration error: %s", exc)

    def configure(self, *, enabled: bool, max_lines: int, font_size: str, color: str) -> None:
        self._config.enabled = bool(enabled)
        self._config.max_lines = max(1, int(max_lines))
        self._config.font_size = _normalise_font_size(font_size)
        self._config.color = _normalise_color(color, self._config.color)

        if not self._config.enabled:
            self.clear()
            return

        self.register_group()
        if self._lines:
            self._lines = self._lines[-self._config.max_lines :]
        self._render()

    def push_event(self, event_name: str, timestamp: Optional[str]) -> None:
        if not self._config.enabled:
            return
        if not event_name:
            return

        time_text = _format_time(timestamp)
        if self._lines and self._lines[-1].event_name == event_name:
            last = self._lines[-1]
            last.count += 1
            last.timestamp = timestamp
        else:
            self._lines.append(OverlayLine(event_name=event_name, timestamp=timestamp))
            if len(self._lines) > self._config.max_lines:
                self._lines = self._lines[-self._config.max_lines :]
        self._render()

    def clear(self) -> None:
        self._lines.clear()
        if not self._ensure_overlay():
            self._last_rendered = 0
            return
        for index in range(self._last_rendered):
            self._overlay.send_message(
                f"{self._id_prefix}line-{index}",
                "",
                self._config.color,
                0,
                0,
                ttl=1,
                size=_OVERLAY_SIZE_MAP[self._config.font_size],
            )
        self._last_rendered = 0

    def shutdown(self) -> None:
        self.clear()
        self._redraw_stop.set()
        self._overlay = None

    def _ensure_overlay(self) -> bool:
        if self._overlay is not None:
            return True
        if edmcoverlay is None:
            return False
        try:
            self._overlay = edmcoverlay.Overlay()
            return True
        except Exception as exc:  # pragma: no cover - runtime specific
            self._logger.debug("Failed to initialise overlay client: %s", exc)
            self._overlay = None
            return False

    def _render(self) -> None:
        if not self._ensure_overlay():
            return
        size_token = _OVERLAY_SIZE_MAP[self._config.font_size]
        line_height = _LINE_HEIGHT[self._config.font_size]

        start_row = max(self._config.max_lines - len(self._lines), 0)
        for index, entry in enumerate(self._lines):
            text = entry.format()
            self._overlay.send_message(
                f"{self._id_prefix}line-{index}",
                text,
                self._config.color,
                0,
                line_height * (start_row + index),
                ttl=_DISPLAY_TTL_SECONDS,
                size=size_token,
            )

        previous = self._last_rendered
        for index in range(len(self._lines), previous):
            self._overlay.send_message(
                f"{self._id_prefix}line-{index}",
                "",
                self._config.color,
                0,
                0,
                ttl=1,
                size=size_token,
            )
        self._last_rendered = len(self._lines)

    def _redraw_loop(self) -> None:
        while not self._redraw_stop.wait(_REDRAW_INTERVAL_SECONDS):
            if self._config.enabled and self._lines:
                self._render()


_manager: Optional[OverlayManager] = None


def init(plugin_name: str, logger: logging.Logger) -> None:
    global _manager
    if _manager is None:
        _manager = OverlayManager(plugin_name, logger)
    _manager.register_group()


def configure(enabled: bool, max_lines: int, font_size: str, color: str) -> None:
    if _manager is None:
        return
    _manager.configure(
        enabled=enabled,
        max_lines=max_lines,
        font_size=font_size,
        color=color,
    )


def push_event(event_name: str, timestamp: Optional[str]) -> None:
    if _manager is None:
        return
    _manager.push_event(event_name, timestamp)


def shutdown() -> None:
    if _manager is None:
        return
    _manager.shutdown()


def _normalise_font_size(value: str) -> str:
    size = (value or "").strip().lower()
    if size not in FONT_SIZE_OPTIONS:
        return "medium"
    return size


def _normalise_color(value: str, fallback: str) -> str:
    candidate = (value or "").strip()
    if not candidate:
        return fallback
    if candidate.startswith("#"):
        if _HEX_COLOR_RE.fullmatch(candidate):
            return candidate
        return fallback
    return candidate


def _format_time(timestamp: Optional[str]) -> str:
    if timestamp:
        try:
            raw = timestamp.strip()
            if raw.endswith("Z"):
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(raw)
            return dt.strftime("%H:%M:%S")
        except Exception:
            pass
    return datetime.utcnow().strftime("%H:%M:%S")

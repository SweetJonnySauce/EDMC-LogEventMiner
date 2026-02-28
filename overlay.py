"""Overlay support for EDMC-LogEventMiner."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import logging
import re
import threading
import time
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
_BASE_X = 5
_BASE_Y = 955
_ANCHOR_OFFSET_X = _BASE_X
_ANCHOR_OFFSET_Y = _BASE_Y
_COLOR_CACHE: dict[str, Optional[tuple[int, int, int]]] = {}
_COLOR_ROOT = None
_LOG_PREFIX = "[overlay]"


@dataclass
class OverlayConfig:
    enabled: bool = False
    max_lines: int = 10
    font_size: str = "medium"
    color: str = "orange"
    color_rgb: Optional[tuple[int, int, int]] = None


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
        self._current_positions: list[int] = []
        self._target_positions: list[int] = []
        self._animating = False
        self._animation_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._fade_index: Optional[int] = None
        self._fade_step = 0
        self._fade_steps_total = 0
        self._fade_out_index: Optional[int] = None
        self._fade_out_step = 0
        self._fade_out_steps_total = 0
        self._trim_after_animation = False
        self._last_rendered = 0
        self._group_registered = False
        self._missing_backend_logged = False
        self._disabled_skip_logged = False
        self._redraw_stop = threading.Event()
        self._redraw_thread = threading.Thread(target=self._redraw_loop, daemon=True)
        self._redraw_thread.start()
        safe_prefix = plugin_name.lower().replace(" ", "").replace("-", "")
        self._id_prefix = f"{safe_prefix}-overlay-"
        self._debug(
            "manager created (id_prefix=%s, group_api=%s, backend=%s)",
            self._id_prefix,
            "available" if define_plugin_group is not None else "missing",
            "available" if edmcoverlay is not None else "missing",
        )

    def _debug(self, message: str, *args) -> None:
        self._logger.debug(f"[{self._plugin_name}] {_LOG_PREFIX} {message}", *args)

    def register_group(self) -> None:
        if self._group_registered:
            self._debug("plugin group already registered.")
            return
        if define_plugin_group is None:
            self._debug("plugin group API unavailable; using legacy absolute coordinates.")
            return
        try:
            define_plugin_group(
                plugin_group=self._plugin_name,
                matching_prefixes=[self._id_prefix],
                id_prefix_group=self._plugin_name,
                id_prefixes=[self._id_prefix],
                id_prefix_group_anchor="sw",
                id_prefix_offset_x=_ANCHOR_OFFSET_X,
                id_prefix_offset_y=_ANCHOR_OFFSET_Y,
                background_color="#AA000000",
                background_border_width=5,
            )
            self._group_registered = True
            self._debug("plugin group registered (group=%s, prefix=%s)", self._plugin_name, self._id_prefix)
        except PluginGroupingError as exc:  # pragma: no cover - runtime specific
            self._debug("plugin group registration failed: %s", exc)
        except Exception as exc:  # pragma: no cover - defensive guard
            self._debug("plugin group registration error: %s", exc)

    def configure(self, *, enabled: bool, max_lines: int, font_size: str, color: str) -> None:
        self._debug(
            "configure requested: enabled=%s lines=%s font=%s color=%s",
            enabled,
            max_lines,
            font_size,
            color,
        )
        with self._lock:
            self._config.enabled = bool(enabled)
            self._config.max_lines = max(1, int(max_lines))
            self._config.font_size = _normalise_font_size(font_size)
            self._config.color = _normalise_color(color, self._config.color)
            self._config.color_rgb = _color_to_rgb(self._config.color)

        self._debug(
            "configure resolved: enabled=%s lines=%s font=%s color=%s",
            self._config.enabled,
            self._config.max_lines,
            self._config.font_size,
            self._config.color,
        )
        if not self._config.enabled:
            self._debug("overlay disabled; clearing rendered lines.")
            self.clear()
            return

        self._disabled_skip_logged = False
        self.register_group()
        with self._lock:
            if self._lines:
                self._lines = self._lines[-self._config.max_lines :]
            self._animating = False
            self._current_positions = self._compute_target_positions()
            self._target_positions = list(self._current_positions)
            self._fade_index = None
            self._fade_step = 0
            self._fade_steps_total = 0
            self._fade_out_index = None
            self._fade_out_step = 0
            self._fade_out_steps_total = 0
            self._trim_after_animation = False
            positions = list(self._current_positions)
        self._render_with_positions(positions)
        self._debug("configured and rendered with %d retained lines.", len(self._lines))

    def push_event(self, event_name: str, timestamp: Optional[str]) -> None:
        if not self._config.enabled:
            if not self._disabled_skip_logged:
                self._debug("push_event skipped while overlay disabled.")
                self._disabled_skip_logged = True
            return
        if not event_name:
            self._debug("push_event skipped because event_name is empty.")
            return

        with self._lock:
            appended = False
            if self._lines and self._lines[-1].event_name == event_name:
                last = self._lines[-1]
                last.count += 1
                last.timestamp = timestamp
            else:
                self._lines.append(OverlayLine(event_name=event_name, timestamp=timestamp))
                if len(self._lines) > self._config.max_lines + 1:
                    self._lines = self._lines[-(self._config.max_lines + 1):]
                if len(self._lines) > self._config.max_lines:
                    self._trim_after_animation = True
                appended = True

            if appended:
                self._target_positions = self._compute_target_positions()
                line_height = _LINE_HEIGHT[self._config.font_size]
                new_index = len(self._lines) - 1
                start_positions: list[int] = []
                for index, target in enumerate(self._target_positions):
                    if index == new_index:
                        start_positions.append(target)
                    else:
                        start_positions.append(target + line_height)
                self._current_positions = start_positions
                self._animating = True
                self._fade_index = new_index
                self._fade_step = 0
                self._fade_steps_total = max(line_height, 1)
                if self._trim_after_animation:
                    self._fade_out_index = 0
                    self._fade_out_step = 0
                    self._fade_out_steps_total = max(line_height, 1)
                else:
                    self._fade_out_index = None
                    self._fade_out_step = 0
                    self._fade_out_steps_total = 0
                self._start_animation_thread()
                positions = list(self._current_positions)
            else:
                positions = list(self._current_positions or self._compute_target_positions())
            line_count = len(self._lines)
            trim_after = self._trim_after_animation
            animating = self._animating
        self._debug(
            "accepted event=%s appended=%s lines=%d trim_after=%s animating=%s",
            event_name,
            appended,
            line_count,
            trim_after,
            animating,
        )
        self._render_with_positions(positions)

    def clear(self) -> None:
        cleared_count = 0
        with self._lock:
            cleared_count = len(self._lines)
            self._lines.clear()
            self._current_positions = []
            self._target_positions = []
            self._animating = False
            self._fade_index = None
            self._fade_step = 0
            self._fade_steps_total = 0
            self._fade_out_index = None
            self._fade_out_step = 0
            self._fade_out_steps_total = 0
            self._trim_after_animation = False
        self._debug("clear requested; removed %d lines.", cleared_count)
        if not self._ensure_overlay():
            self._last_rendered = 0
            return
        for index in range(self._last_rendered):
            self._send_message(
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
        self._debug("shutdown requested.")
        self.clear()
        self._redraw_stop.set()
        self._overlay = None

    def _ensure_overlay(self) -> bool:
        if self._overlay is not None:
            return True
        if edmcoverlay is None:
            if not self._missing_backend_logged:
                self._logger.warning(
                    "[%s] %s EDMCOverlay backend module unavailable; overlay events cannot be sent.",
                    self._plugin_name,
                    _LOG_PREFIX,
                )
                self._missing_backend_logged = True
            return False
        try:
            self._overlay = edmcoverlay.Overlay()
            self._missing_backend_logged = False
            self._debug("overlay client initialised successfully.")
            return True
        except Exception as exc:  # pragma: no cover - runtime specific
            self._logger.warning(
                "[%s] %s failed to initialise overlay client: %s",
                self._plugin_name,
                _LOG_PREFIX,
                exc,
            )
            self._overlay = None
            return False

    def _send_message(
        self,
        message_id: str,
        text: str,
        color: str,
        x_pos: int,
        y_pos: int,
        *,
        ttl: int,
        size: str,
    ) -> bool:
        try:
            self._overlay.send_message(
                message_id,
                text,
                color,
                x_pos,
                y_pos,
                ttl=ttl,
                size=size,
            )
            return True
        except Exception as exc:
            self._logger.warning(
                "[%s] %s send_message failed id=%s error=%s",
                self._plugin_name,
                _LOG_PREFIX,
                message_id,
                exc,
            )
            return False

    def _render_with_positions(self, positions: list[int]) -> None:
        if not self._ensure_overlay():
            self._debug("render skipped because overlay client is unavailable.")
            return
        with self._lock:
            size_token = _OVERLAY_SIZE_MAP[self._config.font_size]
            color = self._config.color
            color_rgb = self._config.color_rgb
            fade_index = self._fade_index
            fade_step = self._fade_step
            fade_total = self._fade_steps_total
            fade_out_index = self._fade_out_index
            fade_out_step = self._fade_out_step
            fade_out_total = self._fade_out_steps_total
            entries = [entry.format() for entry in self._lines]
            x_pos = 0 if self._group_registered else _BASE_X

        self._debug(
            "rendering lines=%d size=%s group_registered=%s",
            len(entries),
            size_token,
            self._group_registered,
        )
        fade_alpha = None
        if fade_index is not None and fade_total > 0:
            fade_alpha = int(round(100 * min(fade_step, fade_total) / fade_total))
        fade_out_alpha = None
        if fade_out_index is not None and fade_out_total > 0:
            fade_out_alpha = int(round(100 * (1.0 - min(fade_out_step, fade_out_total) / fade_out_total)))

        for index, text in enumerate(entries):
            y_pos = positions[index] if index < len(positions) else 0
            line_color = color
            if color_rgb is not None:
                if fade_out_alpha is not None and index == fade_out_index and fade_out_alpha < 100:
                    line_color = _format_color_with_alpha(color_rgb, fade_out_alpha)
                elif fade_alpha is not None and index == fade_index and fade_alpha < 100:
                    line_color = _format_color_with_alpha(color_rgb, fade_alpha)
            self._send_message(
                f"{self._id_prefix}line-{index}",
                text,
                line_color,
                x_pos,
                y_pos,
                ttl=_DISPLAY_TTL_SECONDS,
                size=size_token,
            )

        previous = self._last_rendered
        for index in range(len(self._lines), previous):
            self._send_message(
                f"{self._id_prefix}line-{index}",
                "",
                self._config.color,
                x_pos,
                0,
                ttl=1,
                size=size_token,
            )
        self._last_rendered = len(self._lines)
        self._debug("render complete lines=%d cleared=%d", len(self._lines), max(previous - len(self._lines), 0))

    def _compute_target_positions(self) -> list[int]:
        line_height = _LINE_HEIGHT[self._config.font_size]
        if self._group_registered:
            last_index = len(self._lines) - 1
            return [-(line_height * (last_index - index)) for index in range(len(self._lines))]
        start_row = max(self._config.max_lines - len(self._lines), 0)
        base_offset = _BASE_Y - line_height * (self._config.max_lines - 1)
        return [base_offset + line_height * (start_row + index) for index in range(len(self._lines))]

    def _start_animation_thread(self) -> None:
        if self._animation_thread is not None and self._animation_thread.is_alive():
            return
        self._animation_thread = threading.Thread(target=self._animate_scroll, daemon=True)
        self._animation_thread.start()

    def _animate_scroll(self) -> None:
        while True:
            with self._lock:
                if not self._animating:
                    return
                positions = list(self._current_positions)
                targets = list(self._target_positions)
                fade_step = self._fade_step
                fade_total = self._fade_steps_total
                fade_index = self._fade_index
                fade_out_step = self._fade_out_step
                fade_out_total = self._fade_out_steps_total
                fade_out_index = self._fade_out_index
                trim_after = self._trim_after_animation

            done = True
            for index, target in enumerate(targets):
                if index >= len(positions):
                    continue
                current = positions[index]
                if current > target:
                    positions[index] = max(current - 1, target)
                    done = False
                elif current < target:
                    positions[index] = min(current + 1, target)
                    done = False

            fade_done = True
            if fade_index is not None and fade_total > 0:
                if fade_step < fade_total:
                    fade_step += 1
                    fade_done = False

            fade_out_done = True
            if fade_out_index is not None and fade_out_total > 0:
                if fade_out_step < fade_out_total:
                    fade_out_step += 1
                    fade_out_done = False

            render_positions = positions
            with self._lock:
                self._current_positions = positions
                self._fade_step = fade_step
                self._fade_out_step = fade_out_step
                if done and fade_done and fade_out_done:
                    if trim_after and self._lines:
                        self._lines = self._lines[1:]
                        self._trim_after_animation = False
                        self._fade_out_index = None
                        self._fade_out_step = 0
                        self._fade_out_steps_total = 0
                        self._current_positions = self._compute_target_positions()
                        self._target_positions = list(self._current_positions)
                        render_positions = list(self._current_positions)
                    self._animating = False

            self._render_with_positions(render_positions)
            if done and fade_done and fade_out_done:
                return
            time.sleep(0.025)

    def _redraw_loop(self) -> None:
        while not self._redraw_stop.wait(_REDRAW_INTERVAL_SECONDS):
            if self._config.enabled and self._lines:
                with self._lock:
                    positions = list(self._current_positions or self._compute_target_positions())
                self._render_with_positions(positions)


_manager: Optional[OverlayManager] = None


def init(plugin_name: str, logger: logging.Logger) -> None:
    global _manager
    if _manager is None:
        _manager = OverlayManager(plugin_name, logger)
        logger.debug("[%s] %s init created overlay manager.", plugin_name, _LOG_PREFIX)
    else:
        logger.debug("[%s] %s init reusing existing overlay manager.", plugin_name, _LOG_PREFIX)
    _manager.register_group()


def configure(enabled: bool, max_lines: int, font_size: str, color: str) -> None:
    if _manager is None:
        logging.getLogger().debug(
            "%s configure requested before init; dropping request enabled=%s lines=%s font=%s color=%s",
            _LOG_PREFIX,
            enabled,
            max_lines,
            font_size,
            color,
        )
        return
    _manager.configure(
        enabled=enabled,
        max_lines=max_lines,
        font_size=font_size,
        color=color,
    )


def push_event(event_name: str, timestamp: Optional[str]) -> None:
    if _manager is None:
        logging.getLogger().debug(
            "%s push_event requested before init; dropping event=%s",
            _LOG_PREFIX,
            event_name,
        )
        return
    _manager.push_event(event_name, timestamp)


def shutdown() -> None:
    if _manager is None:
        logging.getLogger().debug("%s shutdown requested before init; nothing to do.", _LOG_PREFIX)
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


def _color_to_rgb(value: str) -> Optional[tuple[int, int, int]]:
    token = (value or "").strip()
    if not token:
        return None
    cache_key = token.lower()
    cached = _COLOR_CACHE.get(cache_key)
    if cache_key in _COLOR_CACHE:
        return cached

    hex_part = ""
    if token.startswith("#"):
        hex_part = token[1:]
    elif len(token) in (6, 8) and all(ch in "0123456789abcdefABCDEF" for ch in token):
        hex_part = token

    if hex_part:
        try:
            if len(hex_part) == 6:
                red = int(hex_part[0:2], 16)
                green = int(hex_part[2:4], 16)
                blue = int(hex_part[4:6], 16)
                rgb = (red, green, blue)
                _COLOR_CACHE[cache_key] = rgb
                return rgb
            if len(hex_part) == 8:
                red = int(hex_part[2:4], 16)
                green = int(hex_part[4:6], 16)
                blue = int(hex_part[6:8], 16)
                rgb = (red, green, blue)
                _COLOR_CACHE[cache_key] = rgb
                return rgb
        except ValueError:
            pass

    try:
        import tkinter as tk
        global _COLOR_ROOT
        root = tk._default_root
        if root is None:
            if _COLOR_ROOT is None:
                _COLOR_ROOT = tk.Tk()
                _COLOR_ROOT.withdraw()
            root = _COLOR_ROOT
        r16, g16, b16 = root.winfo_rgb(token)
        rgb = (r16 // 257, g16 // 257, b16 // 257)
        _COLOR_CACHE[cache_key] = rgb
        return rgb
    except Exception:
        _COLOR_CACHE[cache_key] = None
        return None


def _format_color_with_alpha(rgb: tuple[int, int, int], alpha_percent: int) -> str:
    alpha = max(0, min(100, alpha_percent))
    alpha_byte = int(round(255 * (alpha / 100.0)))
    red, green, blue = rgb
    return f"#{alpha_byte:02X}{red:02X}{green:02X}{blue:02X}"


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

"""Passive CAPI viewer. All methods are called on EDMC's Tk main thread."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import tkinter as tk
from tkinter import ttk
from typing import Any, Mapping


_HISTORY_NOTICE = "[older output discarded to limit monitor history]\n"


def format_capi_report(
    source: str,
    data: Mapping[str, Any],
    is_beta: bool | None = None,
    received_at: datetime | None = None,
) -> str:
    """Format the complete callback mapping, including fields unknown to EDMC."""
    timestamp = received_at if received_at is not None else datetime.now(timezone.utc)
    host = getattr(data, "source_host", "unknown")
    beta = f" | beta={is_beta}" if is_beta is not None else ""
    header = f"[{timestamp.isoformat(timespec='seconds')}] {source} | host={host}{beta}"
    # CAPIData is a UserDict, which json.dumps does not serialize directly.
    payload = json.dumps(dict(data), indent=2, ensure_ascii=False, default=str)
    return f"{header}\n{payload}\n\n"


class CAPIMonitor:
    """Own a single viewer, retaining data only while its window is open."""

    def __init__(self, logger: logging.Logger, max_chars: int = 2_000_000) -> None:
        self._logger = logger
        self._max_chars = max(1000, max_chars)
        self._window: tk.Toplevel | None = None
        self._text: tk.Text | None = None
        self._previous_grab: tk.Misc | None = None

    def show(self, parent: tk.Misc) -> None:
        """Open or raise the viewer independently of the preferences lifetime."""
        # Preferences takes a modal grab. Release it while this independent
        # viewer is open so both windows (and EDMC's Update button) are usable.
        grabbed = parent.grab_current()
        if grabbed is not None:
            self._previous_grab = grabbed
            grabbed.grab_release()

        if self._window is not None:
            self._window.deiconify()
            self._window.lift()
            return

        while parent.master is not None:
            parent = parent.master
        window = tk.Toplevel(parent)
        self._window = window
        window.title("CAPI Monitor")
        window.geometry("900x600")
        window.minsize(480, 300)
        window.resizable(True, True)
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)
        window.protocol("WM_DELETE_WINDOW", self.close)
        window.bind("<Destroy>", self._on_destroy, add="+")

        text = tk.Text(
            window, wrap="none", font="TkFixedFont", background="#141414",
            foreground="#e6e6e6", insertbackground="#e6e6e6",
            selectbackground="#345578", selectforeground="#ffffff",
            state="disabled", padx=8, pady=8,
        )
        self._text = text
        text.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(window, orient="vertical", command=text.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(window, orient="horizontal", command=text.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        text.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        ttk.Button(window, text="Close", command=self.close).grid(
            row=2, column=0, columnspan=2, sticky="e", padx=10, pady=10
        )
        self._append(
            "Listening for new CAPI data from EDMC...\n"
            "Use EDMC's Update button to request fresh commander data.\n"
            "Live, Legacy, and fleet-carrier callbacks appear here when received.\n\n"
        )

    def receive(
        self, source: str, data: Mapping[str, Any], is_beta: bool | None = None
    ) -> None:
        """Display a callback without modifying its data or fetching anything."""
        if self._window is None:
            return
        try:
            report = format_capi_report(source, data, is_beta)
        except (TypeError, ValueError, RecursionError):
            self._logger.exception("Unable to format CAPI monitor data from %s", source)
            report = f"[{source}] Unable to format this CAPI update; see EDMC's debug log.\n\n"
        self._append(report)

    def _append(self, report: str) -> None:
        text = self._text
        if text is None:
            return
        follow_tail = text.yview()[1] >= 0.99
        text.configure(state="normal")
        try:
            # Avoid inserting an arbitrarily large payload into Tk in one go.
            if len(report) > self._max_chars:
                report = _HISTORY_NOTICE + report[-(self._max_chars - len(_HISTORY_NOTICE)):]
            text.insert("end", report)
            count = text.count("1.0", "end-1c", "chars")[0]
            if count > self._max_chars:
                remove = count - self._max_chars + len(_HISTORY_NOTICE)
                text.delete("1.0", f"1.0+{remove}c")
                text.insert("1.0", _HISTORY_NOTICE)
            if follow_tail:
                text.see("end")
        finally:
            text.configure(state="disabled")

    def close(self, *, restore_grab: bool = True) -> None:
        """Destroy the viewer and release its output; safe to call repeatedly."""
        window = self._window
        previous_grab = self._previous_grab
        self._window = None
        self._text = None
        self._previous_grab = None
        if window is not None:
            window.destroy()
        if restore_grab and previous_grab is not None:
            try:
                if previous_grab.winfo_exists() and previous_grab.grab_current() is None:
                    previous_grab.grab_set()
            except tk.TclError:
                # The preferences window or Tcl interpreter may already be gone.
                self._logger.debug("CAPI monitor's previous grab owner was destroyed", exc_info=True)

    def _on_destroy(self, event: tk.Event) -> None:
        if event.widget is self._window:
            self._window = None
            self._text = None
            self._previous_grab = None

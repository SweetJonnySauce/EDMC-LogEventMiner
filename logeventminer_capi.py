"""Passive CAPI viewer. All methods are called on EDMC's Tk main thread."""

from __future__ import annotations

from datetime import datetime, timezone
from bisect import bisect_right
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
import json
import logging
import tkinter as tk
from tkinter import ttk
from typing import Any, Mapping

from logeventminer_json import JsonPath, JsonPresentation, analyze_json, format_json_path


_HISTORY_NOTICE = "[older output discarded to limit monitor history]\n"
_ASYNC_THRESHOLD = 250_000


def _prepare_report(report: str, source: str | None) -> JsonPresentation:
    if source is not None:
        return analyze_json(report, header_lines=1)
    return JsonPresentation(report, (), (None,) * len(report.splitlines()))


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
        self._follow_latest: tk.BooleanVar | None = None
        self._previous_grab: tk.Misc | None = None
        self._breadcrumb: ttk.Entry | None = None
        self._breadcrumb_value: tk.StringVar | None = None
        self._line_contexts: list[tuple[str, JsonPath] | None] = []
        self._utf16_columns = False
        self._json_worker: ThreadPoolExecutor | None = None
        self._pending_reports: deque[tuple[Future, str | None]] = deque()
        self._poll_after: str | None = None

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
        window.rowconfigure(1, weight=1)
        window.protocol("WM_DELETE_WINDOW", self.close)
        window.bind("<Destroy>", self._on_destroy, add="+")

        style = ttk.Style(window)
        breadcrumb_style = "LogEventMiner.CAPIBreadcrumb.TEntry"
        style.configure(breadcrumb_style, padding=(8, 5))
        style.map(breadcrumb_style, fieldbackground=[("readonly", "#202020")],
                  foreground=[("readonly", "#c6c6c6")])
        self._breadcrumb_value = tk.StringVar(master=window, value="CAPI Monitor")
        self._breadcrumb = ttk.Entry(
            window, textvariable=self._breadcrumb_value, state="readonly", width=1,
            style=breadcrumb_style, exportselection=False,
        )
        self._breadcrumb.grid(row=0, column=0, columnspan=2, sticky="ew")

        text = tk.Text(
            window, wrap="none", font="TkFixedFont", background="#141414",
            foreground="#d4d4d4", insertbackground="#e6e6e6",
            insertofftime=0,
            selectbackground="#345578", selectforeground="#ffffff",
            state="disabled", exportselection=False, padx=8, pady=8,
        )
        self._text = text
        self._utf16_columns = text.tk.call("string", "length", "😀") == 2
        for kind, color in {
            "key": "#9cdcfe", "string": "#ce9178", "number": "#b5cea8",
            "literal": "#569cd6", "punctuation": "#d4d4d4", "header": "#808080",
        }.items():
            text.tag_configure(f"json_{kind}", foreground=color)
        text.tag_raise("sel")
        # Tk's class binding starts a repeating selection auto-scan on leaving
        # with button 1 held. A lost release can scroll this viewer indefinitely.
        # Keep selection within the text and use explicit navigation to scroll.
        text.bind("<B1-Leave>", lambda event: "break")
        text.grid(row=1, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(window, orient="vertical", command=text.yview)
        vertical.grid(row=1, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(window, orient="horizontal", command=text.xview)
        horizontal.grid(row=2, column=0, sticky="ew")

        def scrolled(first: str, last: str) -> None:
            vertical.set(first, last)
            self._update_breadcrumb()

        text.configure(yscrollcommand=scrolled, xscrollcommand=horizontal.set)
        text.bind("<Configure>", lambda event: self._update_breadcrumb(), add="+")
        controls = ttk.Frame(window)
        controls.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        controls.columnconfigure(0, weight=1)
        self._follow_latest = tk.BooleanVar(master=window, value=False)
        ttk.Checkbutton(
            controls, text="Follow latest", variable=self._follow_latest,
            command=self._change_follow_latest,
        ).grid(row=0, column=0, sticky="w")
        ttk.Button(controls, text="Close", command=self.close).grid(row=0, column=1)
        self._append(
            "Listening for new CAPI data from EDMC...\n"
            "Use EDMC's Update button to request fresh commander data.\n"
            "Live, Legacy, and fleet-carrier callbacks appear here when received.\n\n"
        )

    def _change_follow_latest(self) -> None:
        if self._follow_latest is not None and self._follow_latest.get() and self._text is not None:
            self._text.see("end")

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
            return
        self._append(report, source)

    def _append(self, report: str, source: str | None = None) -> None:
        if self._window is None:
            return
        if self._pending_reports or (source is not None and len(report) > _ASYNC_THRESHOLD):
            if self._json_worker is None:
                self._json_worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="LogEventMinerJSON")
            future = self._json_worker.submit(_prepare_report, report, source)
            self._pending_reports.append((future, source))
            if self._poll_after is None:
                self._poll_after = self._window.after(25, self._finish_report)
            return
        self._append_document(_prepare_report(report, source), source)

    def _finish_report(self) -> None:
        self._poll_after = None
        if self._window is None or not self._pending_reports:
            return
        future, source = self._pending_reports[0]
        if future.done():
            self._pending_reports.popleft()
            try:
                document = future.result()
            except Exception:
                self._logger.exception("Unable to prepare CAPI monitor JSON")
                document = _prepare_report("Unable to display this CAPI update; see EDMC's debug log.\n", None)
            self._append_document(document, source)
        if self._pending_reports:
            self._poll_after = self._window.after(25, self._finish_report)

    def _append_document(self, document: JsonPresentation, source: str | None) -> None:
        text = self._text
        if text is None:
            return
        if len(document.text) > self._max_chars:
            remove = len(document.text) - self._max_chars + len(_HISTORY_NOTICE)
            document = document.trim_start(remove).with_prefix(_HISTORY_NOTICE)
        # A percentage tolerance spans many lines in large CAPI reports.
        # Even a one-line upward scroll must stop following new data.
        follow_tail = (
            self._follow_latest is not None
            and self._follow_latest.get()
            and text.yview()[1] == 1.0
        )
        text.configure(state="normal")
        try:
            start_line = int(text.index("end-1c").split(".")[0])
            text.insert("end", document.text)
            self._line_contexts.extend(
                (source, path) if source is not None and path is not None else None
                for path in document.paths
            )
            self._apply_colors(document, start_line)
            count = text.count("1.0", "end-1c", "chars")[0]
            if count > self._max_chars:
                remove = count - self._max_chars + len(_HISTORY_NOTICE)
                removed_lines = int(text.index(f"1.0+{remove}c").split(".")[0]) - 1
                text.delete("1.0", f"1.0+{remove}c")
                text.insert("1.0", _HISTORY_NOTICE)
                del self._line_contexts[:removed_lines]
                self._line_contexts.insert(0, None)
            if follow_tail:
                text.see("end")
        finally:
            text.configure(state="disabled")
        self._update_breadcrumb()

    def _apply_colors(self, document: JsonPresentation, start_line: int) -> None:
        text = self._text
        if text is None or not document.spans:
            return
        lines = document.text.splitlines(keepends=True)
        starts = []
        offset = 0
        for line in lines:
            starts.append(offset)
            offset += len(line)

        ranges: dict[str, list[str]] = {}
        for span in document.spans:
            # Punctuation already uses the Text widget's foreground color.
            if span.kind == "punctuation":
                continue
            row = bisect_right(starts, span.start) - 1
            first = span.start - starts[row]
            last = span.end - starts[row]
            prefix = document.text[starts[row]:span.end]
            if self._utf16_columns and not prefix.isascii():
                first = len(prefix[:first].encode("utf-16-le", errors="surrogatepass")) // 2
                last = len(prefix.encode("utf-16-le", errors="surrogatepass")) // 2
            ranges.setdefault(span.kind, []).extend(
                (f"{start_line + row}.{first}", f"{start_line + row}.{last}")
            )
        for kind, positions in ranges.items():
            # Batch ranges to avoid one Python/Tcl round trip per JSON token.
            for offset in range(0, len(positions), 800):
                text.tag_add(f"json_{kind}", *positions[offset:offset + 800])

    def _update_breadcrumb(self) -> None:
        if self._text is None or self._breadcrumb_value is None or self._breadcrumb is None:
            return
        row = int(self._text.index("@0,0").split(".")[0]) - 1
        context = self._line_contexts[row] if row < len(self._line_contexts) else None
        value = f"{context[0]} › {format_json_path(context[1])}" if context else "CAPI Monitor"
        if self._breadcrumb_value.get() != value:
            self._breadcrumb_value.set(value)
            self._breadcrumb.xview_moveto(1.0)

    def close(self, *, restore_grab: bool = True) -> None:
        """Destroy the viewer and release its output; safe to call repeatedly."""
        self._cancel_json_work(wait=not restore_grab)
        window = self._window
        previous_grab = self._previous_grab
        self._window = None
        self._text = None
        self._follow_latest = None
        self._breadcrumb = None
        self._breadcrumb_value = None
        self._line_contexts.clear()
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
            self._cancel_json_work(wait=False)
            self._window = None
            self._text = None
            self._follow_latest = None
            self._breadcrumb = None
            self._breadcrumb_value = None
            self._line_contexts.clear()
            self._previous_grab = None

    def _cancel_json_work(self, *, wait: bool) -> None:
        if self._poll_after is not None and self._window is not None:
            self._window.after_cancel(self._poll_after)
        self._poll_after = None
        for future, _ in self._pending_reports:
            future.cancel()
        self._pending_reports.clear()
        if self._json_worker is not None:
            self._json_worker.shutdown(wait=wait, cancel_futures=True)
            self._json_worker = None

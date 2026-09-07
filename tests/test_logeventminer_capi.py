from collections import UserDict
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import json
import logging
from pathlib import Path
import sys
from types import SimpleNamespace
import tkinter as tk
from tkinter import ttk
from unittest.mock import Mock

import pytest

from logeventminer_capi import CAPIMonitor, format_capi_report


def test_report_preserves_unknown_fields_and_labels_callback_metadata():
    data = UserDict({"newField": {"values": [1, None, True, "Étoile"]}})
    data.source_host = "example.invalid"
    before = deepcopy(data)
    report = format_capi_report(
        "cmdr_data", data, True, datetime(2026, 9, 7, 12, 30, tzinfo=timezone.utc)
    )
    header, payload = report.split("\n", 1)
    assert "2026-09-07T12:30:00+00:00" in header
    assert "cmdr_data" in header
    assert "example.invalid" in header
    assert "beta=True" in header
    assert json.loads(payload) == data
    assert "Étoile" in payload
    assert data == before


def test_closed_monitor_does_not_inspect_payload():
    monitor = CAPIMonitor(logging.getLogger("test.capi"))
    monitor.receive("cmdr_data", object(), False)
    monitor.close()
    monitor.close()


@pytest.fixture
def plugin(monkeypatch, tmp_path):
    # Isolate load.py's existing import-time file logging from the installed plugin.
    settings = {}
    config = SimpleNamespace(
        logs_dir=tmp_path,
        shutting_down=False,
        get_str=lambda key: settings.get(key, ""),
        set=lambda key, value: settings.__setitem__(key, value),
    )
    notebook = SimpleNamespace(
        **{name: getattr(ttk, name) for name in (
            "Frame", "Label", "Checkbutton", "Button", "Radiobutton", "Notebook"
        )},
        EntryMenu=ttk.Entry, OptionMenu=ttk.OptionMenu,
    )
    monkeypatch.setitem(sys.modules, "config", SimpleNamespace(appname="test.capi", config=config))
    monkeypatch.setitem(sys.modules, "myNotebook", notebook)
    spec = importlib.util.spec_from_file_location(
        "capi_test_plugin", Path(__file__).resolve().parents[1] / "load.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "overlay_support", None)
    yield module
    module.plugin_stop()
    for handler in list(module.logger.handlers):
        module.logger.removeHandler(handler)
        handler.close()


def test_all_capi_hooks_forward_original_payload_independently_of_logging(plugin):
    monitor = Mock()
    plugin._capi_monitor = monitor
    plugin._logging_enabled = False
    data = UserDict({"unexpected": [1, 2]})
    assert plugin.cmdr_data(data, False) is None
    assert plugin.cmdr_data(data, True) is None
    assert plugin.cmdr_data_legacy(data, False) is None
    assert plugin.capi_fleetcarrier(data) is None
    assert [(call.args[0], call.args[2]) for call in monitor.receive.call_args_list] == [
        ("cmdr_data", False), ("cmdr_data", True),
        ("cmdr_data_legacy", False), ("capi_fleetcarrier", None),
    ]
    assert all(call.args[1] is data for call in monitor.receive.call_args_list)


def test_shutdown_closes_monitor_and_ignores_late_data(plugin):
    plugin._capi_monitor = Mock()
    plugin.config.shutting_down = True
    plugin.cmdr_data({}, False)
    plugin.cmdr_data_legacy({}, False)
    plugin.capi_fleetcarrier({})
    plugin._show_capi_monitor(object())
    plugin._capi_monitor.receive.assert_not_called()
    plugin._capi_monitor.show.assert_not_called()
    plugin.plugin_stop()
    plugin._capi_monitor.close.assert_called_once_with(restore_grab=False)


@pytest.fixture
def root():
    try:
        window = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")
    window.withdraw()
    yield window
    try:
        window.destroy()
    except tk.TclError:
        pass


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


def test_window_lifecycle_resize_output_and_preferences_grab(root):
    prefs = tk.Toplevel(root)
    parent = ttk.Frame(prefs)
    prefs.grab_set()
    monitor = CAPIMonitor(logging.getLogger("test.capi"))
    monitor.show(parent)
    window = next(child for child in root.winfo_children() if child is not prefs)
    assert window.title() == "CAPI Monitor"
    assert window.resizable() == (1, 1)
    assert root.grab_current() is None
    monitor.show(parent)
    assert len(root.winfo_children()) == 2
    text = next(child for child in descendants(window) if isinstance(child, tk.Text))
    bars = [child for child in descendants(window) if isinstance(child, ttk.Scrollbar)]
    assert len(bars) == 2
    monitor.receive("cmdr_data", UserDict({"newField": [42]}), False)
    assert '"newField"' in text.get("1.0", "end")
    assert str(text.cget("state")) == "disabled"
    window.geometry("1000x700")
    root.update_idletasks()
    assert text.winfo_width() > 800
    close = next(child for child in descendants(window)
                 if isinstance(child, ttk.Button) and child.cget("text") == "Close")
    close.invoke()
    assert not window.winfo_exists()
    assert root.grab_current() is prefs
    monitor.show(parent)
    prefs.destroy()
    monitor.receive("capi_fleetcarrier", {"carrier": "test"})
    window = root.winfo_children()[0]
    assert window.winfo_exists()
    root.tk.call(window.protocol("WM_DELETE_WINDOW"))
    assert not window.winfo_exists()
    monitor.show(root)
    root.destroy()
    monitor.receive("cmdr_data", object())
    monitor.close(restore_grab=False)


def test_history_is_bounded_and_reports_discarding_old_output(root):
    monitor = CAPIMonitor(logging.getLogger("test.capi"), max_chars=1000)
    monitor.show(root)
    for index in range(20):
        monitor.receive("cmdr_data", {"sequence": index, "value": "x" * 100})
    window = root.winfo_children()[0]
    text = next(child for child in descendants(window) if isinstance(child, tk.Text))
    output = text.get("1.0", "end-1c")
    assert len(output) <= 1000
    assert "older output discarded" in output
    assert '"sequence": 19' in output
    assert '"sequence": 0,' not in output
    monitor.close()


def test_oversized_report_is_visibly_truncated_and_invalid_data_is_reported(root):
    logger = Mock()
    monitor = CAPIMonitor(logger, max_chars=1000)
    monitor.show(root)
    monitor.receive("cmdr_data", {"large": "x" * 5000})
    window = root.winfo_children()[0]
    text = next(child for child in descendants(window) if isinstance(child, tk.Text))
    output = text.get("1.0", "end-1c")
    assert len(output) <= 1000
    assert "older output discarded" in output
    recursive = {}
    recursive["cycle"] = recursive
    monitor.receive("cmdr_data", recursive)
    assert "Unable to format this CAPI update" in text.get("1.0", "end")
    assert str(text.cget("state")) == "disabled"
    logger.exception.assert_called_once()
    monitor.close()


def test_new_data_does_not_interrupt_scrolling_through_previous_output(root):
    monitor = CAPIMonitor(logging.getLogger("test.capi"))
    monitor.show(root)
    next(child for child in descendants(root) if isinstance(child, ttk.Checkbutton)
         and child.cget("text") == "Follow latest").invoke()
    monitor.receive("cmdr_data", {"rows": list(range(200))})
    root.update_idletasks()
    window = root.winfo_children()[0]
    text = next(child for child in descendants(window) if isinstance(child, tk.Text))
    text.yview_moveto(0)
    monitor.receive("cmdr_data", {"latest": True})
    assert text.yview()[0] == 0
    text.see("end")
    monitor.receive("cmdr_data", {"next": True})
    assert text.yview()[1] == 1
    monitor.close()


def test_preferences_button_opens_monitor_and_survives_settings_close(plugin, root):
    plugin.plugin_start3(str(plugin.PLUGIN_DIR))
    prefs = tk.Toplevel(root)
    notebook = ttk.Notebook(prefs)
    container = plugin.plugin_prefs(notebook, "Test", False)
    button = next(child for child in descendants(container)
                  if isinstance(child, ttk.Button) and child.cget("text") == "CAPI Monitor")
    button.invoke()
    prefs.destroy()
    plugin.cmdr_data({"newField": "received"}, False)
    text = next(child for child in descendants(root) if isinstance(child, tk.Text))
    assert '"received"' in text.get("1.0", "end")
    plugin.plugin_stop()
    assert not root.winfo_children()


@pytest.mark.parametrize("scroll_method", ["scrollbar", "wheel"])
def test_scrolling_up_near_bottom_of_large_report_stops_following(root, scroll_method):
    monitor = CAPIMonitor(logging.getLogger("test.capi"))
    monitor.show(root)
    next(child for child in descendants(root) if isinstance(child, ttk.Checkbutton)
         and child.cget("text") == "Follow latest").invoke()
    monitor.receive("cmdr_data", {"rows": list(range(20_000))})
    root.update_idletasks()
    window = root.winfo_children()[0]
    text = next(child for child in descendants(window) if isinstance(child, tk.Text))
    text.see("end")
    root.update_idletasks()
    if scroll_method == "wheel":
        if root.tk.call("tk", "windowingsystem") == "x11":
            text.event_generate("<Button-4>", x=10, y=10)
        else:
            text.event_generate("<MouseWheel>", delta=120, x=10, y=10)
    else:
        scrollbar = next(child for child in descendants(window)
                         if isinstance(child, ttk.Scrollbar)
                         and str(child.cget("orient")) == "vertical")
        root.tk.call(scrollbar.cget("command"), "scroll", -1, "units")
    root.update_idletasks()
    assert 0.99 < text.yview()[1] < 1
    first_visible_line = text.index("@0,0")
    for index in range(3):
        monitor.receive("cmdr_data", {"update": index})
        root.update_idletasks()
        assert text.index("@0,0") == first_visible_line
        assert text.yview()[1] < 1
    text.see("end")
    monitor.receive("cmdr_data", {"following_again": True})
    assert text.yview()[1] == 1
    monitor.close()


def test_dragging_selection_outside_viewer_does_not_start_idle_scrolling(root):
    monitor = CAPIMonitor(logging.getLogger("test.capi"))
    monitor.show(root)
    monitor.receive("cmdr_data", {"rows": list(range(2000))})
    root.update()
    text = next(child for child in descendants(root) if isinstance(child, tk.Text))
    text.yview_moveto(0.5)
    root.update()
    text.event_generate("<ButtonPress-1>", x=20, y=60)
    text.event_generate("<Motion>", state=0x100, x=90, y=90)
    assert text.tag_ranges("sel")
    first_line = text.index("@0,0")
    viewport = text.yview()
    try:
        # Reproduce a drag leaving the window without a delivered release.
        text.event_generate("<Leave>", state=0x100, x=20, y=-10)
        assert text.yview() == viewport
        finished = tk.BooleanVar(master=root, value=False)
        root.after(250, lambda: finished.set(True))
        root.wait_variable(finished)
        assert text.index("@0,0") == first_line
        assert text.tag_ranges("sel")
    finally:
        text.event_generate("<ButtonRelease-1>", x=20, y=20)
        monitor.close()


def test_follow_latest_is_opt_in_and_can_be_stopped(root):
    monitor = CAPIMonitor(logging.getLogger("test.capi"))
    monitor.show(root)
    root.update_idletasks()
    text = next(child for child in descendants(root) if isinstance(child, tk.Text))
    follow = next(child for child in descendants(root) if isinstance(child, ttk.Checkbutton)
                  and child.cget("text") == "Follow latest")
    assert not follow.instate(["selected"])
    monitor.receive("cmdr_data", {"rows": list(range(2000))})
    root.update_idletasks()
    assert text.index("@0,0") == "1.0"
    follow.invoke()
    assert text.yview()[1] == 1
    monitor.receive("cmdr_data", {"following": True})
    assert text.yview()[1] == 1
    follow.invoke()
    first_line = text.index("@0,0")
    for index in range(5):
        monitor.receive("cmdr_data", {"paused": index})
        root.update_idletasks()
        assert text.index("@0,0") == first_line
    assert str(text.cget("state")) == "disabled"
    monitor.close()
    monitor.show(root)
    follow = next(child for child in descendants(root) if isinstance(child, ttk.Checkbutton)
                  and child.cget("text") == "Follow latest")
    assert not follow.instate(["selected"])
    monitor.close()

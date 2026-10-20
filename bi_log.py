"""
bi_log.py - the problem log: unexpected errors (and hard crashes) are written to
%LOCALAPPDATA%\\BACnetInspector\\logs\\bacnet-inspector.log, a small window says something went wrong, and
Help > Report a problem shows the details to copy and send.
"""
from __future__ import annotations

import faulthandler
import os
import platform
import sys
import threading
import time
import traceback

from bacnet_live import APP_VERSION, state_dir

MAX_BYTES = 1_000_000            # the log is rolled over to .1 at this size
_lock = threading.Lock()
_last_popup = 0.0
_crash_file = None
on_error = None                  # set by the main window: called (in the GUI thread) with the error summary


def log_dir():
    d = os.path.join(state_dir(), 'logs')
    os.makedirs(d, exist_ok=True)
    return d


def log_path():
    return os.path.join(log_dir(), 'bacnet-inspector.log')


def system_info():
    return (f'BACnet Inspector {APP_VERSION} · Windows {platform.release()} ({platform.version()}) · '
            f'Python {platform.python_version()} · {"installed" if getattr(sys, "frozen", False) else "from source"}')


def write(text):
    """Add a timestamped entry to the log (never raises)."""
    try:
        with _lock:
            p = log_path()
            if os.path.isfile(p) and os.path.getsize(p) > MAX_BYTES:
                os.replace(p, p + '.1')
            with open(p, 'a', encoding='utf-8') as f:
                f.write(f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] {text.rstrip()}\n')
    except OSError:
        pass


def _report(kind, et, ev, tb):
    summary = f'{et.__name__}: {ev}'
    write(f'{kind}: {summary}\n{system_info()}\n' + ''.join(traceback.format_exception(et, ev, tb)))
    global _last_popup
    if on_error and time.time() - _last_popup > 10:       # at most one window every 10 s
        _last_popup = time.time()
        try:
            on_error(summary)
        except Exception:
            pass


def _hook(et, ev, tb):
    if issubclass(et, KeyboardInterrupt):
        return sys.__excepthook__(et, ev, tb)
    _report('Error', et, ev, tb)


def _thread_hook(a):
    _report(f'Error in background task {a.thread.name if a.thread else ""}', a.exc_type, a.exc_value, a.exc_traceback)


def install():
    """Log unexpected errors from now on. Hard crashes go to crash.txt in the same folder."""
    global _crash_file
    sys.excepthook = _hook
    threading.excepthook = _thread_hook
    try:
        _crash_file = open(os.path.join(log_dir(), 'crash.txt'), 'a', encoding='utf-8')
        faulthandler.enable(_crash_file)
    except (OSError, RuntimeError):
        pass
    write(f'Started. {system_info()}')


def recent(n=12000):
    """The end of the log (and of crash.txt, if anything is in it) for the Report a problem window."""
    out = []
    for name in ('bacnet-inspector.log', 'crash.txt'):
        p = os.path.join(log_dir(), name)
        try:
            with open(p, encoding='utf-8', errors='replace') as f:
                f.seek(max(0, os.path.getsize(p) - n))
                t = f.read().strip()
            if t:
                out.append(f'--- {name} ---\n{t}')
        except OSError:
            pass
    return '\n\n'.join(out)


def error_count():
    try:
        with open(log_path(), encoding='utf-8', errors='replace') as f:
            return sum(1 for line in f if '] Error' in line)
    except OSError:
        return 0

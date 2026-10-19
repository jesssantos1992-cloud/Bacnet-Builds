"""
bi_store.py - settings, device / network names, saved filters and packet notes, kept in one
JSON file in %LOCALAPPDATA%\\BACnetInspector (next to the session file the app already uses).
"""
from __future__ import annotations

import json
import os
import threading

from bacnet_live import state_dir


class Store:
    def __init__(self, name='settings.json'):
        self.path = os.path.join(state_dir(), name)
        self.lock = threading.Lock()
        try:
            with open(self.path, encoding='utf-8') as f:
                self.d = json.load(f)
            if not isinstance(self.d, dict):
                self.d = {}
        except (OSError, ValueError):
            self.d = {}
        lb = self.d.get('bi_labels') or {}
        self._labels = {'d': dict(lb.get('d') or {}), 'n': dict(lb.get('n') or {})}
        self._timer = None

    def get(self, k, default=None):
        with self.lock:
            return self.d.get(k, default)

    def set(self, k, v):
        with self.lock:
            if v is None:
                self.d.pop(k, None)
            else:
                self.d[k] = v
        self._save_soon()

    def _save_soon(self):
        with self.lock:
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(0.4, self.flush)
            self._timer.daemon = True
            self._timer.start()

    def flush(self):
        with self.lock:
            data = json.dumps(self.d, ensure_ascii=False)
            self._timer = None
        tmp = self.path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(data)
            os.replace(tmp, self.path)
        except OSError:
            pass

    # ---- names for device IDs ('d') and networks ('n'); keys are strings
    def labels(self):
        return self._labels

    def save_labels(self):
        self.set('bi_labels', self._labels)

    def label(self, kind, n):
        return self._labels[kind].get(str(n), '')

    def set_label(self, kind, n, v):
        v = (v or '').strip()
        if v:
            self._labels[kind][str(n)] = v
        else:
            self._labels[kind].pop(str(n), None)
        self.save_labels()

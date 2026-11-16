"""
bi_histwin.py - the History tab in Discover: the last discovers kept on this computer (how many is a setting), each
one's devices and points, what changed between two discovers or since one, reopening one in the Devices tab, export
and delete. Storage and comparison are in bi_history.py.
"""
from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QHBoxLayout, QLabel, QPushButton, QSpinBox,
                               QSplitter, QVBoxLayout, QWidget)

import bi_explore as E
import bi_history as H
from bi_common import Table, colors, csv_text, label


def when(t):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(t))


def ago(t):
    s = time.time() - t
    if s < 3600:
        return f'{max(1, round(s / 60))} min ago'
    if s < 86400:
        return f'{round(s / 3600)} h ago'
    d = round(s / 86400)
    return f"{d} day{'' if d == 1 else 's'} ago"


def addr(d):
    if d.get('via') == 'mstp':
        return f"MS/TP MAC {d.get('mac')}"
    if d.get('sn') is not None:
        return f"{d.get('ip')} → network {d['sn']}" + (f", {d['sa']}" if d.get('sa') else '')
    return d.get('ip') or ''


class HistoryPage(QWidget):
    SHOW = ['Devices and points in this discover', 'Changes since the discover before it',
            'Changes compared with the Devices tab now']

    def __init__(self, dv):
        super().__init__()
        self.dv, self.win, self.ex = dv, dv.win, dv.ex
        self.idx = []                     # bi_history.index()
        self.snap = None                  # the selected discover, loaded
        self.dev = None                   # a device opened from the list (its points are shown)
        self.rows = []                    # what the table shows, for Export
        self.seen = None
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 12, 24, 12)
        v.setSpacing(10)
        top = QHBoxLayout()
        tl = QVBoxLayout()
        tl.setSpacing(0)
        tl.addWidget(label('History', bold=True, size=15, wrap=False))
        tl.addWidget(label('Each discover – the devices that answered and the points you read – is kept on this computer.',
                           muted=True, wrap=False))
        top.addLayout(tl)
        top.addStretch(1)
        top.addWidget(QLabel('Keep the last'))
        self.keep = QSpinBox()
        self.keep.setRange(0, 100)
        self.keep.setValue(self.ex.hist_keep())
        self.keep.setToolTip('How many discovers to keep. Older ones are deleted. 0 switches History off.')
        self.keep.valueChanged.connect(self.keep_changed)
        top.addWidget(self.keep)
        top.addWidget(QLabel('discovers'))
        self.del_b = QPushButton('Delete')
        self.del_b.setToolTip('Delete the discovers picked in the list')
        self.del_b.clicked.connect(self.delete)
        top.addWidget(self.del_b)
        v.addLayout(top)
        self.empty = label('', muted=True)
        v.addWidget(self.empty)
        sp = QSplitter(Qt.Orientation.Horizontal)
        self.list = Table(['When', 'Connection', 'Devices', 'Points'])
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.list.itemSelectionChanged.connect(self.picked)
        sp.addWidget(self.list)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(8, 0, 0, 0)
        rv.setSpacing(8)
        self.head = label('', bold=True, size=13)
        rv.addWidget(self.head)
        r = QHBoxLayout()
        self.show_c = QComboBox()
        for t in self.SHOW:
            self.show_c.addItem(t)
        self.show_c.currentIndexChanged.connect(lambda _i: (setattr(self, 'dev', None), self.fill()))
        r.addWidget(self.show_c)
        self.vals = QCheckBox('Include point value changes')
        self.vals.setToolTip('Values change all the time; tick this to list them too')
        self.vals.toggled.connect(lambda _on: self.fill())
        r.addWidget(self.vals)
        r.addStretch(1)
        self.back_b = QPushButton('◀ All devices')
        self.back_b.clicked.connect(lambda: (setattr(self, 'dev', None), self.fill()))
        r.addWidget(self.back_b)
        self.open_b = QPushButton('Open in Discover')
        self.open_b.setToolTip('Put these devices and the points read then back in the Devices tab (marked as from '
                               'History until they answer again)')
        self.open_b.clicked.connect(self.open_in_discover)
        r.addWidget(self.open_b)
        self.exp_b = QPushButton('Export…')
        self.exp_b.clicked.connect(self.export)
        r.addWidget(self.exp_b)
        rv.addLayout(r)
        self.sub = label('', muted=True)
        rv.addWidget(self.sub)
        self.tbl = Table([''])
        self.tbl.rowActivated.connect(self.activated)
        rv.addWidget(self.tbl, 1)
        sp.addWidget(right)
        sp.setSizes([380, 820])
        sp.setStretchFactor(1, 1)
        v.addWidget(sp, 1)
        self.sp = sp

    # ------------------------------------------------------------- the list --
    def reload(self):
        self.seen = getattr(self.ex, 'hist_seq', 0)
        sel = self.snap['meta']['id'] if self.snap else None
        self.idx = H.index()
        self.list.blockSignals(True)
        self.list.fill([[f"{when(x['at'])}  ·  {ago(x.get('upd') or x['at'])}", x.get('where') or ('MS/TP' if x.get('mode') == 'mstp' else 'BACnet/IP'),
                         x.get('n', 0), f"{x.get('pts', 0):,}"] for x in self.idx], list(self.idx))
        self.list.blockSignals(False)
        keep = self.ex.hist_keep()
        self.empty.setText('History is off. Set “Keep the last” to 1 or more to keep your discovers.' if keep <= 0 else
                           '' if self.idx else 'No discovers saved yet. Scan the network on the Devices tab: each discover '
                                               'is kept here, with the points you read.')
        self.empty.setVisible(bool(self.empty.text()))
        self.sp.setVisible(bool(self.idx))
        i = next((i for i, x in enumerate(self.idx) if x['id'] == sel), 0 if self.idx else -1)
        if i >= 0:
            self.list.selectRow(i)
        self.picked()

    def maybe_reload(self):
        if getattr(self.ex, 'hist_seq', 0) != self.seen:
            self.reload()

    def keep_changed(self, n):
        self.win.store.set('bi_hist_keep', n)
        if n < len(self.idx):
            H.prune(n)
        self.reload()

    def selected(self):
        return [self.idx[i.row()] for i in self.list.selectionModel().selectedRows() if i.row() < len(self.idx)]

    def picked(self):
        S = self.selected()
        self.del_b.setEnabled(bool(S))
        self.del_b.setText(f'Delete {len(S)}' if len(S) > 1 else 'Delete')
        m = S[0] if S else None
        if not m:
            self.snap = None
        elif not self.snap or self.snap['meta']['id'] != m['id'] or self.snap['meta'].get('upd') != m.get('upd'):
            self.snap = H.load(m['id'])
            self.dev = None
        self.fill()

    def delete(self):
        S = self.selected()
        if not S:
            return
        H.delete([x['id'] for x in S])
        if getattr(self.ex, 'hist_id', None) in {x['id'] for x in S}:
            self.ex.new_history()                       # the next save makes a new entry instead
        self.snap = None
        self.reload()
        self.win.toast(f"Deleted {len(S)} discover{'' if len(S) == 1 else 's'}")

    # ------------------------------------------------------------ the right --
    def previous(self):
        """The discover saved just before the selected one, loaded (or None)."""
        i = next((i for i, x in enumerate(self.idx) if self.snap and x['id'] == self.snap['meta']['id']), -1)
        return H.load(self.idx[i + 1]['id']) if 0 <= i < len(self.idx) - 1 else None

    def fill(self):
        s = self.snap
        c = colors()
        mode = self.show_c.currentIndex()
        self.vals.setVisible(mode > 0)
        self.back_b.setVisible(mode == 0 and self.dev is not None)
        for b in (self.open_b, self.exp_b):
            b.setEnabled(bool(s))
        if not s:
            self.head.setText('')
            self.sub.setText('Pick a discover on the left.' if self.idx else '')
            self.tbl.setColumnCount(1)
            self.tbl.fill([])
            self.rows = []
            return
        m = s['meta']
        self.head.setText(f"{when(m['at'])} · {m.get('where') or ''}")
        if mode == 0 and self.dev is None:
            devs = sorted(s['devs'], key=lambda d: d['id'])
            head = ['Device ID', 'Name', 'Manufacturer', 'Model', 'Firmware', 'Address', 'Points']
            self.rows = [[d['id'], d.get('name') or '', d.get('vendor') or '', d.get('model') or '', d.get('fw') or '', addr(d),
                          len(d['objs']) if d.get('objs') is not None else 'not read'] for d in devs]
            self.sub.setText(f"{len(devs)} device{'' if len(devs) == 1 else 's'} · {m.get('pts', 0):,} points read"
                             + (f" · updated {when(m['upd'])}" if m.get('upd') and m['upd'] - m['at'] > 60 else '')
                             + ' · double-click a device to see its points')
            self._table(head, self.rows, devs)
        elif mode == 0:
            d = self.dev
            objs = d.get('objs') or []
            head = ['Object', 'Name', 'Value', 'Units', 'Description']
            self.rows = [[f"{E.ABBR.get(o['ty'], E.sd_ty(o['ty']))} {o['inst']}", o.get('name') or '', o.get('val') or '',
                          o.get('u') or '', o.get('desc') or ''] for o in objs]
            self.sub.setText(f"{d.get('name') or 'Device ' + str(d['id'])} ({d['id']}) · {len(objs)} points as read on "
                             f"{when(m['at'])}" if objs else 'The points of this device were not read in this discover.')
            self._table(head, self.rows, None)
        else:
            if mode == 1:
                old = self.previous()
                if not old:
                    self.sub.setText('This is the oldest discover kept, so there is nothing before it to compare with.')
                    self._table(['Change'], [], None)
                    self.rows = []
                    return
                ch = H.diff(old['devs'], s['devs'], self.vals.isChecked())
                what = f"since {when(old['meta']['at'])}"
            else:
                ms = self.ex.mode == 'mstp'
                now = H.slim([d for d in self.ex.devs.values() if E.is_mstp(d) == ms and not d.get('hist')])
                if not now:
                    self.sub.setText('The Devices tab is empty: scan the network first, then compare.')
                    self._table(['Change'], [], None)
                    self.rows = []
                    return
                ch = H.diff(s['devs'], now, self.vals.isChecked())
                what = 'between this discover and the Devices tab now'
            word = {'new': 'Added', 'gone': 'Missing', 'changed': 'Changed'}
            col = {'new': c['no'], 'gone': c['se'], 'changed': c['wa']}
            self.rows = [[word[k], dev, w, a, b] for k, dev, w, a, b in ch]
            nd = sum(1 for k, _d, w, _a, _b in ch if w == 'device found')
            ng = sum(1 for k, _d, w, _a, _b in ch if w == 'device did not answer')
            self.sub.setText((f"{len(ch)} change{'' if len(ch) == 1 else 's'} {what}" +
                              (f" · {nd} new device{'' if nd == 1 else 's'}" if nd else '') +
                              (f" · {ng} device{'' if ng == 1 else 's'} missing" if ng else ''))
                             if ch else f'No changes {what}.')
            self.tbl.setColumnCount(5)
            self.tbl.setHorizontalHeaderLabels(['Change', 'Device', 'What', 'Before', 'Now'])
            self.tbl.fill([[(word[k], {'fg': col[k], 'bold': True}), dev, w, a, b] for k, dev, w, a, b in ch])

    def _table(self, head, rows, data):
        self.tbl.setColumnCount(len(head))
        self.tbl.setHorizontalHeaderLabels(head)
        self.tbl.fill(rows, data)

    def activated(self, d):
        if d and self.show_c.currentIndex() == 0 and self.dev is None:
            self.dev = d
            self.fill()

    def open_in_discover(self):
        s = self.snap
        if not s:
            return
        n = self.ex.open_history(s)
        other = s['meta'].get('mode', 'ip') != self.ex.mode
        self.dv.live = True
        self.dv.show_tab('dev')
        self.win.toast((f"{n} device{'' if n == 1 else 's'} from {when(s['meta']['at'])} added" if n else
                        'Those devices are already in the list')
                       + (' – switch Connection to ' + ('MS/TP' if s['meta'].get('mode') == 'mstp' else 'BACnet/IP')
                          + ' to see them' if other else ''))

    def export(self):
        if not self.snap:
            return
        head = [self.tbl.horizontalHeaderItem(i).text() for i in range(self.tbl.columnCount())]
        stamp = time.strftime('%Y%m%d-%H%M', time.localtime(self.snap['meta']['at']))
        name = ['discover', 'changes', 'changes-vs-now'][self.show_c.currentIndex()]
        self.dv.save_csv(f'{name}-{stamp}.csv', csv_text(','.join(head), self.rows))

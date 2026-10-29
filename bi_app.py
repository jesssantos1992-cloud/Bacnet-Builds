"""
bi_app.py - BACnet Inspector, native Windows version (Qt / PySide6).

Run:  python bi_app.py [capture.pcapng]
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time

from PySide6.QtCore import (QAbstractTableModel, QByteArray, QEvent, QModelIndex, QObject, QRect, QSize, Qt, QThread,
                            QTimer, Signal)
from PySide6.QtGui import (QAction, QColor, QFont, QGuiApplication, QIcon, QKeySequence, QPainter, QPalette, QPixmap,
                           QShortcut)
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
                               QDialogButtonBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
                               QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox,
                               QPlainTextEdit, QPushButton, QSizePolicy, QSplitter, QStackedWidget, QSystemTrayIcon,
                               QTabBar, QTableView, QTextBrowser, QToolButton, QTreeWidget, QTreeWidgetItem,
                               QVBoxLayout, QWidget)

import bacnet_live as BL
import bi_core as C
import bi_ui as U
from bi_common import (AUTHOR, HighlightDelegate, Labels, colors, csv_text, csv_to_xlsx, doc, esc, html_table, is_dark,
                       label, semibold, stamp)
from bi_store import Store

APP_NAME = 'BACnet Inspector'
LIVE_MAX = 100_000


def res_path(name):
    return os.path.join(BL.BASE, name)


# ================================================================ captures --
class CaptureTab:
    """One open capture (a file, or the live capture)."""
    _ids = 0

    def __init__(self, name, path='', live=False):
        CaptureTab._ids += 1
        self.id = CaptureTab._ids
        self.n = name
        self.path = path
        self.live = live
        self.P = []
        self.FD = C.Analysis()
        self.T0 = 0.0
        self.q = ''
        self.busy = ''
        self.dirty = False
        self.sz = 0
        self.sv = {}
        self.scroll = 0
        self.sel_no = None
        self.next_no = 1

    def notes_key(self):
        return f'bi_notes|{self.n}|{self.sz or len(self.P)}|{C.jsround(self.T0)}'


class Loader(QThread):
    """Reads and decodes a capture file off the UI thread, then analyses it."""
    progress = Signal(object, str)
    finished_ok = Signal(object)
    failed = Signal(object, str)

    def __init__(self, tab, data, local_net, own_ips=()):
        super().__init__()
        self.tab, self.data, self.local_net, self.own_ips = tab, data, local_net, own_ips

    def run(self):
        t = self.tab
        try:
            k = C.parse(self.data)
            if not k:
                raise C.CaptureError('empty')
        except C.CaptureError:
            self.failed.emit(t, f'Could not read {t.n} (needs a pcap or pcapng file)')
            return
        self.data = None
        N = len(k)
        t.T0 = k[0][0]
        P = []
        step = 5000 if N > 20000 else N
        for j, (ts, lt, d, i) in enumerate(k):
            r = C.dis(ts, lt, d, j + 1, i)
            P.append(r)
            if step and (j + 1) % step == 0 and j + 1 < N:
                self.progress.emit(t, f'decoding {C.jsround(100 * (j + 1) / N)}% ({C.locale_int(j + 1)} of {C.locale_int(N)} packets)')
        t.P = P
        t.sz = N
        self.progress.emit(t, 'analysing…')
        t.FD = C.analyze(P, t.T0, self.local_net, self.own_ips)
        self.finished_ok.emit(t)


class Analyser(QThread):
    """Re-runs the analysis for the live capture in the background."""
    done = Signal(object, object)

    def __init__(self, tab, P, T0, local_net, own_ips=()):
        super().__init__()
        self.tab, self.P, self.T0, self.local_net, self.own_ips = tab, P, T0, local_net, own_ips

    def run(self):
        self.done.emit(self.tab, C.analyze(self.P, self.T0, self.local_net, self.own_ips))


# ============================================================ packet list --
class PacketModel(QAbstractTableModel):
    COLS = ['No.', 'Time', 'Source', 'Destination', 'Gateway', 'Protocol', 'Len', 'Info']

    def __init__(self, win):
        super().__init__()
        self.win = win
        self.V = []
        self.T0 = 0.0
        self.hit = None
        self.sort = None
        self.mono = QFont('Cascadia Mono')
        self.mono.setStyleHint(QFont.StyleHint.Monospace)
        self.mono.setPointSizeF(9)
        self.retheme()

    def retheme(self):
        c = colors()
        self.cb, self.cm, self.cbad, self.chit = QColor(c['b']), QColor(c['m']), QColor(c['bad']), QColor(c['hit'])
        self.cnote = QColor('#b8860b')

    def set_rows(self, V, T0, hit):
        self.beginResetModel()
        self.V, self.T0, self.hit = V, T0, hit
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.V)

    def columnCount(self, parent=QModelIndex()):
        return 8

    def headerData(self, s, o, role=Qt.ItemDataRole.DisplayRole):
        if o == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            t = self.COLS[s]
            keys = ['no', 't', 'src', 'dst', 'gw', 'proto', 'len', 'info']
            if self.sort and self.sort[0] == keys[s]:
                t += '  ▲' if self.sort[1] > 0 else '  ▼'
            return t
        if o == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.ToolTipRole:
            return 'Click to sort'
        return None

    def data(self, ix, role=Qt.ItemDataRole.DisplayRole):
        r = self.V[ix.row()]
        c = ix.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if c == 0:
                return ('★ ' if r.bm else '') + str(r.no)
            if c == 1:
                return C.tofixed(r.t - self.T0, 4)
            if c == 2:
                return f'net {r.sn} / {r.sa}' if r.sn is not None else r.src
            if c == 3:
                return r.dst
            if c == 4:
                return r.o if r.sn is not None else ''
            if c == 5:
                return r.proto
            if c == 6:
                return str(r.len)
            s = self.win.labels.lz(r.info)
            return s + (f'   \U0001f4dd {r.note}' if r.note else '')
        if role == Qt.ItemDataRole.BackgroundRole:
            if self.hit is not None and ix.row() in self.hit:
                return self.chit
            return self.cbad if r.bad else self.cm if r.proto == 'MS/TP' else self.cb
        if role == Qt.ItemDataRole.ForegroundRole:
            if self.hit is not None and ix.row() in self.hit:
                return QColor('#1c1917')
            if is_dark():
                return QColor('#f5f5f7')
            return None
        if role == Qt.ItemDataRole.FontRole:
            return self.mono
        if role == Qt.ItemDataRole.ToolTipRole and c == 7:
            return r.exp or None
        return None


SORTKEY = {'no': lambda r: r.no, 't': lambda r: r.t,
           'src': lambda r: f'net {r.sn} / {r.sa}' if r.sn is not None else r.src, 'dst': lambda r: r.dst,
           'gw': lambda r: r.o if r.sn is not None else '', 'proto': lambda r: r.proto, 'len': lambda r: r.len,
           'info': lambda r: r.info or ''}


QUICK = [('All', ''), ('I-Am', 'iam'), ('Who-Is', 'whois'), ('Routers', 'router'), ('Via gateway', 'gateway'),
         ('BACnet/IP', 'proto == "BACnet/IP"'), ('MS/TP', 'proto == "MS/TP"'), ('Damaged', 'bad'), ('Refused', 'nak'),
         ('Writes', 'write'), ('Commands', 'command'), ('Errors & aborts', 'error'), ('COV', 'cov'),
         ('Time sync / DCC', 'info contains "Time" || info contains "Communication"')]


class PacketsPane(QWidget):
    """Packets view: list, decoded details and hex, with search and quick filters above."""

    def __init__(self, win):
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        # search + quick filters
        bar = QWidget()
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(12, 8, 12, 8)
        bl.setSpacing(8)
        self.sq = QLineEdit()
        self.sq.setPlaceholderText('Search: device ID, IP or network…')
        self.sq.setToolTip('Type a device ID, an IP address, a network number or any word. Several words must all match.\n'
                           'Enter = next match, Shift+Enter = previous.')
        self.sq.setClearButtonEnabled(True)
        self.sq.setFixedWidth(240)
        bl.addWidget(self.sq)
        self.mode_hl = QToolButton(text='Highlight')
        self.mode_f = QToolButton(text='Filter')
        self.mode_hl.setToolTip('Highlight the matching packets and step through them')
        self.mode_f.setToolTip('Show only the matching packets')
        bl.addWidget(U.Segmented([self.mode_hl, self.mode_f]))
        m = (win.store.get('bi_sq') or {}).get('m', 'hl')
        (self.mode_f if m == 'f' else self.mode_hl).setChecked(True)
        self.sqn = label('', wrap=False, muted=True)
        self.sqn.setMinimumWidth(80)
        bl.addWidget(self.sqn)
        self.sqp = U.tool(QToolButton(), 'up', tip='Previous match (Shift+Enter)')
        self.sqd = U.tool(QToolButton(), 'down', tip='Next match (Enter)')
        bl.addWidget(self.sqp)
        bl.addWidget(self.sqd)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        bl.addWidget(sep)
        self.chips = QWidget()
        self.chl = QHBoxLayout(self.chips)
        self.chl.setContentsMargins(0, 0, 0, 0)
        self.chl.setSpacing(4)
        from PySide6.QtWidgets import QScrollArea
        sa = QScrollArea()
        sa.setWidget(self.chips)
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.Shape.NoFrame)
        sa.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sa.setFixedHeight(34)
        bl.addWidget(sa, 1)
        lay.addWidget(bar)
        self.build_chips()
        # list + details
        self.model = PacketModel(win)
        self.tv = QTableView()
        self.tv.setModel(self.model)
        self.tv.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tv.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tv.setShowGrid(False)
        self.tv.setWordWrap(False)
        self.tv.verticalHeader().setVisible(False)
        self.tv.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.tv.verticalHeader().setDefaultSectionSize(24)
        hh = self.tv.horizontalHeader()
        hh.setStretchLastSection(True)
        hh.setSectionsClickable(True)
        hh.setHighlightSections(False)
        hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._auto_cols = True               # share the width out until the user drags a column
        self._sizing = False
        self.tv.installEventFilter(self)
        hh.sectionResized.connect(self._col_dragged)
        self.fit_columns()
        self.tv.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.hl = HighlightDelegate(self.tv, clickable=False)   # colour IPs, MACs, networks and device IDs
        for c in (2, 3, 4, 7):
            self.tv.setItemDelegateForColumn(c, self.hl)
        self.det = QTreeWidget()
        self.det.setHeaderHidden(True)
        self.det.setFont(self.model.mono)
        self.det.setUniformRowHeights(True)
        self.det.setAnimated(True)
        self.det.setItemDelegate(HighlightDelegate(self.det, clickable=False))
        self.det.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        cp = QAction('Copy', self.det)
        cp.triggered.connect(lambda: QApplication.clipboard().setText(
            '\n'.join(('    ' if i.parent() else '') + i.text(0) for i in self.det.selectedItems()) or ''))
        self.det.addAction(cp)
        self.det.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.hex = QPlainTextEdit()
        self.hex.setReadOnly(True)
        self.hex.setFont(self.model.mono)
        self.hex.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.bot = QSplitter(Qt.Orientation.Horizontal)
        self.bot.addWidget(self.det)
        self.bot.addWidget(self.hex)
        self.bot.setSizes([600, 420])
        self.empty = U.EmptyState()
        self.top = QStackedWidget()
        self.top.addWidget(self.empty)
        self.top.addWidget(self.tv)
        self.split = QSplitter(Qt.Orientation.Vertical)
        self.split.addWidget(self.top)
        self.split.addWidget(self.bot)
        self.split.setStretchFactor(0, 3)
        self.split.setStretchFactor(1, 2)
        self.split.setSizes([560, 360])
        st = win.store.get('bi_split')
        if st:
            self.split.restoreState(QByteArray.fromBase64(st.encode()))
        self.split.splitterMoved.connect(lambda *_: win.store.set('bi_split', bytes(self.split.saveState().toBase64()).decode()))
        lay.addWidget(self.split, 1)
        self.set_empty('Open a capture', 'Drop a .pcap or .pcapng file here, or open one. BACnet/IP and MS/TP are decoded on '
                       'this computer – nothing is uploaded.', 'file', [('Open capture…', win.open_files)])
        # state
        self.V = []
        self.HI = []
        self.HK = -1
        self.sort = None
        self.sel = None
        # wiring
        self.tv.selectionModel().currentRowChanged.connect(self.on_row)
        self.tv.customContextMenuRequested.connect(self.menu)
        self.tv.doubleClicked.connect(self.dbl)
        hh.sectionClicked.connect(self.sort_click)
        self._sqt = QTimer(self, singleShot=True, timeout=self.relist)
        self.sq.textChanged.connect(lambda _: self._sqt.start(250 if len(self.win.P) > 20000 else 0))
        self.sq.returnPressed.connect(lambda: self.sq_go(-1 if QGuiApplication.keyboardModifiers() & Qt.KeyboardModifier.ShiftModifier else 1))
        self.sqd.clicked.connect(lambda: self.sq_go(1))
        self.sqp.clicked.connect(lambda: self.sq_go(-1))
        for b in (self.mode_hl, self.mode_f):
            b.toggled.connect(self.mode_changed)
        esc_ = QShortcut(QKeySequence('Escape'), self.sq, activated=lambda: self.sq.clear())
        esc_.setContext(Qt.ShortcutContext.WidgetShortcut)

    # -------------------------------------------------------------- columns --
    COLW = [(.05, 48), (.07, 72), (.20, 150), (.17, 140), (.15, 110), (.08, 80), (.04, 40)]   # (share, minimum); Info gets the rest

    def fit_columns(self):
        if not self._auto_cols:
            return
        w = max(600, self.tv.viewport().width())
        self._sizing = True
        for i, (share, mn) in enumerate(self.COLW):
            self.tv.setColumnWidth(i, max(mn, int(w * share)))
        self._sizing = False

    def _col_dragged(self, *_):
        if not self._sizing:
            self._auto_cols = False

    def eventFilter(self, obj, ev):
        if obj is self.tv and ev.type() == QEvent.Type.Resize:
            self.fit_columns()
        return False

    # ---------------------------------------------------------------- chips --
    def build_chips(self):
        while self.chl.count():
            w = self.chl.takeAt(0).widget()
            if w:
                w.setParent(None)                   # hide it now, not when Qt gets round to deleting it
                w.deleteLater()
        for n, f in QUICK:
            b = QToolButton(text=n.replace('&', '&&'))
            b.setToolTip(f or 'Show everything')
            b.setAutoRaise(False)
            b.clicked.connect(lambda _=False, f=f: self.win.set_filter(f))
            self.chl.addWidget(b)
        for i, (n, f) in enumerate(self.win.store.get('bi_presets') or []):
            b = QToolButton(text='★ ' + n.replace('&', '&&'))
            b.setToolTip(f + '\n(right-click to remove this saved filter)')
            b.clicked.connect(lambda _=False, f=f: self.win.set_filter(f))
            b.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            b.customContextMenuRequested.connect(lambda _p, i=i: self.del_preset(i))
            self.chl.addWidget(b)
        s = QToolButton(text='＋ Save current filter')
        s.setToolTip('Save the filter in the box as a one-click button')
        s.clicked.connect(self.save_preset)
        self.chl.addWidget(s)
        self.chl.addStretch(1)

    def save_preset(self):
        f = self.win.qbox.text().strip()
        if not f:
            return self.win.toast('Type a filter in the box first, then save it')
        n, ok = QInputDialog.getText(self, 'Save filter', f'Name for this filter:\n{f}', text=f[:24])
        if ok and n.strip():
            UP = self.win.store.get('bi_presets') or []
            UP.append([n.strip(), f])
            self.win.store.set('bi_presets', UP)
            self.build_chips()

    def del_preset(self, i):
        UP = self.win.store.get('bi_presets') or []
        if 0 <= i < len(UP) and QMessageBox.question(self, 'Remove saved filter', f'Remove the saved filter “{UP[i][0]}”?') == QMessageBox.StandardButton.Yes:
            UP.pop(i)
            self.win.store.set('bi_presets', UP)
            self.build_chips()

    # ---------------------------------------------------------------- list --
    def set_empty(self, title, text='', icon='file', buttons=None, busy=False):
        self.empty.set(icon, title, text, [] if buttons is None else buttons, busy)

    def show_list(self, on):
        self.top.setCurrentIndex(1 if on else 0)

    def mode_changed(self, on):
        if not on:
            return
        self.win.store.set('bi_sq', {'m': 'f' if self.mode_f.isChecked() else 'hl'})
        self.HK = -1
        self.relist()

    def sort_click(self, col):
        k = ['no', 't', 'src', 'dst', 'gw', 'proto', 'len', 'info'][col]
        self.sort = (k, 1) if not self.sort or self.sort[0] != k else (k, -1) if self.sort[1] > 0 else None
        self.relist()

    def relist(self, keep=True):
        """Apply the display filter, search and sort (the original's rl())."""
        win = self.win
        P = win.P
        q = win.qbox.text().strip()
        ok = True
        try:
            ff = C.compile_filter(q, win.T0)
        except C.FilterError:
            ok = False
        win.filter_state(q, ok)
        V = [r for r in P if ff(r)] if q and ok else P
        sqt = self.sq.text().strip()
        if sqt and self.mode_f.isChecked():
            m = C.search_matcher(sqt)
            V = [r for r in V if m(r)]
        self._gen = getattr(self, '_gen', 0) + 1
        if self.sort:
            # V is in capture order and Python's sort is stable, so equal values stay in capture order both ways
            key, rev, gen = self._sort_key(), self.sort[1] < 0, self._gen
            if len(V) > 60000:                      # big capture: sort in the background, keep the window responsive
                if not getattr(self, '_waiting', False):
                    self._waiting = True
                    QApplication.setOverrideCursor(Qt.CursorShape.BusyCursor)
                win.st.setText(f'Sorting {C.locale_int(len(V))} packets…')

                def work(V=V):
                    S = sorted(V, key=key, reverse=rev)
                    win.on_ui(lambda: self._sorted(gen, S, sqt, keep))
                threading.Thread(target=work, daemon=True).start()
                return
            V = sorted(V, key=key, reverse=rev)
        self._apply(V, sqt, keep)

    def _sort_key(self):
        """Sort key for the chosen column; text keys are worked out once per packet and remembered."""
        k = self.sort[0]
        g = SORTKEY[k]
        if k in ('no', 't', 'len'):
            return g
        attr = '_sk_' + k

        def key(r):
            v = r.__dict__.get(attr)
            if v is None:
                v = C.natural_key(g(r))
                setattr(r, attr, v)
            return v
        return key

    def _sorted(self, gen, S, sqt, keep):
        if getattr(self, '_waiting', False):
            self._waiting = False
            QApplication.restoreOverrideCursor()
        if gen == self._gen:                        # ignore a sort that a newer filter or click has replaced
            self._apply(S, sqt, keep)

    def _apply(self, V, sqt, keep):
        win = self.win
        self.V = V
        self.HI = []
        hit = None
        if sqt and self.mode_hl.isChecked():
            m = C.search_matcher(sqt)
            self.HI = [i for i, r in enumerate(V) if m(r)]
            hit = set(self.HI)
        self.model.sort = self.sort
        sel = self.sel
        sb = self.tv.verticalScrollBar()
        y = sb.value()
        self.model.set_rows(V, win.T0, hit)
        sb.setValue(y)
        self.sq_ui()
        win.status_count()
        if sel is not None and keep:
            try:
                i = V.index(sel)
            except ValueError:
                self.clear_details()
                return
            sm = self.tv.selectionModel()
            sm.blockSignals(True)
            self.tv.selectRow(i)
            sm.blockSignals(False)
            self.tv.viewport().update()
            sb.setValue(y)

    def sq_ui(self):
        on = bool(self.sq.text().strip())
        hl = on and self.mode_hl.isChecked()
        self.sqp.setVisible(hl and bool(self.HI))
        self.sqd.setVisible(hl and bool(self.HI))
        if not on:
            self.sqn.setText('')
        elif self.mode_f.isChecked():
            self.sqn.setText(f'{C.locale_int(len(self.V))} shown')
        else:
            n = len(self.HI)
            self.sqn.setText(f"{C.locale_int(n)} match{'' if n == 1 else 'es'}" + (f' · {self.HK + 1} of {n}' if self.HK >= 0 and n else ''))
            if n > 1:
                self.win.tip('find', self.sq)

    def sq_go(self, d):
        if not self.HI:
            return
        self.HK = (self.HK + d + len(self.HI)) % len(self.HI)
        self.pick(self.HI[self.HK])
        self.sq_ui()

    def pick(self, i):
        if 0 <= i < len(self.V):
            self.tv.selectRow(i)
            self.tv.scrollTo(self.model.index(i, 0))

    def follow(self):
        if self.V:
            self.tv.scrollToBottom()

    def on_row(self, cur, _prev):
        i = cur.row()
        if not (0 <= i < len(self.V)):
            return
        self.sel = self.V[i]
        if self.win.ac:
            self.win.ac.sel_no = self.sel.no
        self.show_packet(self.sel)
        self.win.tip('packet', self.tv)

    def clear_details(self):
        self.sel = None
        self.det.clear()
        QTreeWidgetItem(self.det, ['Select a packet'])
        self.hex.setPlainText('')

    def show_packet(self, r):
        self.det.clear()
        lz = self.win.labels.lz
        top = QTreeWidgetItem(self.det, [f'Frame {r.no}: {r.len} bytes' + (f' · note: {r.note}' if r.note else '')])
        f = semibold(top.font(0))
        top.setFont(0, f)
        at = {}                                    # the last item at each depth, so rows nest as deep as they go
        for lvl, s in C.detail_tree(r):
            par = at.get(lvl - 1) if lvl > 0 else None
            if par is None:
                it = QTreeWidgetItem(self.det, [lz(s)])
                it.setFont(0, f)
                lvl = 0
            else:
                it = QTreeWidgetItem(par, [lz(s)])
                if s.startswith('Meaning: '):
                    it.setForeground(0, QColor(colors()['mu']))
            it.setToolTip(0, s)
            at[lvl] = it
            for x in [x for x in at if x > lvl]:
                del at[x]
        self.det.expandAll()
        self.hex.setPlainText(C.hx(r.d))

    def dbl(self, ix):
        r = self.V[ix.row()]
        f = ['no', 'time', 'src', 'dst', 'gateway', 'proto', 'len', 'info'][ix.column()]
        v = (C.tofixed(r.t - self.win.T0, 4) if f == 'time' else r.o if f == 'gateway' else
             {'no': r.no, 'src': r.src, 'dst': r.dst, 'proto': r.proto, 'len': r.len, 'info': r.info}[f])
        self.win.set_filter(f'{f} == "{v}"')

    # ----------------------------------------------------------- right-click --
    def menu(self, pos):
        ix = self.tv.indexAt(pos)
        if not ix.isValid():
            return
        self.tv.selectRow(ix.row())
        r = self.V[ix.row()]
        win = self.win
        F = C.cell_filter(r, ix.column(), win.T0)
        cur = win.qbox.text().strip()
        conv = (f'(from == "{r.key}" && to == "{r.dk}") || (from == "{r.dk}" && to == "{r.key}")' if r.key and r.dk else '')
        txt = str(self.model.data(ix))
        row = '\t'.join(str(self.model.data(self.model.index(ix.row(), c))) for c in range(8))
        neg = '!' + F

        def wrap(x):
            return f'({cur}) {x}'
        m = QMenu(self)

        def add(menu, text, fn, on=True):
            a = menu.addAction(text)
            a.setEnabled(bool(on))
            a.triggered.connect(fn)
        s1 = m.addMenu('Apply as Filter')
        add(s1, 'Selected', lambda: win.set_filter(F), F)
        add(s1, 'Not Selected', lambda: win.set_filter(neg), F)
        add(s1, '…and Selected', lambda: win.set_filter(wrap('&& ' + F)), F and cur)
        add(s1, '…or Selected', lambda: win.set_filter(wrap('|| ' + F)), F and cur)
        add(s1, '…and not Selected', lambda: win.set_filter(wrap('&& ' + neg)), F and cur)
        add(s1, '…or not Selected', lambda: win.set_filter(wrap('|| ' + neg)), F and cur)
        s2 = m.addMenu('Prepare as Filter')
        add(s2, 'Selected', lambda: win.set_filter(F, go=False), F)
        add(s2, '…and Selected', lambda: win.set_filter(wrap('&& ' + F), go=False), F and cur)
        add(s2, '…or Selected', lambda: win.set_filter(wrap('|| ' + F), go=False), F and cur)
        add(m, 'Conversation: traffic between these two addresses', lambda: win.set_filter(conv), conv)
        m.addSeparator()
        s3 = m.addMenu('Copy')
        add(s3, 'Cell value', lambda: QApplication.clipboard().setText(txt))
        add(s3, 'As filter', lambda: QApplication.clipboard().setText(F), F)
        add(s3, 'Whole row', lambda: QApplication.clipboard().setText(row))
        add(m, 'Clear filter', lambda: win.set_filter(''), cur)
        m.addSeparator()
        dv = win.pk_device(r)
        ob = win.pk_obj(r)
        add(m, 'Open this device in Discover', lambda: win.open_device_from_packet(dv), dv)
        add(m, 'Read this point now (live, read-only)', lambda: win.read_now(dv, ob), dv and ob)
        m.addSeparator()
        add(m, 'Remove bookmark' if r.bm else 'Bookmark this packet', lambda: (win.toggle_bm(r), win.tip('bookmark', self.tv)))
        add(m, 'Edit note…' if r.note else 'Add note…', lambda: win.note_dlg(r))
        m.exec(self.tv.viewport().mapToGlobal(pos))


# ============================================================ live capture --
class LivePanel(QWidget):
    """Live capture controls (shown while the Live capture tab is active)."""

    def __init__(self, win):
        super().__init__()
        self.win = win
        self.IFS = []
        v = QVBoxLayout(self)
        v.setContentsMargins(12, 8, 12, 8)
        v.setSpacing(6)
        row = QHBoxLayout()
        row.setSpacing(8)
        t = label('CAPTURE', wrap=False, muted=True, bold=True)
        t.setFixedWidth(70)
        row.addWidget(t)
        self.ifc = QComboBox()
        self.ifc.setToolTip('Where to listen: a network adapter (BACnet/IP) or a serial port (MS/TP)')
        self.ifc.setMinimumWidth(320)
        self.ifc.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        row.addWidget(self.ifc, 1)
        self.rf = U.tool(QToolButton(), 'refresh', tip='Look for adapters again')
        row.addWidget(self.rf)
        self.bdl = label('Baud', wrap=False)
        self.bd = QComboBox()
        self.bd.addItems(['9600', '19200', '38400', '57600', '76800', '115200'])
        self.bd.setCurrentText('38400')
        self.bd.setToolTip('Speed of the RS-485 trunk. All devices on a trunk use the same rate.')
        self.bdt = QPushButton('Detect')
        self.bdt.setToolTip('Listen on the trunk for a few seconds and find the baud rate')
        for w in (self.bdl, self.bd, self.bdt):
            row.addWidget(w)
        self.go = QPushButton('Start')
        self.go.setDefault(True)
        self.go.setMinimumWidth(90)
        row.addWidget(self.go)
        self.cl = QPushButton('Clear')
        self.cl.setToolTip('Throw away the packets captured so far')
        self.sv = QPushButton('Save capture')
        self.sv.setToolTip('Save everything captured so far as a .pcapng file')
        row.addWidget(self.cl)
        row.addWidget(self.sv)
        self.follow = QCheckBox('Follow newest')
        self.follow.setChecked(True)
        self.follow.setToolTip('Keep the newest packet in view')
        row.addWidget(self.follow)
        self.ls = QLabel('Stopped')
        row.addWidget(self.ls)
        self.ask_b = U.disclose(QToolButton(), 'Ask the network')
        self.ask_b.setToolTip('Send Who-Is, Who-Is-Router and similar messages')
        self.opt_b = U.disclose(QToolButton(), 'More options')
        row.addWidget(self.ask_b)
        row.addWidget(self.opt_b)
        v.addLayout(row)
        # options
        self.opt = QWidget()
        ol = QHBoxLayout(self.opt)
        ol.setContentsMargins(78, 0, 0, 0)
        ol.addWidget(label('Capture filter (Wireshark/Npcap only):', wrap=False))
        self.cf = QLineEdit('udp portrange 47808-47823')
        self.cf.setToolTip('Capture filter (BPF, Wireshark/Npcap only)')
        self.cf.setMaximumWidth(320)
        ol.addWidget(self.cf)
        ol.addStretch(1)
        self.opt.hide()
        v.addWidget(self.opt)
        # ask the network
        self.ask = QWidget()
        al = QHBoxLayout(self.ask)
        al.setContentsMargins(0, 0, 0, 0)
        t2 = label('ASK', wrap=False, muted=True, bold=True)
        t2.setFixedWidth(70)
        al.addWidget(t2)
        self.bw = QPushButton('Find all devices (Who-Is)')
        self.bw.setToolTip('Broadcast a Who-Is: every device answers with an I-Am')
        self.br = QPushButton('Find routers (Who-Is-Router)')
        self.br.setToolTip('Broadcast Who-Is-Router-To-Network: every router answers with the networks it can reach')
        self.bn = QPushButton('Ask network number (What-Is-Network-Number)')
        self.bn.setToolTip('Ask routers which number this network has')
        for b in (self.bw, self.br, self.bn):
            al.addWidget(b)
        al.addSpacing(16)
        al.addWidget(label('Send from', wrap=False))
        self.sf = QComboBox()
        self.sf.addItem('Automatic', '')
        self.sf.setToolTip('Which address on this PC to send from')
        al.addWidget(self.sf)
        al.addWidget(label('to', wrap=False))
        self.st2 = QLineEdit('255.255.255.255')
        self.st2.setToolTip('Broadcast address to send to')
        self.st2.setMaximumWidth(140)
        al.addWidget(self.st2)
        al.addStretch(1)
        self.ask.hide()
        v.addWidget(self.ask)
        self.err = QLabel()
        self.err.setWordWrap(True)
        self.err.setStyleSheet(f"color:{colors()['se']}")
        self.err.hide()
        v.addWidget(self.err)
        self.ask_b.toggled.connect(self.ask.setVisible)
        self.opt_b.toggled.connect(self.opt.setVisible)
        self.ifc.currentIndexChanged.connect(self.if_changed)
        self.rf.clicked.connect(lambda: self.win.load_interfaces(toast=True))
        self.bdt.clicked.connect(self.win.detect_baud)
        self.go.clicked.connect(self.win.start_stop)
        self.cl.clicked.connect(self.win.clear_live)
        self.sv.clicked.connect(self.win.save_live_raw)
        self.bw.clicked.connect(lambda: self.win.send_msg('whois'))
        self.br.clicked.connect(lambda: self.win.send_msg('whoisrouter'))
        self.bn.clicked.connect(lambda: self.win.send_msg('netnum'))
        self.if_changed()

    def cur(self):
        i = self.ifc.currentIndex()
        return self.IFS[i] if 0 <= i < len(self.IFS) else None

    def fill(self, l):
        self.IFS = l
        self.ifc.blockSignals(True)
        self.ifc.clear()
        if not l:
            self.ifc.addItem('No interfaces found – install Wireshark')
        for x in l:
            self.ifc.addItem(x['name'] + ('  ★ picked for you' if x.get('auto') else ''))
        sv = self.win.store.get('bi_if')
        i = -1
        if sv:
            i = next((k for k, x in enumerate(l) if x['name'] == sv), -1)
        if i < 0:
            i = next((k for k, x in enumerate(l) if x.get('auto')), -1)
        if i >= 0:
            self.ifc.setCurrentIndex(i)
        self.ifc.blockSignals(False)
        self.if_changed()

    def if_changed(self):
        s = self.cur()
        ser = bool(s) and s.get('backend') == 'serial'
        for w in (self.bdl, self.bd, self.bdt):
            w.setVisible(ser)
        self.cf.setEnabled(not s or s.get('backend') == 'dumpcap')
        if s:
            self.win.store.set('bi_if', s['name'])

    def show_err(self, m):
        self.err.setText(m or '')
        self.err.setVisible(bool(m))

    def set_running(self, run, n):
        self.go.setText('Stop' if run else 'Start')
        c = colors()
        self.ls.setText((f"● Capturing – {C.locale_int(n)} packet{'' if n == 1 else 's'}" if run
                         else f"Stopped – {C.locale_int(n)} packet{'' if n == 1 else 's'}"))
        self.ls.setStyleSheet(f"color:{c['no'] if run else c['mu']};font-weight:600")


# ============================================================ side bar icons --
def side_icon(k):
    """Sidebar icon: a thin line drawing in the accent colour."""
    return U.icon(k, colors()['ac'], 18, 1.7)


SIDE = [(None, None), ('p', 'Packets'), ('Analyze', None), ('f', 'Findings'), ('d', 'Devices'), ('w', 'Changes'),
        ('t', 'Traffic'), ('s', 'Response times & errors'), ('o', 'Online board'), ('Network', None),
        ('g', 'Network map'), ('a', 'Available IDs'), ('n', 'Available networks'), ('MS/TP', None),
        ('m', 'MS/TP trunk'), ('b', 'Bus speed'), ('Tools', None), ('c', 'Compare captures')]
VNAME = {'p': 'packets', 'f': 'findings', 'd': 'devices', 'a': 'available-ids', 'n': 'available-networks',
         's': 'response-times', 'c': 'compare', 'b': 'bus-speed', 'o': 'online', 'w': 'changes', 't': 'traffic',
         'm': 'mstp-trunk', 'g': 'network-map', 'x': 'explorer', 'r': 'report'}
VTITLE = {'p': 'Packets', 'f': 'Findings', 'd': 'Devices', 'a': 'Available IDs', 'n': 'Available Networks',
          's': 'Response times & errors', 'c': 'Compare', 'b': 'Bus speed', 'o': 'Online board', 'w': 'Changes',
          't': 'Traffic', 'm': 'MS/TP trunk', 'g': 'Network map', 'x': 'Discover'}


# ============================================================ main window --
class Bridge(QObject):
    """Thread-safe hop onto the UI thread."""
    call = Signal(object)


class MainWindow(QMainWindow):
    def __init__(self, store):
        super().__init__()
        self.store = store
        self.labels = Labels(store)
        import bi_common
        bi_common.LABELS = self.labels          # lets tables and trees highlight addresses
        bi_common.FIND = self.find_link         # clicking a highlighted address shows its packets
        self.bridge = Bridge()
        self.bridge.call.connect(lambda fn: fn())
        self.setWindowTitle(APP_NAME)
        ico = res_path('bacnet_inspector.ico')
        if os.path.isfile(ico):
            self.setWindowIcon(QIcon(ico))
        self.setAcceptDrops(True)
        self.TB = []
        self.ac = None
        self.P = []
        self.FD = C.Analysis()
        self.T0 = 0.0
        self.loaders = []
        self.cap = BL.Capture()
        try:
            self.own_ips = set(BL.local_ips()) | {'127.0.0.1'}    # this PC's addresses
        except OSError:
            self.own_ips = {'127.0.0.1'}
        self.LT = None
        self.run = False
        self.helper = True
        self.analysing = False
        self.live_dirty = False
        self.cur_view = 'p'
        self.last_capture_view = 'p'
        self.nav = []
        self.nav_lock = False
        self.ALR = []
        self.WS = {'init': 0, 'dev': set(), 'fit': set(), 'stat': {}, 'rb': 0}
        self.upd = None
        self.tray = None
        from bi_explore import Explorer
        self.explorer = Explorer(BL.RELAY, store, notify=self._ex_notify)
        self._ex_pending = False
        self.views = {}
        self.build_ui()
        self.build_menus()
        self.restore_geometry()
        QApplication.instance().installEventFilter(self)       # mouse Back button
        QTimer.singleShot(0, self.after_show)

    # --------------------------------------------------------------- layout --
    def build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        # sidebar: a title, then the views grouped under small headings
        self.sidew = QFrame()
        self.sidew.setObjectName('sidew')
        self.sidew.setFixedWidth(236)
        sv = QVBoxLayout(self.sidew)
        sv.setContentsMargins(0, 16, 0, 8)
        sv.setSpacing(6)
        self.side_title = label('Capture', bold=True, size=17, wrap=False)
        self.side_title.setContentsMargins(22, 0, 0, 2)
        sv.addWidget(self.side_title)
        self.side = QListWidget()
        self.side.setIconSize(QSize(18, 18))
        self.side.setFrameShape(QFrame.Shape.NoFrame)
        self.side.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.side_items = {}
        for k, t in SIDE:
            if k is None:
                continue
            if t is None:
                it = QListWidgetItem(k.upper())
                f = semibold(it.font())
                f.setPointSizeF(7.5)
                f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.6)
                it.setFont(f)
                it.setFlags(Qt.ItemFlag.NoItemFlags)
                it.setSizeHint(QSize(200, 34))
                it.setTextAlignment(Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft)
            else:
                it = QListWidgetItem(side_icon(k), t)
                it.setData(Qt.ItemDataRole.UserRole, k)
                it.setSizeHint(QSize(200, 32))
                self.side_items[k] = it
            self.side.addItem(it)
        self.side.currentItemChanged.connect(self._side_changed)
        self.side.itemClicked.connect(lambda _it: self.tip('views', self.side))
        sv.addWidget(self.side, 1)
        h.addWidget(self.sidew)
        col = QWidget()
        h.addWidget(col, 1)
        v = QVBoxLayout(col)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        # top bar: Back on the left, the Capture | Discover switch in the middle, search on the right
        top = QWidget()
        tg = QGridLayout(top)
        tg.setContentsMargins(12, 8, 12, 6)
        tg.setHorizontalSpacing(8)
        self.back = U.tool(QToolButton(), 'back', tip='Back to where you were (Alt+←)', px=18)
        self.back.setEnabled(False)
        self.back.clicked.connect(self.nav_back)
        self.back.clicked.connect(lambda: self.tip('back', self.back))
        tg.addWidget(self.back, 0, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.mode_c = QToolButton(text='Capture')
        self.mode_d = QToolButton(text='Discover')
        self.seg = U.Segmented([self.mode_c, self.mode_d], 112)
        self.mode_c.setChecked(True)
        self.mode_c.setToolTip('Captures and their analysis')
        self.mode_d.setToolTip('Find devices on the network and read their points (Ctrl+5)')
        self.mode_c.clicked.connect(lambda: self.goto(self.last_capture_view))
        self.mode_d.clicked.connect(lambda: (self.goto('x'), self.tip('discover', self.seg)))
        tg.addWidget(self.seg, 0, 1, Qt.AlignmentFlag.AlignCenter)
        rw = QWidget()
        rl = QHBoxLayout(rw)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)
        self.find_b = QPushButton('Search   Ctrl+K')
        self.find_b.setToolTip('Jump to any view, device, point, capture tab or command (Ctrl+K)')
        self.find_b.setCursor(Qt.CursorShape.PointingHandCursor)
        self.find_b.setMinimumWidth(170)
        self.find_b.clicked.connect(lambda: self.command_palette(True))
        rl.addWidget(self.find_b)
        tg.addWidget(rw, 0, 2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        tg.setColumnStretch(0, 1)
        tg.setColumnStretch(2, 1)
        v.addWidget(top)
        self.prog = U.TopProgress()              # thin progress line: decoding, scanning, sorting
        v.addWidget(self.prog)
        # write-access and update banners
        self.wb = QFrame()
        self.wb.setStyleSheet('QFrame{background:#c42b1c} QLabel{color:white} QPushButton{padding:2px 10px}')
        wl = QHBoxLayout(self.wb)
        wl.setContentsMargins(16, 8, 16, 8)
        self.wb_l = QLabel()
        wl.addWidget(self.wb_l, 1)
        b = QPushButton('Turn off')
        b.clicked.connect(self.disarm)
        wl.addWidget(b)
        self.wb.hide()
        v.addWidget(self.wb)
        self.ub = QFrame()
        self.ub.setObjectName('ub')
        wl2 = QHBoxLayout(self.ub)
        wl2.setContentsMargins(16, 8, 16, 8)
        self.ub_l = QLabel()
        wl2.addWidget(self.ub_l, 1)
        for t, fn in (('What’s new', lambda: self.upd_dlg()), ('Update now', lambda: self.upd_install()),
                      ('Later', self.upd_later)):
            bb = QPushButton(t)
            bb.clicked.connect(fn)
            wl2.addWidget(bb)
            if t == 'Update now':
                self.ub_go = bb
        self.ub.hide()
        v.addWidget(self.ub)
        # capture tabs
        self.tabrow = QWidget()
        tl = QHBoxLayout(self.tabrow)
        tl.setContentsMargins(8, 0, 8, 0)
        tl.setSpacing(4)
        self.tabbar = QTabBar()
        self.tabbar.setTabsClosable(True)
        self.tabbar.setMovable(True)
        self.tabbar.setExpanding(False)
        self.tabbar.setDocumentMode(True)
        self.tabbar.setElideMode(Qt.TextElideMode.ElideMiddle)
        self.tabbar.currentChanged.connect(self._tab_changed)
        self.tabbar.tabCloseRequested.connect(lambda i: self.close_tab(self._tab_at(i)))
        self.tabbar.tabMoved.connect(self._tab_moved)
        tl.addWidget(self.tabbar, 1)
        self.nb = U.tool(QToolButton(), 'plus', tip='Open capture in a new tab (Ctrl+O)')
        self.nb.clicked.connect(self.open_files)
        tl.addWidget(self.nb)
        v.addWidget(self.tabrow)
        # header: open + display filter + status
        self.header = QWidget()
        hl = QHBoxLayout(self.header)
        hl.setContentsMargins(16, 8, 16, 8)
        hl.setSpacing(12)
        ob = QPushButton('Open capture')
        ob.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        ob.clicked.connect(self.open_files)
        hl.addWidget(ob, 0, Qt.AlignmentFlag.AlignLeft)
        self.qbox = QLineEdit()
        self.qbox.setPlaceholderText('Display filter, e.g. device == 1001 && proto == "MS/TP"')
        self.qbox.setClearButtonEnabled(True)
        self.qbox.setToolTip('Wireshark-style display filter. Press F1 for the filter reference.')
        self.q_ok = self.qbox.addAction(self._dot('#22a722'), QLineEdit.ActionPosition.LeadingPosition)
        self.q_ok.setVisible(False)
        self.qbox.textChanged.connect(self._q_changed)
        self.qbox.returnPressed.connect(lambda: self.pk.relist())
        self._qt = QTimer(self, singleShot=True, timeout=self._q_apply)
        hl.addWidget(self.qbox, 1)
        self.st = label('No file loaded', wrap=False, muted=True)
        hl.addWidget(self.st)
        v.addWidget(self.header)
        self.live = LivePanel(self)
        self.live.hide()
        v.addWidget(self.live)
        # views
        self.stack = QStackedWidget()
        v.addWidget(self.stack, 1)
        self.pk = PacketsPane(self)
        self.stack.addWidget(self.pk)
        self.empty_view = U.EmptyState()       # analysis views before a capture is open
        self.stack.addWidget(self.empty_view)
        self.toaster = U.Toast(root)
        self.tipper = U.TipBubble(self, self.tips_off)
        self.write_timer = QTimer(self, interval=1000, timeout=self.wb_draw)
        self.write_timer.start()
        self.poll_timer = QTimer(self, interval=700, timeout=self.poll)
        self.online_timer = QTimer(self, interval=2000, timeout=self._online_tick)
        self.online_timer.start()
        self.busy_timer = QTimer(self, interval=120, timeout=self._busy_tick)
        self.busy_timer.start()
        sc = [('Ctrl+1', 'p'), ('Ctrl+2', 'f'), ('Ctrl+3', 'd'), ('Ctrl+4', 'o'), ('Ctrl+5', 'x'), ('Ctrl+6', 'w'),
              ('Ctrl+7', 't'), ('Ctrl+8', 'm'), ('Ctrl+9', 'g')]
        for k, vk in sc:
            QShortcut(QKeySequence(k), self, activated=lambda vk=vk: self.goto(vk))
        QShortcut(QKeySequence('Alt+Left'), self, activated=self.nav_back)
        QShortcut(QKeySequence('Ctrl+K'), self, activated=self.command_palette)
        esc_ = QShortcut(QKeySequence('Escape'), self.qbox, activated=lambda: self.set_filter(''))
        esc_.setContext(Qt.ShortcutContext.WidgetShortcut)
        self.style_chrome()
        self.side.setCurrentItem(self.side_items['p'])

    def style_chrome(self):
        """Colours of the sidebar, search field and banners (again after a theme change)."""
        c = colors()
        ac = QColor(c['ac'])
        sel = f"rgba({ac.red()},{ac.green()},{ac.blue()},{0.24 if is_dark() else 0.13})"
        self.sidew.setStyleSheet(
            f"QFrame#sidew{{background:{c['side']};border-right:1px solid {c['hair']}}}"
            'QListWidget{background:transparent;border:0;outline:0}'
            f"QListWidget::item{{border-radius:7px;padding:0px 6px;margin:0px 10px;color:{c['fg']}}}"
            'QListWidget::item:hover:!selected:enabled{background:rgba(118,118,128,0.14)}'
            f"QListWidget::item:selected{{background:{sel};color:{c['fg']}}}"
            f"QListWidget::item:disabled{{color:{c['mu']};background:transparent;padding-left:8px}}")
        for k, it in self.side_items.items():
            it.setIcon(side_icon(k))
        self.find_b.setIcon(U.icon('search', c['mu'], 16))
        self.find_b.setStyleSheet(f"QPushButton{{text-align:left;padding:5px 12px;border-radius:8px;border:0;"
                                  f"background:rgba(118,118,128,{0.24 if is_dark() else 0.12});color:{c['mu']}}}"
                                  f"QPushButton:hover{{background:rgba(118,118,128,{0.32 if is_dark() else 0.18})}}")
        self.ub.setStyleSheet(f"QFrame#ub{{background:{c['ac']}}} QFrame#ub QLabel{{color:white}} QPushButton{{padding:2px 10px}}")
        for b, n in ((self.back, 'back'), (self.nb, 'plus'), (self.pk.sqp, 'up'), (self.pk.sqd, 'down'), (self.live.rf, 'refresh')):
            b.setIcon(U.icon(n, c['fg'], 16))
        self.empty_view.retheme()
        self.pk.empty.retheme()

    @staticmethod
    def _dot(col):
        pm = QPixmap(16, 16)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QColor(col))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(4, 4, 8, 8)
        p.end()
        return QIcon(pm)

    def build_menus(self):
        mb = self.menuBar()

        def act(menu, text, fn, sc=None, en=None):
            a = QAction(text, self)
            if sc:
                a.setShortcut(QKeySequence(sc))
                a.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
            a.triggered.connect(fn)
            a._en = en
            menu.addAction(a)
            return a

        def refresh(menu):
            for a in menu.actions():
                if getattr(a, '_en', None):
                    a.setEnabled(bool(a._en()))
        m = mb.addMenu('&File')
        act(m, 'Open capture…', self.open_files, 'Ctrl+O')
        act(m, 'Close tab', lambda: self.close_tab(self.ac), 'Ctrl+W', lambda: self.ac and not self.ac.live)
        m.addSeparator()
        act(m, 'Save', lambda: self.do_save(False), 'Ctrl+S', lambda: self.ac or self.cur_view == 'x')
        act(m, 'Save As…', lambda: self.do_save(True), 'Ctrl+Shift+S', lambda: self.ac or self.cur_view == 'x')
        act(m, 'Export report…', self.do_report, None, lambda: self.ac)
        m.addSeparator()
        act(m, 'Exit', self.close)
        m.aboutToShow.connect(lambda m=m: refresh(m))
        m = mb.addMenu('&Edit')
        act(m, 'Copy selected packet', self.copy_packet, None, lambda: self.pk.sel)
        act(m, 'Search packets…', self.focus_search, 'Ctrl+F')
        act(m, 'Display filter…', self.focus_filter, 'Ctrl+L')
        act(m, 'Clear filter', lambda: self.set_filter(''), None, lambda: self.qbox.text())
        m.addSeparator()
        act(m, 'Bookmark selected packet', lambda: self.toggle_bm(self.pk.sel), 'Ctrl+B', lambda: self.pk.sel)
        act(m, 'Add / edit note…', lambda: self.note_dlg(self.pk.sel), None, lambda: self.pk.sel)
        act(m, 'Show bookmarked packets', lambda: self.go_packets('bookmark'), None, lambda: self.ac)
        m.addSeparator()
        act(m, 'Names & labels…', self.labels_dlg)
        m.aboutToShow.connect(lambda m=m: refresh(m))
        m = mb.addMenu('&View')
        for t, k in [('Packets', 'p'), ('Findings', 'f'), ('Devices', 'd'), ('Online board', 'o'),
                     ('Discover (find and browse devices)', 'x'), ('Changes (writes and commands)', 'w'),
                     ('Traffic', 't'), ('MS/TP trunk', 'm'), ('Network map', 'g')]:
            a = QAction(t, self)
            a.setShortcut(QKeySequence({'p': 'Ctrl+1', 'f': 'Ctrl+2', 'd': 'Ctrl+3', 'o': 'Ctrl+4', 'x': 'Ctrl+5',
                                        'w': 'Ctrl+6', 't': 'Ctrl+7', 'm': 'Ctrl+8', 'g': 'Ctrl+9'}[k]))
            a.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)    # handled by the window shortcuts
            a.triggered.connect(lambda _=False, k=k: self.goto(k))
            m.addAction(a)
        m.addSeparator()
        for t, k in [('Available IDs', 'a'), ('Available Networks', 'n'), ('Response times & errors', 's'),
                     ('Compare captures', 'c'), ('Bus speed', 'b')]:
            act(m, t, lambda _=False, k=k: self.goto(k))
        m.addSeparator()
        for t, v in [('Theme: automatic', ''), ('Theme: light', 'light'), ('Theme: dark', 'dark')]:
            act(m, t, lambda _=False, v=v: self.set_theme(v))
        self.m_galaxy = QAction('Galactic cursor', self, checkable=True)
        self.m_galaxy.setChecked(self.store.get('bi_galaxy', True))
        self.m_galaxy.toggled.connect(self.set_galaxy)
        m.addAction(self.m_galaxy)
        m.addSeparator()
        act(m, 'Reset pane size', self.reset_panes)
        m.addSeparator()
        act(m, 'Expand all devices', lambda: (self.goto('d'), self.view('d').expand(True)))
        act(m, 'Collapse all devices', lambda: (self.goto('d'), self.view('d').expand(False)))
        m = mb.addMenu('&Capture')
        self.m_arm = act(m, 'Enable write access…', lambda: self.disarm() if self.explorer.armed() else self.arm_dlg())
        act(m, 'Scan network for devices', lambda: (self.goto('x'), self.view('x').scan()), 'Ctrl+D', lambda: not self.explorer.busy)
        act(m, 'Discovery options…', lambda: self.view('x').options())
        act(m, 'Build site inventory…', lambda: (self.goto('x'), self.view('x').inventory()), None,
            lambda: not self.explorer.busy)
        m.addSeparator()
        act(m, 'Send Who-Is (all devices)', lambda: self.send_msg('whois'))
        act(m, 'Send Who-Is-Router (all networks)', lambda: self.send_msg('whoisrouter'))
        act(m, 'Send What-Is-Network-Number', lambda: self.send_msg('netnum'))
        m.addSeparator()
        self.m_run = act(m, 'Start capture', lambda: (self.switch_tab(self.LT), self.start_stop()), None, lambda: self.LT)
        act(m, 'Clear live capture', self.clear_live, None, lambda: self.LT)
        act(m, 'Save raw live capture (.pcapng)', self.save_live_raw, None, lambda: self.LT)

        def cap_menu(m=m):
            self.m_arm.setText('Turn off write access' if self.explorer.armed() else 'Enable write access…')
            self.m_run.setText('Stop capture' if self.run else 'Start capture')
            refresh(m)
        m.aboutToShow.connect(cap_menu)
        m = mb.addMenu('&Help')
        self.help_menu = m
        act(m, 'User manual', lambda: self.manual(), 'F1')
        act(m, 'Take the tour', self.tour)
        m.addSeparator()
        act(m, 'Quick start', lambda: self.manual('quick'))
        act(m, 'Display filter reference', lambda: self.manual('filter'))
        act(m, 'Discover and reading points', lambda: self.manual('discover'))
        act(m, 'Keyboard shortcuts', lambda: self.manual('keys'))
        act(m, 'Troubleshooting', lambda: self.manual('trouble'))
        m.addSeparator()
        act(m, 'Search everything…', self.command_palette)
        m.addSeparator()
        self.m_tips = QAction('Show tips', self, checkable=True)
        self.m_tips.toggled.connect(self.set_tips)
        m.addAction(self.m_tips)
        act(m, 'Show all tips again', self.reset_tips)
        m.aboutToShow.connect(lambda: (self.m_tips.blockSignals(True),
                                       self.m_tips.setChecked(not (self.store.get('bi_tips') or {}).get('off')),
                                       self.m_tips.blockSignals(False)))
        m.addSeparator()
        act(m, 'What’s new', self.whats_new)
        act(m, 'Check for updates…', lambda: self.upd_check(True))
        act(m, 'Report a problem…', self.report_problem)
        m.addSeparator()
        act(m, 'About BACnet Inspector', self.about)

    # ---------------------------------------------------------------- views --
    def view(self, k):
        """The view widget for k (created the first time it is needed)."""
        if k == 'p':
            return self.pk
        v = self.views.get(k)
        if v is None:
            if k == 'x':
                from bi_discover import DiscoverView
                v = DiscoverView(self)
            else:
                import bi_views
                v = bi_views.make(k, self)
            self.views[k] = v
            self.stack.addWidget(v)
        return v

    def _side_changed(self, it, _prev):
        k = it.data(Qt.ItemDataRole.UserRole) if it else None
        if k:
            self.show_view(k)

    def goto(self, k):
        if k == 'x':                            # Discover is its own mode, not a sidebar entry
            self.show_view('x')
            return
        it = self.side_items.get(k)
        if it is None:
            return
        if self.side.currentItem() is it:       # e.g. coming back from Discover
            self.show_view(k)
        else:
            self.side.setCurrentItem(it)

    NEEDS_CAPTURE = set('fdwtsoganmb')         # views that show a capture's analysis

    def _place(self, k, fade):
        """Show view k, or a friendly empty page when it needs a capture and none is loaded."""
        w = self.view(k)
        if k in self.NEEDS_CAPTURE and not self.P:
            t = self.ac
            e = self.empty_view
            if t and t.busy:
                e.set('file', f'Opening {t.n}', t.busy[:1].upper() + t.busy[1:], [], busy=True)
            elif t and t.live:
                e.set('wave', 'Nothing captured yet', f'{VTITLE.get(k, "This view")} fills in as packets arrive. '
                      'Start the live capture, or open a saved capture.',
                      [('Start capture', lambda: (self.goto('p'), self.start_stop())), ('Open capture…', self.open_files)])
            else:
                e.set('file', 'No capture open', f'Open a capture to see {VTITLE.get(k, "this view").lower()}.',
                      [('Open capture…', self.open_files)])
            w = e
        if self.stack.currentWidget() is not w:
            self.stack.setCurrentWidget(w)
            if fade:
                U.fade_in(w)
        return w

    def show_view(self, k):
        if k != self.cur_view:
            self.nav_note(k)
        self.cur_view = k
        if k != 'x':
            self.last_capture_view = k
        self.store.set('bi_view', k)
        w = self._place(k, True)
        disc = k == 'x'
        (self.mode_d if disc else self.mode_c).setChecked(True)
        self.sidew.setVisible(not disc)
        self.tabrow.setVisible(not disc)
        self.header.setVisible(not disc)
        self.qbox.setVisible(k == 'p')
        self.st.setVisible(k == 'p')
        self.live.setVisible(not disc and bool(self.ac and self.ac.live))
        if k != 'p' and w is not self.empty_view and hasattr(w, 'refresh'):
            w.refresh()
        self.update_back()

    def refresh_views(self):
        """The active capture or its analysis changed: update the current view and the badges."""
        nf = len(self.FD)
        self.side_items['f'].setText('Findings' + (f'   ({nf})' if nf else ''))
        nd = len(self.FD.dv or [])
        self.side_items['d'].setText('Devices' + (f'   ({nd})' if nd else ''))
        for k, v in self.views.items():
            v._stale = True
        if self.cur_view not in ('p', 'x'):
            self._place(self.cur_view, True)
        w = self.stack.currentWidget()
        if w is not self.pk and w is not self.empty_view and hasattr(w, 'refresh'):
            w.refresh()
        self.update_tabs()

    # ----------------------------------------------------------- navigation --
    def nav_note(self, new_view, node=None):
        """Remember the view we are leaving (Discover keeps its own page history)."""
        if self.nav_lock:
            return
        self.nav.append(self.cur_view)
        del self.nav[:-50]
        self.update_back()

    def nav_back(self):
        """Back: first through the pages of Discover, then to the previous view."""
        if self.cur_view == 'x' and 'x' in self.views and self.views['x'].back():
            self.update_back()
            return
        if not self.nav:
            return
        v = self.nav.pop()
        self.nav_lock = True
        try:
            self.goto(v)
        finally:
            self.nav_lock = False
        self.update_back()

    def update_back(self):
        disc = self.cur_view == 'x' and 'x' in self.views and self.views['x'].can_back()
        self.back.setEnabled(bool(self.nav) or disc)

    def eventFilter(self, obj, ev):
        """The Back button on a mouse goes back too."""
        if ev.type() == QEvent.Type.MouseButtonPress and ev.button() == Qt.MouseButton.BackButton and self.isActiveWindow():
            self.nav_back()
            return True
        return False

    # ----------------------------------------------------------------- tabs --
    def _tab_at(self, i):
        tid = self.tabbar.tabData(i)
        return next((t for t in self.TB if t.id == tid), None)

    def _tab_moved(self, a, b):
        order = [self.tabbar.tabData(i) for i in range(self.tabbar.count())]
        self.TB.sort(key=lambda t: order.index(t.id) if t.id in order else 0)
        self.save_session()

    def update_tabs(self):
        self.tabbar.blockSignals(True)
        while self.tabbar.count() > len(self.TB):
            self.tabbar.removeTab(self.tabbar.count() - 1)
        for i, t in enumerate(self.TB):
            if i >= self.tabbar.count():
                self.tabbar.addTab('')
            ns = sum(1 for f in t.FD if f['s'] == 'SERIOUS')
            txt = t.n + (f'  ⚠ {ns}' if ns else '')
            self.tabbar.setTabText(i, txt)
            self.tabbar.setTabIcon(i, U.dot(colors()['no']) if t.live and self.run else
                                   U.icon('wave' if t.live else 'file', colors()['mu'], 14))
            self.tabbar.setTabData(i, t.id)
            self.tabbar.setTabToolTip(i, t.path or t.n)
            self.tabbar.setTabTextColor(i, QColor(colors()['se']) if ns else self.tabbar.palette().color(QPalette.ColorRole.WindowText))
            if t.live:
                self.tabbar.setTabButton(i, QTabBar.ButtonPosition.RightSide, None)
            if t is self.ac:
                self.tabbar.setCurrentIndex(i)
        self.tabbar.blockSignals(False)
        self.tabrow.setVisible(self.cur_view != 'x')

    def _tab_changed(self, i):
        t = self._tab_at(i)
        if t is not None and t is not self.ac:
            self.switch_tab(t)

    def switch_tab(self, t):
        if t is None:
            return
        if self.ac:
            self.ac.q = self.qbox.text()
            self.ac.scroll = self.pk.tv.verticalScrollBar().value()
        self.ac = t
        self.P, self.T0, self.FD = t.P, t.T0, t.FD
        self.qbox.blockSignals(True)
        self.qbox.setText(t.q)
        self.qbox.blockSignals(False)
        self.pk.sel = next((r for r in t.P if r.no == t.sel_no), None) if t.sel_no else None
        self.pk.relist()
        if self.pk.sel is None:
            self.pk.clear_details()
        else:
            self.pk.show_packet(self.pk.sel)
        self.pk.show_list(bool(self.P))
        if not self.P:
            if t.live:
                self.pk.set_empty('Live capture ready', 'Choose an adapter above and press Start. Saved captures open in their own '
                                  'tabs.', 'wave', [('Start capture', self.start_stop), ('Open capture…', self.open_files)])
            else:
                self.pk.set_empty(f'Opening {t.n}', t.busy[:1].upper() + t.busy[1:], 'file', [], busy=True)
        QTimer.singleShot(0, lambda s=t.scroll: self.pk.tv.verticalScrollBar().setValue(s))
        self.live.setVisible(t.live and self.cur_view != 'x')
        self.setWindowTitle(f'{t.n} – {APP_NAME}')
        self.refresh_views()
        self.save_session()

    def close_tab(self, t):
        if not t or t.live:
            return
        i = self.TB.index(t)
        self.TB.remove(t)
        if t.path:
            self.toast(f'Closed {t.n}', lambda p=t.path, q=(self.qbox.text() if t is self.ac else t.q): self.open_path(p, q))
        if t is self.ac:
            self.ac = None
            nt = self.TB[min(i, len(self.TB) - 1)] if self.TB else None
            if nt:
                self.switch_tab(nt)
            else:
                self.P, self.FD, self.T0 = [], C.Analysis(), 0.0
                self.pk.relist()
                self.pk.show_list(False)
                self.pk.set_empty('Open a capture', 'Drop a .pcap or .pcapng file here, or open one.', 'file',
                                  [('Open capture…', self.open_files)])
                self.st.setText('No file loaded')
                self.setWindowTitle(APP_NAME)
                self.refresh_views()
        self.update_tabs()
        self.save_session()

    # ---------------------------------------------------------------- files --
    def open_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, 'Open capture', self.store.get('bi_dir') or '',
                                                'Capture files (*.pcap *.pcapng *.cap);;All files (*.*)')
        for p in paths:
            self.store.set('bi_dir', os.path.dirname(p))
            self.open_path(p)
        if paths:
            self.tip('open', self.tabrow, 900)

    def open_path(self, path, q='', activate=True):
        path = os.path.abspath(path)
        for t in self.TB:
            if t.path and os.path.normcase(t.path) == os.path.normcase(path):
                if activate:
                    self.switch_tab(t)
                return
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except OSError as e:
            return self.toast(f'Could not open {path}: {e.strerror}')
        t = CaptureTab(os.path.basename(path), path)
        t.q = q
        t.busy = 'decoding 0%'
        self.TB.append(t)
        if activate or not self.ac:
            self.switch_tab(t)
        self.update_tabs()
        ld = Loader(t, data, self.local_net(), self.own_ips)
        ld.progress.connect(self._load_progress)
        ld.finished_ok.connect(self._loaded)
        ld.failed.connect(self._load_failed)
        ld.finished.connect(lambda ld=ld: self.loaders.remove(ld) if ld in self.loaders else None)
        self.loaders.append(ld)
        ld.start()

    def _load_progress(self, t, msg):
        t.busy = msg
        if t is self.ac:
            self.st.setText(f'{t.n}: {msg}')
            if not t.P:
                self.pk.set_empty(f'Opening {t.n}', msg[:1].upper() + msg[1:], 'file', [], busy=True)
            if self.stack.currentWidget() is self.empty_view:
                self._place(self.cur_view, False)

    def _loaded(self, t):
        t.busy = ''
        self.load_notes(t)
        if t is self.ac:
            self.switch_tab(t)
            if t.sel_no is None:
                self.pk.clear_details()
        self.update_tabs()
        self.save_session()

    def _load_failed(self, t, msg):
        if t in self.TB:
            self.TB.remove(t)
            if t is self.ac:
                self.ac = None
                if self.TB:
                    self.switch_tab(self.TB[-1])
                else:
                    self.P, self.FD = [], C.Analysis()
                    self.pk.relist()
                    self.pk.show_list(False)
            self.update_tabs()
        self.toast(msg)
        self.st.setText(msg)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        for u in e.mimeData().urls():
            p = u.toLocalFile()
            if p and os.path.isfile(p):
                self.open_path(p)

    def local_net(self):
        try:
            return int((self.store.get('bi_av2') or {}).get('ln') or '') or None
        except ValueError:
            return None

    # ---------------------------------------------------------- notes / bm --
    def load_notes(self, t):
        o = self.store.get(t.notes_key()) or {}
        if not o:
            return
        for r in t.P:
            x = o.get(str(r.no))
            if x:
                r.bm = 1
                if x[1]:
                    r.note = x[1]

    def save_notes(self, t):
        if not t or t.live:
            return
        o = {str(r.no): [1, r.note or ''] for r in t.P if r.bm}
        self.store.set(t.notes_key(), o or None)

    def toggle_bm(self, r):
        if not r:
            return
        r.bm = 0 if r.bm else 1
        if not r.bm:
            r.note = None
        self.save_notes(self.ac)
        self.pk.relist()
        if r is self.pk.sel:
            self.pk.show_packet(r)
        self.toast(f'Bookmarked packet {r.no}' if r.bm else 'Bookmark removed')

    def note_dlg(self, r):
        if not r:
            return
        d = QDialog(self)
        d.setWindowTitle(f'Note for packet {r.no}')
        v = QVBoxLayout(d)
        v.addWidget(label(r.info, muted=True))
        ed = QPlainTextEdit(r.note or '')
        v.addWidget(ed)
        v.addWidget(label('A packet with a note is also bookmarked. Notes are saved on this computer for this capture and '
                          'included in saved packet lists and reports.', muted=True))
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        rm = bb.addButton('Remove note', QDialogButtonBox.ButtonRole.DestructiveRole)
        v.addWidget(bb)
        bb.accepted.connect(d.accept)
        bb.rejected.connect(d.reject)
        rm.clicked.connect(lambda: d.done(2))
        d.resize(460, 260)
        res = d.exec()
        if res == 2:
            r.note = None
        elif res == QDialog.DialogCode.Accepted:
            t = ed.toPlainText().strip()
            if t:
                r.note = t
                r.bm = 1
            else:
                r.note = None
        else:
            return
        self.save_notes(self.ac)
        self.pk.relist()
        if r is self.pk.sel:
            self.pk.show_packet(r)

    # -------------------------------------------------------------- filters --
    def _q_changed(self, _t):
        self._qt.start(250 if len(self.P) > 20000 else 0)

    def _q_apply(self):
        self.pk.relist()
        self.save_session()
        if self.qbox.text().strip():
            self.tip('filter', self.qbox, 1200)

    def filter_state(self, q, ok):
        self.q_ok.setVisible(bool(q))
        self.q_ok.setIcon(self._dot('#22a722' if ok else '#d13438'))
        self.q_ok.setToolTip('Filter is valid' if ok else 'This filter is not valid – press F1 for the reference')

    def set_filter(self, f, go=True):
        self.qbox.blockSignals(True)
        self.qbox.setText(f)
        self.qbox.blockSignals(False)
        if self.ac:
            self.ac.q = f
        if go:
            self.pk.relist()
        else:
            self.filter_state(f, True)
        self.save_session()

    def find_link(self, href):
        """A highlighted IP, MAC, network or device ID was clicked: show the packets that involve it."""
        import re
        from urllib.parse import unquote
        kind, _, val = unquote(href[3:]).partition('|')
        if not self.ac:
            return self.toast('Open a capture to find this in the packets')
        n = (re.search(r'\d+', val) or [''])[0] if kind in ('mac', 'net', 'id') else ''
        if kind == 'ip':
            f, what = f'ip == "{val}"', val
        elif kind == 'host':
            f, what = f'host == "{val}"', val
        elif kind == 'mac':
            f, what = f'mac == {n}', f'MAC {n}'
        elif kind == 'net':
            f, what = f'net == {n} || dnet == {n}', f'network {n}'
        elif kind == 'q':                       # 'Show the packets behind this finding'
            self.go_packets(val)
            n = len(self.pk.V)
            return self.toast(f'{C.locale_int(n)} packet{"" if n == 1 else "s"} behind this finding – '
                              'clear the filter (Esc) to see everything again' if n else 'No packets match this finding')
        elif kind == 'id':
            keys = sorted(k for k, ids in C.kid_map(self.FD).items() if int(n) in ids and k)
            f = ' || '.join([f'host == "{k}"' for k in keys] + [f'device == {n}'])
            what = f'device {n}'
        else:
            return
        self.go_packets(f)
        self.toast(f'{C.locale_int(len(self.pk.V))} packets involve {what}' if self.pk.V else f'No packets involve {what}')

    def go_packets(self, f):
        self.goto('p')
        self.set_filter(f)
        self.pk.tv.scrollToTop()

    def status_count(self):
        t = self.ac
        busy = f' – {t.busy}' if t and t.busy else ''
        if t:
            self.st.setText(f'{C.locale_int(len(self.pk.V))} of {C.locale_int(len(self.P))} packets{busy}')
        else:
            self.st.setText('No file loaded')

    def focus_search(self):
        self.goto('p')
        self.pk.sq.setFocus()
        self.pk.sq.selectAll()

    def focus_filter(self):
        self.goto('p')
        self.qbox.setFocus()
        self.qbox.selectAll()

    def copy_packet(self):
        i = self.pk.tv.currentIndex().row()
        if i >= 0:
            QApplication.clipboard().setText('\t'.join(str(self.pk.model.data(self.pk.model.index(i, c))) for c in range(8)))

    # ---------------------------------------------------------- live capture --
    def after_show(self):
        """Things that run once the window is on screen."""
        self.LT = CaptureTab('Live capture', live=True)
        self.TB.insert(0, self.LT)
        threading.Thread(target=self._bg_init, daemon=True).start()
        if not self.ac:
            self.switch_tab(self.LT)
        self.update_tabs()
        self.restore_session()
        last = self.store.get('bi_view')
        if last and last != 'p' and (last == 'x' or last in self.side_items):
            self.goto(last)                       # open where the user left off
            self.nav.clear()
            self.update_back()
        U.style_titlebar(self)
        seen = self.store.get('bi_seen_ver')
        if self.first_run_ui and seen != BL.APP_VERSION:
            self.store.set('bi_seen_ver', BL.APP_VERSION)
            if seen or self.store.get('bi_geom'):          # an existing user who has just updated
                self.store.set('bi_toured', self.store.get('bi_toured') or 'offered')
                QTimer.singleShot(700, self.whats_new)
            elif not self.store.get('bi_toured'):         # brand new: show them around
                QTimer.singleShot(900, self.tour)
        if self.store.get('bi_updauto', '1') != '0' and time.time() - float(self.store.get('bi_updlast') or 0) > 86400:
            QTimer.singleShot(4000, lambda: self.upd_check(False))

    def _bg_init(self):
        try:
            l = BL.list_interfaces()
        except Exception:
            l = []
        try:
            ips = BL.local_ips()
        except Exception:
            ips = []
        self.on_ui(lambda: self._got_ifs(l, ips))

    def _got_ifs(self, l, ips):
        self.live.fill(l)
        self.live.sf.clear()
        self.live.sf.addItem('Automatic', '')
        for x in ips:
            self.live.sf.addItem(x, x)

    def load_interfaces(self, toast=False):
        def work():
            try:
                l = BL.list_interfaces()
            except Exception:
                l = []
            self.on_ui(lambda: (self.live.fill(l), self.live.show_err(''),
                                toast and self.toast(f"Found {len(l)} adapter{'' if len(l) == 1 else 's'}" if l else 'No adapters found')))
        threading.Thread(target=work, daemon=True).start()

    def on_ui(self, fn):
        self.bridge.call.emit(fn)

    def start_stop(self):
        s = self.live.cur()
        if self.run:
            self.cap.stop()
            self.poll()
            return
        if not s or s.get('backend') == 'none':
            return self.live.show_err((s or {}).get('hint') or 'No adapter selected.')
        link = self.explorer.link
        if s.get('backend') == 'serial' and link and link.on and link.port == s.get('id'):
            return self.live.show_err(f"{s['id']} is in use by Discover (joined to the MS/TP trunk). Leave the trunk in "
                                      'Discover first – one program at a time can use a COM port.')
        self.LT.ts = time.time()
        self.live.show_err('')
        self.switch_tab(self.LT)
        self.clear_live(local_only=True)
        self.cap.start(s['backend'], s['id'], self.live.cf.text(), int(self.live.bd.currentText()))
        self.run = True
        self.poll_timer.start()
        self.poll()
        self.tip('live', self.live.follow, 3000)
        ex = self.explorer
        if ex.opt.get('auto') and s.get('backend') != 'serial' and ex.mode != 'mstp':
            QTimer.singleShot(1500, lambda: self.run and not ex.busy and self.view('x').scan(quiet=True))

    def clear_live(self, local_only=False):
        if not self.LT:
            return
        if not local_only:
            self.cap.clear()
        self.cap_cur = 0
        self.LT.P = []
        self.LT.FD = C.Analysis()
        self.LT.T0 = 0
        self.LT.next_no = 1
        self.WS = {'init': 0, 'dev': set(), 'fit': set(), 'stat': {}, 'rb': 0}
        if self.ac is self.LT:
            self.P, self.FD, self.T0 = self.LT.P, self.LT.FD, 0
            self.pk.relist()
            self.pk.show_list(False)
            self.refresh_views()

    cap_cur = 0

    def poll(self):
        cap = self.cap
        with cap.lock:
            end = cap.base + len(cap.pk)
            since = min(max(self.cap_cur, cap.base), end)
            items = cap.pk[since - cap.base:since - cap.base + 20000]
            running = cap.running
            err = cap.err
        if end < self.cap_cur:
            self.clear_live(local_only=True)
        self.cap_cur = since + len(items)
        LT = self.LT
        if items:
            if not LT.P:
                LT.T0 = items[0][0]
            for ts, lt, d in items:
                LT.P.append(C.dis(ts, lt, d, LT.next_no))
                LT.next_no += 1
            if len(LT.P) > LIVE_MAX:
                del LT.P[:len(LT.P) - LIVE_MAX]
            self.live_dirty = True
            if self.ac is LT:
                self.P, self.T0 = LT.P, LT.T0
                self.pk.show_list(True)
                self.pk.relist()
                if self.live.follow.isChecked():
                    self.pk.follow()
        elif running and not LT.P and self.ac is LT:
            self.st.setText('Capturing… waiting for BACnet packets')
        s = self.live.cur()
        m = err or ''
        if not m and running and not LT.P and s and s.get('backend') == 'serial' and time.time() - getattr(LT, 'ts', 0) > 6:
            m = ('No MS/TP frames yet. Check the baud rate (press Detect), that the adapter wires are on the trunk '
                 '(swap A and B if nothing arrives) and that devices on the trunk are powered.')
        self.live.show_err(m)
        if err and self.ac is LT:
            self.st.setText(err)
        if self.live_dirty and not self.analysing:
            self.live_dirty = False
            self.analysing = True
            a = Analyser(LT, list(LT.P), LT.T0, self.local_net(), self.own_ips)
            a.done.connect(self._live_analysed)
            a.finished.connect(a.deleteLater)
            self._an = a
            a.start()
        if running != self.run:
            self.run = running
            self.update_tabs()
            if not running and not self._feed:
                self.poll_timer.stop()
        self.live.set_running(running, len(LT.P))
        if self._feed and not running:
            self.live.ls.setText(f'● MS/TP link (Discover) – {C.locale_int(len(LT.P))} frames')

    _feed = False

    def mstp_feed(self, on):
        """While Discover is joined to an MS/TP trunk, its frames appear in the Live capture tab."""
        self._feed = on
        if on:
            self.poll_timer.start()
            self.toast('Joined the MS/TP trunk – every frame the PC sends and receives is shown in the Live capture tab')
        elif not self.run:
            self.poll_timer.stop()
            self.poll()

    def _live_analysed(self, tab, F):
        self.analysing = False
        tab.FD = F
        if self.ac is tab:
            self.FD = F
            self.refresh_views()
        self.watch(F)

    def detect_baud(self):
        s = self.live.cur()
        if not s:
            return
        if self.run:
            return self.toast('Press Stop first')
        b = self.live.bdt
        b.setEnabled(False)
        b.setText('Listening…')
        self.live.show_err('')

        def work():
            self.cap.stop()
            d = BL.autobaud(str(s['id']))

            def done():
                b.setEnabled(True)
                b.setText('Detect')
                if d.get('error'):
                    self.live.show_err(d['error'])
                elif d.get('baud'):
                    self.live.bd.setCurrentText(str(d['baud']))
                    self.toast(f"Detected {d['baud']} baud")
                else:
                    self.live.show_err('No MS/TP traffic was heard at any common baud rate. Check the adapter wiring '
                                       '(try swapping A and B), that the adapter is connected to the trunk, and that '
                                       'devices on it are powered.')
            self.on_ui(done)
        threading.Thread(target=work, daemon=True).start()

    def save_live_raw(self):
        p, _ = QFileDialog.getSaveFileName(self, 'Save live capture', 'bacnet_capture.pcapng', 'Capture file (*.pcapng)')
        if not p:
            return
        try:
            with open(p, 'wb') as f:
                f.write(self.cap.pcapng())
            self.toast('Saved ' + p)
        except OSError as e:
            self.toast(f'Save failed: {e.strerror}')

    def send_msg(self, kind):
        s = self.live.cur()
        if s and s.get('backend') == 'serial':
            return self.toast('Sending is not available on an MS/TP serial connection – a sniffer has to stay silent on '
                              'the trunk. Send from a BACnet/IP connection instead.')
        nm = {'whois': 'Who-Is (all devices)', 'whoisrouter': 'Who-Is-Router-To-Network', 'netnum': 'What-Is-Network-Number'}[kind]
        d = BL.send_request({'kind': kind, 'from': self.live.sf.currentData() or '', 'to': self.live.st2.text().strip() or '255.255.255.255'})
        self.toast(f"Sent {nm}.{' Replies will appear in the Packets list.' if self.run else ' Press Start to see the replies.'}"
                   if d['ok'] else d['error'])

    # --------------------------------------------------------------- alerts --
    def _online_tick(self):
        if self.ac and self.ac.live and self.cur_view == 'o':
            self.view('o').refresh()

    def watch(self, F):
        if not self.LT or not self.run:
            return
        cfg = self.watch_cfg()
        live = time.time() - getattr(self.LT, 'ts', 0) > 15
        WS = self.WS

        def nm(d):
            lab = self.labels.d(d['id'])
            return f"device {d['id']}{' “' + lab + '”' if lab else ''} at {d['sa'] + ' via gateway' if d['sn'] is not None else d['key']}"
        for d in F.dv or []:
            k = f"{d['id']}|{d['key']}"
            if k not in WS['dev']:
                WS['dev'].add(k)
                if WS['init'] and live and cfg['dev']:
                    self.alert(f'New {nm(d)} appeared')
        for f in F:
            if f['s'] != 'NOTE' and f['t'] not in WS['fit']:
                WS['fit'].add(f['t'])
                if WS['init'] and live and cfg['prob']:
                    self.alert(f"New problem: {f['t']}")
        for r in C.online_rows(F, True):
            was = WS['stat'].get(r['k'])
            if r['st'] == 'sil' and was == 'on' and live and cfg['sil']:
                who = f"Device {', '.join(map(str, r['ids']))} ({r['k']})" if r['ids'] else r['k']
                self.alert(f"{who} has gone silent (not heard for {C.gap(r['si'])})")
            WS['stat'][r['k']] = r['st']
        if (F.rb or 0) > WS['rb']:
            if WS['init'] and live and cfg['busy']:
                self.alert('A router reports it is busy (Router-Busy)')
            WS['rb'] = F.rb
        WS['init'] = 1

    def watch_cfg(self):
        c = {'dev': 1, 'sil': 1, 'prob': 1, 'busy': 1, 'snd': 0, 'ntf': 0}
        c.update(self.store.get('bi_watch') or {})
        return c

    def alert(self, m):
        self.ALR.append({'t': time.time(), 'm': m})
        del self.ALR[:-300]
        self.toast(m)
        cfg = self.watch_cfg()
        if cfg['snd']:
            QApplication.beep()
        if cfg['ntf']:
            if self.tray is None:
                self.tray = QSystemTrayIcon(self.windowIcon(), self)
                self.tray.show()
            self.tray.showMessage(APP_NAME, m, QSystemTrayIcon.MessageIcon.Information, 6000)
        if self.cur_view == 'o':
            self.view('o').refresh()

    # ------------------------------------------------------------ discover --
    def _ex_notify(self):
        """Called from worker threads: redraw the Discover view soon (at most 4x a second)."""
        if self._ex_pending:
            return
        self._ex_pending = True

        def go():
            self._ex_pending = False
            if 'x' in self.views:
                self.views['x'].ex_changed()
        self.on_ui(lambda: QTimer.singleShot(250, go))

    def pk_device(self, r):
        dv = self.FD.dv or []
        if r.rq is not None:
            if r.dn is not None:
                import re
                m = re.search(r'network \d+, (.+)$', str(r.dk or ''))
                return next((d for d in dv if d['sn'] == r.dn and m and d['sa'] == m.group(1)), None)
            return next((d for d in dv if d['key'] == r.dk), None)
        if r.sn is not None:
            return next((d for d in dv if d['sn'] == r.sn and d['sa'] == r.sa), None)
        return (next((d for d in dv if d['key'] == r.key and d['sn'] is None), None) or
                next((d for d in dv if d['key'] == r.key), None))

    @staticmethod
    def pk_obj(r):
        import re
        for m in re.finditer(r'\b([a-z][a-z-]*) (\d+)\b', r.info):
            if m.group(1) in C.OT:
                t = C.OT.index(m.group(1))
                return {'ty': t, 'inst': int(m.group(2)), 'o': t * 4194304 + int(m.group(2))}
        return None

    def open_device_from_packet(self, d):
        if not d:
            return
        dv = self.view('x')
        k = next((x['key'] for x in dv.sd_devs() if x['cap'] is d), None)
        if k:
            dv.open_device(k)

    def read_now(self, d, ob):
        from bi_discover import read_now
        read_now(self, d, ob)

    # ---------------------------------------------------------- write access --
    def wb_draw(self):
        ex = self.explorer
        on = ex.armed()
        if on:
            s = max(0, int(round(ex.arm_until - time.time())))
            self.wb_l.setText(f'<b>⚠ Write access is ON</b> – changes you send go to real equipment. '
                              f'Switches off in <b>{s // 60}:{s % 60:02d}</b>.')
        if on != self.wb.isVisible():
            self.wb.setVisible(on)
            if not on:
                ex.arm_until = 0
            if 'x' in self.views:
                self.views['x'].ex_changed()

    def disarm(self):
        try:
            self.explorer.arm(0)
        except Exception:
            pass
        self.explorer.arm_until = 0
        self.wb_draw()
        self.toast('Write access is off')

    def arm_dlg(self, then=None):
        from bi_discover import arm_dialog
        if arm_dialog(self):
            self.wb_draw()
            if then:
                then()

    # -------------------------------------------------------------- labels --
    def edit_label(self, kind, n):
        cur = self.store.label(kind, n)
        d = QDialog(self)
        d.setWindowTitle(f"Name for {'device ID' if kind == 'd' else 'network'} {n}")
        v = QVBoxLayout(d)
        v.addWidget(label('Names are saved on this computer and shown on every tab and in reports.', muted=True))
        ed = QLineEdit(cur)
        ed.setPlaceholderText('e.g. Rooftop unit 3' if kind == 'd' else 'e.g. Second floor trunk')
        v.addWidget(ed)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        rm = bb.addButton('Remove name', QDialogButtonBox.ButtonRole.DestructiveRole)
        v.addWidget(bb)
        bb.accepted.connect(d.accept)
        bb.rejected.connect(d.reject)
        rm.clicked.connect(lambda: d.done(2))
        d.resize(380, 140)
        res = d.exec()
        if res == 2:
            self.store.set_label(kind, n, '')
        elif res == QDialog.DialogCode.Accepted:
            self.store.set_label(kind, n, ed.text())
        else:
            return
        self.labels_changed()

    def labels_changed(self):
        self.pk.model.layoutChanged.emit()
        if self.pk.sel:
            self.pk.show_packet(self.pk.sel)
        self.refresh_views()

    def labels_dlg(self):
        from bi_views import LabelsDialog
        LabelsDialog(self).exec()
        self.labels_changed()

    # ---------------------------------------------------------------- saving --
    def formats(self, v):
        """[(key, filter label, extension, maker)] for view v; maker returns str or bytes."""
        if v == 'p':
            fm = [('html', 'Web page – exactly as shown (*.html)', 'html', self.html_packets),
                  ('pcapng', 'Capture file – only the packets that match the filter (*.pcapng)', 'pcapng', lambda: C.pcapng(self.pk.V)),
                  ('csv', 'Spreadsheet – the rows shown (*.csv)', 'csv', lambda: '﻿' + self.csv_packets())]
        else:
            w = self.view(v)
            fm = w.formats() if hasattr(w, 'formats') else []
        # every spreadsheet export can also be saved as an Excel workbook
        out = []
        for f in fm:
            out.append(f)
            if f[2] == 'csv':
                lab = f[1].replace('Spreadsheet', 'Excel workbook').replace('(*.csv)', '(*.xlsx)')
                sheet = 'Site inventory' if f[0] == 'inventory' else VTITLE.get(v, 'Sheet1')
                out.append(('xlsx' if f[0] == 'csv' else f[0] + '.xlsx', lab, 'xlsx',
                            lambda mk=f[3], sheet=sheet: csv_to_xlsx(mk(), sheet)))
        return out

    def base_name(self):
        import re
        return re.sub(r'\.(pcapng|pcap|cap)$', '', (self.ac.n if self.ac else 'capture') or 'capture', flags=re.I)

    def def_name(self, v, ext):
        if v == 'inv':
            return f"site-inventory-{time.strftime('%Y-%m-%d')}.{ext}"
        return f"{self.base_name()}-{VNAME.get(v, v)}{'-filtered' if v == 'p' and self.qbox.text().strip() else ''}.{ext}"

    def do_save(self, save_as):
        v = self.cur_view
        if not self.ac and v != 'x':
            return self.toast('Open a capture first')
        fm = self.formats(v)
        if not fm:
            return self.toast('There is nothing to save on this tab')
        holder = self.ac.sv if self.ac else self.store_sv
        o = holder.get(v)
        if not save_as and o and o.get('path'):
            f = next((x for x in fm if x[0] == o['f']), None)
            if f:
                return self.write_out(f, o['path'])
        self.save_as(v, fm, holder)

    store_sv = {}

    def save_as(self, v, fm, holder, title=None):
        o = holder.get(v) or {}
        filters = ';;'.join(x[1] for x in fm)
        first = next((x for x in fm if x[0] == o.get('f')), fm[0])
        start = o.get('path') or os.path.join(self.store.get('bi_sdir') or '', self.def_name(v, first[2]))
        p, chosen = QFileDialog.getSaveFileName(self, title or f'Save As – {VTITLE.get(v, v)}', start, filters, first[1])
        if not p:
            return
        f = next((x for x in fm if x[1] == chosen), first)
        if not p.lower().endswith('.' + f[2]):
            p += '.' + f[2]
        self.store.set('bi_sdir', os.path.dirname(p))
        if self.write_out(f, p):
            holder[v] = {'f': f[0], 'path': p}

    def write_out(self, f, path):
        if f[0] == 'pcapng' and self.cur_view == 'p' and not self.pk.V:
            self.toast('No packets match the current filter, so there is nothing to save')
            return False
        try:
            data = f[3]()
        except Exception as e:                      # show, don't crash
            self.toast(f'Could not build the file: {e}')
            return False
        try:
            with open(path, 'wb') as fh:
                fh.write(data if isinstance(data, (bytes, bytearray)) else data.encode('utf-8'))
        except OSError as e:
            self.toast(f'Save failed: {e.strerror}')
            return False
        self.toast('Saved ' + path)
        return True

    def html_packets(self):
        rows, cls = [], []
        for r in self.pk.V:
            rows.append([r.no, C.tofixed(r.t - self.T0, 4), esc(f'net {r.sn} / {r.sa}' if r.sn is not None else r.src),
                         esc(r.dst), esc(r.o) if r.sn is not None else '', r.proto, r.len, esc(r.info),
                         ('★ ' if r.bm else '') + esc(r.note or '')])
            cls.append('bad' if r.bad else 'm' if r.proto == 'MS/TP' else 'b')
        body = (f'<h3>{esc(self.ac.n)} – packets</h3><p class="mu">Display filter: <code>{esc(self.qbox.text().strip() or "(none)")}</code>'
                f' · {len(self.pk.V)} of {len(self.P)} packets · saved {stamp()}</p>' +
                html_table(['No.', 'Time', 'Source', 'Destination', 'Gateway', 'Protocol', 'Len', 'Info', 'Note'], rows, cls))
        return doc('Packets – ' + self.ac.n, body)

    def csv_packets(self):
        rows = [[r.no, C.tofixed(r.t - self.T0, 6), f'net {r.sn} / {r.sa}' if r.sn is not None else r.src, r.dst,
                 r.o if r.sn is not None else '', r.proto, r.len, r.info, r.exp or '', 'yes' if r.bm else '', r.note or '']
                for r in self.pk.V]
        return csv_text('No.,Time,Source,Destination,Gateway,Protocol,Length,Info,Meaning,Bookmark,Note', rows)

    def do_report(self):
        if not self.ac:
            return self.toast('Open a capture first')
        import bi_views
        fm = [('html', 'Web page – a plain-English report you can open, print or email (*.html)', 'html', lambda: bi_views.html_report(self)),
              ('txt', 'Text file – the same report as plain text (*.txt)', 'txt', lambda: bi_views.txt_report(self))]
        self.save_as('r', fm, self.ac.sv, 'Export report')

    # -------------------------------------------------------------- session --
    def save_session(self):
        if getattr(self, '_restoring', False):
            return
        tabs = [{'path': t.path, 'q': (self.qbox.text() if t is self.ac else t.q)} for t in self.TB if t.path]
        BL.save_session({'tabs': tabs, 'active': self.ac.path if self.ac and self.ac.path else None})

    def restore_session(self):
        self._restoring = True
        try:
            s = BL.load_session()
            first = getattr(self, 'open_first', None)
            for t in s.get('tabs') or []:
                p = t.get('path')
                if p and os.path.isfile(p):
                    self.open_path(p, t.get('q') or '', activate=(p == s.get('active') and not first))
            if first:
                self.open_path(first)
        finally:
            self._restoring = False
        self.save_session()

    def restore_geometry(self):
        s = BL.load_session()
        g = self.store.get('bi_geom')
        if g:
            self.restoreGeometry(QByteArray.fromBase64(g.encode()))
        else:
            self.resize(min(7680, max(900, int(s.get('w') or 1300))), min(4320, max(600, int(s.get('h') or 820))))

    def closeEvent(self, e):
        self.store.set('bi_geom', bytes(self.saveGeometry().toBase64()).decode())
        self.save_session()
        try:
            self.cap.stop()
        except Exception:
            pass
        self.explorer.stop = True
        self.explorer.on = False
        if self.explorer.link:
            self.explorer.link.stop()          # leave the MS/TP trunk and free the COM port
        self.store.flush()
        e.accept()

    # ------------------------------------------------------------------ misc --
    def toast(self, m, action=None, action_text='Undo'):
        """A short message at the bottom of the window (with an optional action such as Undo)."""
        self.toaster.show_msg(m, action, action_text)

    def set_galaxy(self, on):
        self.store.set('bi_galaxy', bool(on))
        U.set_galaxy_cursor(on)
        self.toast('Galactic cursor ' + ('on' if on else 'off'))

    def set_theme(self, v):
        self.store.set('bi_theme', v)
        apply_theme(v)
        self.theme_soon()
        self.toast('Theme: ' + (v or 'automatic – follows Windows'))

    def theme_soon(self):
        if not getattr(self, '_theme_pending', False):
            self._theme_pending = True
            QTimer.singleShot(0, self.theme_changed)

    def theme_changed(self):
        """Light / dark changed (from the View menu or from Windows): repaint everything in the new colours."""
        self._theme_pending = False
        app = QApplication.instance()
        app.setStyle(app.style().name())          # re-create the style so checkboxes etc. repaint in the new colours
        U.apply_palette(app)
        self.style_chrome()
        U.style_titlebar(self)
        self.tipper.update()
        self.pk.model.retheme()
        self.pk.model.layoutChanged.emit()
        for w in self.views.values():
            w._stale = True
        self.refresh_views()
        self.update_tabs()
        if 'x' in self.views:
            self.views['x'].retheme()

    def _busy_tick(self):
        """Drive the thin progress line under the toolbar."""
        t = self.ac
        on, pct = False, None
        if t and t.busy:
            on = True
            import re
            m = re.search(r'(\d+)%', t.busy)
            pct = int(m.group(1)) if m else None
        elif any(ld.isRunning() for ld in self.loaders) or getattr(self.pk, '_waiting', False) or self.explorer.busy:
            on = True
        self.prog.set_state(on, pct)

    # -------------------------------------------------------- command palette --
    def command_palette(self, from_button=False):
        """Ctrl+K: jump to anything by typing."""
        import bi_explore as E
        items = []
        keys = {'p': 'Ctrl+1', 'f': 'Ctrl+2', 'd': 'Ctrl+3', 'o': 'Ctrl+4', 'x': 'Ctrl+5', 'w': 'Ctrl+6', 't': 'Ctrl+7',
                'm': 'Ctrl+8', 'g': 'Ctrl+9'}
        for k, t in VTITLE.items():
            items.append((k, t, keys.get(k, ''), lambda k=k: self.goto(k), 'View'))
        for t in self.TB:
            items.append(('wave' if t.live else 'tab', t.n, 'capture tab',
                          lambda t=t: (self.switch_tab(t), self.goto(self.last_capture_view)), 'Tab'))
        for m in self.menuBar().actions():
            menu = m.menu()
            if menu is None:
                continue
            mt = m.text().replace('&', '')
            for a in menu.actions():
                if a.isSeparator() or a.menu() is not None or not a.text():
                    continue
                en = getattr(a, '_en', None)
                if en is not None and not en():
                    continue
                sc = a.shortcut().toString()
                items.append(('cmd', a.text().replace('&', '').rstrip('…'), mt + (f' · {sc}' if sc else ''), a.trigger, 'Command'))
        dv = self.view('x')
        for d in dv.sd_devs():
            items.append(('d', 'Device ' + dv.dev_label(d), d['ip'] or dv.grp_name(dv.grp(d)),
                          lambda key=d['key']: dv.open_device(key), 'Device'))
        for e in list(self.explorer.devs.values()):
            for o in e.get('objs') or []:
                nm = o['name'] or f"{E.sd_ty(o['ty'])} {o['inst']}"
                items.append(('point', nm, f"{E.sd_ty(o['ty'])} {o['inst']} · device {e['id']}",
                              lambda k=e['key'], o=o['o']: self.open_point(k, o), 'Point'))
        for f in self.FD:
            items.append(('f', f['t'], f['s'].lower(), lambda: self.goto('f'), 'Finding'))
        U.CommandPalette(self, items).exec()
        if from_button:
            self.tip('search', self.find_b)

    def open_point(self, k, o):
        dv = self.view('x')
        dv.live = True
        self.goto('x')
        dv.go_node({'k': k, 'o': o})

    # ---------------------------------------------------------- about / news --
    def whats_new(self):
        notes = ''
        p = res_path('release_notes.txt')
        if os.path.isfile(p):
            with open(p, encoding='utf-8', errors='replace') as f:
                notes = f.read()
        U.whats_new_dialog(self, BL.APP_VERSION, notes, self.tour)

    # ---------------------------------------------------------- tips & tour --
    first_run_ui = False                   # set by main(): the tour and What's new only open in the real app

    TIPS = {
        'views': ('Jump between views', 'Every view in the sidebar has a keyboard shortcut.', 'Ctrl+1 … Ctrl+9'),
        'discover': ('Switch from the keyboard', 'Ctrl+5 opens Discover, and Ctrl+1 takes you back to the packets.',
                     'Ctrl+5 or Ctrl+1'),
        'search': ('Search from anywhere', 'Press Ctrl+K in any view to jump straight to a device, a point, a view or a '
                   'menu command.', 'Ctrl+K'),
        'back': ('Going back', 'Alt+Left, or the Back button on your mouse, does the same.', 'Alt+Left'),
        'open': ('Drag and drop works too', 'Drag .pcap or .pcapng files onto the window to open them. Each capture '
                 'gets its own tab.', 'Ctrl+O'),
        'filter': ('Filters without typing', 'Right-click any packet and choose Apply as Filter. Press F1 to see every '
                   'filter you can type.', 'F1'),
        'packet': ('Filter by any cell', 'Double-click a cell in the packet list to show only the packets with that '
                   'value. Right-click a packet for more.', ''),
        'find': ('Step through the matches', 'Enter jumps to the next match and Shift+Enter to the previous one. Esc '
                 'clears the search.', 'Enter or Shift+Enter'),
        'bookmark': ('Bookmark faster', 'Ctrl+B bookmarks the selected packet. Edit > Show bookmarked packets lists '
                     'them all.', 'Ctrl+B'),
        'live': ('Reading while it captures?', 'Untick Follow newest so the list stops scrolling while you read.', ''),
        'insp': ('Point details', 'Click another point in the list to see its details here. Esc closes this panel.', 'Esc'),
    }

    def tip(self, key, anchor=None, delay=400):
        """Show a one-time tip next to what the user just used (at most one every 30 seconds)."""
        cfg = self.store.get('bi_tips') or {}
        if cfg.get('off') or key in (cfg.get('seen') or []) or getattr(self, '_touring', False) or key not in self.TIPS:
            return
        if time.time() - getattr(self, '_tip_t', 0) < 30 or self.tipper.isVisible():
            return
        self._tip_t = time.time()
        self.store.set('bi_tips', {**cfg, 'seen': (cfg.get('seen') or []) + [key]})
        t, x, k = self.TIPS[key]
        QTimer.singleShot(delay, lambda: self.isVisible() and not getattr(self, '_touring', False)
                          and self.tipper.show_tip(anchor, t, x, k))

    def tips_off(self):
        self.set_tips(False)
        self.toast('Tips are off. You can turn them back on in Help > Show tips.')

    def set_tips(self, on):
        cfg = self.store.get('bi_tips') or {}
        self.store.set('bi_tips', {**cfg, 'off': not on})
        if not on:
            self.tipper.close_tip()

    def reset_tips(self):
        self.store.set('bi_tips', {'off': False, 'seen': []})
        self._tip_t = 0
        self.toast('Tips will show again as you use the app')

    def tour(self):
        """A guided tour of the main parts of the window."""
        if getattr(self, '_touring', False):
            return
        self._touring = True
        self.tipper.close_tip()
        if self.cur_view == 'x':
            self.goto(self.last_capture_view)
        if self.cur_view != 'p':
            self.goto('p')
        hm = self.help_menu.menuAction()

        def help_rect():
            g = self.menuBar().actionGeometry(hm)
            return QRect(self.menuBar().mapTo(self, g.topLeft()), g.size())
        steps = [
            (None, 'Welcome to BACnet Inspector',
             'See what is happening on a BACnet network: open a capture to find problems, or use Discover to find '
             'devices and read their points live. This quick tour shows you around – it takes about a minute.', ''),
            (self.seg, 'Two ways to work',
             'Capture is for looking at recorded or live traffic. Discover finds the devices on the network, or on an '
             'MS/TP trunk through a USB RS-485 adapter, and reads their points.', 'Ctrl+5'),
            (self.tabrow, 'Captures open in tabs',
             'Open a .pcap or .pcapng with Open capture or the + button, or drag files onto the window. The Live '
             'capture tab records traffic from a network adapter or an RS-485 adapter.', 'Ctrl+O'),
            (self.sidew, 'Look at a capture different ways',
             'Findings explains problems in plain English. Devices, Network map, Traffic and the rest each answer one '
             'question about the capture.', 'Ctrl+1 … Ctrl+9'),
            (self.qbox, 'Filter the packets',
             'Type a Wireshark-style filter such as device == 1001, or right-click any packet and choose Apply as '
             'Filter. F1 lists every filter.', 'F1'),
            (self.pk.top, 'Packets and their details',
             'Click a packet to decode it underneath. Double-click a cell to filter by it. IP addresses, networks and '
             'device IDs are highlighted so they are easy to spot.', 'Ctrl+F'),
            (self.find_b, 'Find anything',
             'Search jumps to any view, device, point, capture tab or menu command – just start typing.', 'Ctrl+K'),
            (help_rect, 'Help is always here',
             'The user manual explains every part of the app – press F1 on any page to open it at that page. The '
             'tour and the tips settings are here too.', 'F1'),
            (None, 'You’re all set',
             'Open a capture or start the live capture to begin. You can take this tour again any time from Help.', ''),
        ]
        U.Tour(self, steps, self._tour_done)

    def _tour_done(self):
        self._touring = False
        self.store.set('bi_toured', BL.APP_VERSION)
        self._tip_t = time.time()             # give it a moment before the first tip

    def about(self):
        page = None
        try:
            with open(res_path('update_url.txt'), encoding='utf-8') as f:
                u = f.read().strip()
            if '/releases/' in u:
                page = u.split('/releases/')[0] + '/releases'
        except OSError:
            pass
        U.about_dialog(self, BL.APP_VERSION, lambda: self.upd_check(True), self.whats_new, res_path('bacnet_inspector.ico'), page)

    def reset_panes(self):
        self.pk._auto_cols = True
        self.pk.fit_columns()
        self.pk.split.setSizes([600, 400])
        self.pk.bot.setSizes([600, 420])
        self.store.set('bi_split', None)

    def manual(self, cid=None):
        """The user manual; without a chapter it opens at the page for what is on screen."""
        import bi_manual
        if cid is None:
            cid = 'filter' if self.qbox.hasFocus() else bi_manual.FOR_VIEW.get(self.cur_view, 'welcome')
            if self.cur_view == 'x' and self.explorer.mode == 'mstp':
                cid = 'dmstp'
            elif self.cur_view == 'p' and self.ac and self.ac.live:
                cid = 'live'
        w = getattr(self, '_manual', None)
        if w is None:
            w = self._manual = bi_manual.ManualWindow(self)
        w.tb.document().setDefaultStyleSheet(bi_manual.css())
        w.open_at(cid)

    def report_problem(self):
        """Help > Report a problem: what went wrong recently, ready to copy and send."""
        import bi_log
        d = QDialog(self)
        d.setWindowTitle('Report a problem')
        d.resize(760, 540)
        v = QVBoxLayout(d)
        v.setContentsMargins(22, 18, 22, 16)
        n = bi_log.error_count()
        v.addWidget(label('Report a problem', bold=True, size=15))
        v.addWidget(label(('The app has logged ' + (f'{n} unexpected error' + ('s' if n != 1 else '')) if n else
                           'No unexpected errors have been logged.') +
                          ' Copy the details below and send them with a short note of what you were doing.', muted=True))
        txt = QPlainTextEdit()
        txt.setReadOnly(True)
        txt.setFont(QFont('Cascadia Mono', 9))
        txt.setPlainText(bi_log.system_info() + '\n\n' + (bi_log.recent() or '(the log is empty)'))
        txt.moveCursor(txt.textCursor().MoveOperation.End)
        v.addWidget(txt, 1)
        h = QHBoxLayout()
        cp = QPushButton('Copy details')
        cp.clicked.connect(lambda: (QApplication.clipboard().setText(txt.toPlainText()), self.toast('Details copied')))
        of = QPushButton('Open log folder')
        of.clicked.connect(lambda: os.startfile(bi_log.log_dir()))
        cl = QPushButton('Close')
        cl.setDefault(True)
        cl.clicked.connect(d.accept)
        for b in (cp, of):
            h.addWidget(b)
        h.addStretch(1)
        h.addWidget(cl)
        v.addLayout(h)
        d.exec()

    def help(self, w):
        if w in ('start', 'filter', 'bms', 'keys'):
            return self.manual({'start': 'quick', 'filter': 'filter', 'bms': 'discover', 'keys': 'keys'}[w])
        from bi_views import HELP
        t, body = HELP[w]
        body = body.replace('{ver}', BL.APP_VERSION).replace('{author}', AUTHOR)
        d = QDialog(self)
        d.setWindowTitle(t)
        v = QVBoxLayout(d)
        tb = QTextBrowser()
        tb.setOpenExternalLinks(True)
        tb.setHtml(f'<h2>{t}</h2>{body}')
        v.addWidget(tb)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(d.reject)
        v.addWidget(bb)
        d.resize(720, 560)
        d.exec()

    # -------------------------------------------------------------- updates --
    def upd_check(self, manual):
        def work():
            try:
                r = BL.update_check()
            except Exception:
                r = {'ok': False, 'error': 'Could not check for updates.', 'configured': True, 'current': BL.APP_VERSION}
            self.on_ui(lambda: self._upd_got(r, manual))
        threading.Thread(target=work, daemon=True).start()

    def _upd_got(self, r, manual):
        self.upd = r
        self.store.set('bi_updlast', str(time.time()))
        self.upd_bar()
        if manual:
            self.upd_dlg()

    def upd_bar(self):
        r = self.upd
        if not r or not r.get('newer') or self.store.get('bi_updlater') == r.get('latest'):
            self.ub.hide()
            return
        self.ub_l.setText(f"Version {r['latest']} is available (you have {r['current']}).")
        self.ub_go.setVisible(bool(r.get('can_install')))
        self.ub.show()

    def upd_later(self):
        if self.upd:
            self.store.set('bi_updlater', self.upd.get('latest'))
        self.ub.hide()

    def upd_dlg(self):
        r = self.upd or {}
        d = QDialog(self)
        d.setWindowTitle('Check for updates')
        v = QVBoxLayout(d)
        if not r.get('configured'):
            v.addWidget(label('Updates are not set up in this copy of BACnet Inspector.'))
            v.addWidget(label(f"You have version {r.get('current') or '?'}.", muted=True))
        elif not r.get('ok'):
            v.addWidget(label(r.get('error') or 'Could not check for updates.'))
            v.addWidget(label(f"You have version {r.get('current')}. Check your internet connection and try again.", muted=True))
        elif not r.get('newer'):
            v.addWidget(label(f"You have the latest version ({r.get('current')}).", bold=True))
        else:
            v.addWidget(label(f"Version {r['latest']} is available{' (' + r['date'] + ')' if r.get('date') else ''}. You have {r['current']}.", bold=True))
            if r.get('notes'):
                n = QPlainTextEdit(r['notes'])
                n.setReadOnly(True)
                n.setMaximumHeight(200)
                v.addWidget(n)
            v.addWidget(label('Your captures, labels and settings are kept. The app closes, updates and reopens by itself.'
                              + ('' if r.get('can_install') else ' Automatic install only works in the installed Windows app.'), muted=True))
        auto = QCheckBox('Check automatically')
        auto.setChecked(self.store.get('bi_updauto', '1') != '0')
        auto.toggled.connect(lambda on: self.store.set('bi_updauto', '1' if on else '0'))
        bb = QDialogButtonBox()
        if r.get('ok') and r.get('newer') and r.get('can_install'):
            g = bb.addButton('Install and restart', QDialogButtonBox.ButtonRole.AcceptRole)
            g.clicked.connect(lambda: (d.accept(), self.upd_install()))
        if r.get('ok') and r.get('newer') and r.get('page'):
            pg = bb.addButton('Download page', QDialogButtonBox.ButtonRole.ActionRole)
            from PySide6.QtGui import QDesktopServices
            from PySide6.QtCore import QUrl
            pg.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(r['page'])))
        bb.addButton(QDialogButtonBox.StandardButton.Close).clicked.connect(d.reject)
        row = QHBoxLayout()
        row.addWidget(auto)
        row.addStretch(1)
        row.addWidget(bb)
        v.addLayout(row)
        d.resize(520, 200)
        d.exec()

    def upd_install(self):
        d = QMessageBox(self)
        d.setWindowTitle('Updating…')
        d.setText('Downloading and checking the new version. The app will close and reopen by itself – this takes about a minute.')
        d.setStandardButtons(QMessageBox.StandardButton.NoButton)
        d.show()

        def work():
            r = BL.update_install()

            def done():
                d.hide()
                if r and r.get('ok') is False:
                    QMessageBox.warning(self, 'Update failed', f"{r.get('error') or 'Something went wrong.'}\n\n"
                                        'Nothing was changed. You can keep using this version.')
                elif r and r.get('ok'):
                    self.store.flush()
                    self.save_session()
            self.on_ui(done)
        threading.Thread(target=work, daemon=True).start()


# ================================================================== start --
def apply_theme(v):
    hints = QGuiApplication.styleHints()
    try:
        hints.setColorScheme({'light': Qt.ColorScheme.Light, 'dark': Qt.ColorScheme.Dark}.get(v, Qt.ColorScheme.Unknown))
    except AttributeError:
        pass


SERVER = 'BACnetInspectorNative-' + (os.environ.get('USERNAME') or 'user')


def hand_off(path):
    """If BACnet Inspector is already open, give it the file and return True."""
    s = QLocalSocket()
    s.connectToServer(SERVER)
    if not s.waitForConnected(400):
        return False
    s.write(json.dumps({'path': os.path.abspath(path) if path else None}).encode() + b'\n')
    s.waitForBytesWritten(1000)
    s.disconnectFromServer()
    return True


def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(BL.APP_VERSION)
    from PySide6.QtWidgets import QStyleFactory
    if 'windows11' in [k.lower() for k in QStyleFactory.keys()]:
        app.setStyle('windows11')
    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    path = args[0] if args and os.path.isfile(args[0]) else None
    if '--new-instance' not in sys.argv and hand_off(path):
        return 0
    import bi_log
    bi_log.install()
    store = Store()
    apply_theme(store.get('bi_theme') or '')
    U.apply_fonts(app)
    U.apply_palette(app)
    MainWindow.first_run_ui = True
    w = MainWindow(store)
    try:
        QGuiApplication.styleHints().colorSchemeChanged.connect(lambda *_: w.theme_soon())
    except AttributeError:
        pass
    w.open_first = path
    U.set_galaxy_cursor(store.get('bi_galaxy', True))
    bi_log.on_error = lambda s: w.bridge.call.emit(
        lambda: w.toast('Something went wrong – it was saved to the problem log', w.report_problem, 'Details'))
    srv = QLocalServer()
    QLocalServer.removeServer(SERVER)
    if srv.listen(SERVER):
        def incoming():
            c = srv.nextPendingConnection()

            def read():
                for line in bytes(c.readAll()).decode(errors='replace').splitlines():
                    try:
                        p = json.loads(line).get('path')
                    except ValueError:
                        continue
                    if p and os.path.isfile(p):
                        w.open_path(p)
                w.setWindowState((w.windowState() & ~Qt.WindowState.WindowMinimized) | Qt.WindowState.WindowActive)
                w.raise_()
                w.activateWindow()
            c.readyRead.connect(read)
        srv.newConnection.connect(incoming)
    w.show()
    return app.exec()


if __name__ == '__main__':
    sys.exit(main())

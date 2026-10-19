"""
bi_discover.py - the Discover view: networks > devices > categories > points, read from the live
network, with the guarded write dialog. The network work itself is in bi_explore.Explorer.
"""
from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
                               QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton, QSplitter,
                               QTabWidget, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

import bi_core as C
import bi_explore as E
from bi_common import Page, Pill, Table, colors, csv_text, doc, esc, heading, html_table, label, stamp

K_ROLE = Qt.ItemDataRole.UserRole


def ago(t):
    s = round(time.time() - t)
    return ('just now' if s < 60 else f'{round(s / 60)} min ago' if s < 3600 else f'{round(s / 3600)} h ago' if s < 86400
            else time.strftime('%Y-%m-%d', time.localtime(t)))


class DiscoverView(QWidget):
    key, title = 'x', 'Discover'

    def __init__(self, win):
        super().__init__()
        self.win = win
        self.ex = win.explorer
        self._stale = True
        self.node = None            # {'k': device key, 't': object type, 'o': object id}
        self.open = set()           # expanded devices / categories
        self.gopen = set()          # expanded network groups
        self.vis = set()
        self.live = False
        self.pk = None              # device picker {'src','sel','run','stop'}
        self.tq = ''
        self.ptab = 0
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QFrame()
        bar.setObjectName('dxbar')
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(18, 10, 18, 10)
        t = QVBoxLayout()
        t.setSpacing(0)
        t.addWidget(label('Discover', bold=True, size=14, wrap=False))
        t.addWidget(label('Find devices and read their points', muted=True, wrap=False))
        bl.addLayout(t)
        self.armpill = Pill('WRITE ACCESS ON', 'SERIOUS')
        bl.addWidget(self.armpill)
        bl.addStretch(1)
        self.b_new = QPushButton('New discover')
        self.b_scan = QPushButton('Scan network')
        self.b_opts = QPushButton('Options…')
        self.b_arm = QPushButton('Enable write access…')
        self.b_arm.setToolTip('Allow Write Property for a limited time')
        for b in (self.b_new, self.b_scan, self.b_opts, self.b_arm):
            bl.addWidget(b)
        v.addWidget(bar)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        v.addWidget(line)
        self.split = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(10, 8, 6, 6)
        self.status = label('', muted=True)
        ll.addWidget(self.status)
        self.q = QLineEdit()
        self.q.setPlaceholderText('Search devices and points')
        self.q.setClearButtonEnabled(True)
        ll.addWidget(self.q)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        ll.addWidget(self.tree, 1)
        self.leg = label('● answered scan    ● in capture    ○ not seen now', muted=True)
        ll.addWidget(self.leg)
        self.left = left
        self.split.addWidget(left)
        rightw = QWidget()
        rv = QVBoxLayout(rightw)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(0)
        nav = QWidget()                          # Back / Discover home / where you are
        nl = QHBoxLayout(nav)
        nl.setContentsMargins(14, 8, 14, 6)
        nl.setSpacing(6)
        self.b_back = QToolButton(text='‹  Back')
        self.b_back.setToolTip('Back to what you were looking at before (Alt+←, or the mouse Back button)')
        self.b_home = QToolButton(text='⌂  Discover home')
        self.b_home.setToolTip('Back to the Discover start page')
        nl.addWidget(self.b_back)
        nl.addWidget(self.b_home)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        nl.addWidget(sep)
        self.crumbw = QWidget()
        self.crumbs = QHBoxLayout(self.crumbw)
        self.crumbs.setContentsMargins(4, 0, 0, 0)
        self.crumbs.setSpacing(2)
        nl.addWidget(self.crumbw, 1)
        rv.addWidget(nav)
        ln = QFrame()
        ln.setFrameShape(QFrame.Shape.HLine)
        rv.addWidget(ln)
        self.right = Page(1100)
        rv.addWidget(self.right, 1)
        self.split.addWidget(rightw)
        self.hist = []                           # earlier places in Discover, for Back
        self.b_back.clicked.connect(self.back)
        self.b_home.clicked.connect(self.home)
        self.split.setSizes([320, 900])
        self.split.setStretchFactor(1, 1)
        v.addWidget(self.split, 1)
        self.b_new.clicked.connect(self.new_discover)
        self.b_scan.clicked.connect(lambda: self.scan())
        self.b_opts.clicked.connect(self.options)
        self.b_arm.clicked.connect(lambda: win.disarm() if self.ex.armed() else win.arm_dlg())
        self.q.textChanged.connect(self._search)
        self.tree.currentItemChanged.connect(self._tree_pick)
        self.tree.itemExpanded.connect(lambda it: self._exp(it, True))
        self.tree.itemCollapsed.connect(lambda it: self._exp(it, False))
        self.tree.itemChanged.connect(self._checked)
        self.tree.customContextMenuRequested.connect(self._menu)
        self._building = False

    # ----------------------------------------------------------------- data --
    def sd_devs(self):
        """Devices from the capture and from discovery, in one list (the original's sdDevs)."""
        F = self.win.FD
        out, used = [], set()
        ex = list(self.ex.devs.values())
        nmv = F.nm or {}
        lab = self.win.labels
        for d in F.dv or []:
            ip = E.ip_of(d['key'])
            e = next((x for x in ex if x['id'] == d['id'] and (x['ip'] == ip or (x.get('sn') is not None and x.get('sn') == d['sn']))), None)
            if e:
                used.add(e['key'])
            m = nmv.get(d['id']) or {}
            out.append({'id': d['id'], 'net': d['sn'], 'ip': ip, 'cap': d, 'ex': e,
                        'name': lab.d(d['id']) or (e and e.get('name')) or m.get('name', ''),
                        'vendor': (e and e.get('vendor')) or m.get('vendor') or C.VN.get(d['v'], ''),
                        'model': (e and e.get('model')) or m.get('model', ''),
                        'key': e['key'] if e else f"c|{d['id']}|{d['key']}", 'filt': f'host == "{d["key"]}"'})
        for e in ex:
            if e['key'] in used:
                continue
            out.append({'id': e['id'], 'net': e.get('sn'), 'ip': e['ip'], 'cap': None, 'ex': e,
                        'name': lab.d(e['id']) or e.get('name') or '', 'vendor': e.get('vendor') or C.VN.get(e.get('vn'), ''),
                        'model': e.get('model') or '', 'key': e['key'],
                        'filt': (f'net == {e["sn"]} && gateway == "{e["ip"]}:{e["port"]}"' if e.get('sn') is not None
                                 else f'host == "{e["ip"]}:{e["port"]}"')})
        return out

    def entry(self, k):
        return next((x for x in self.sd_devs() if x['key'] == k), None)

    def select(self, k, **extra):
        en = self.entry(k)
        if en and not en['ex'] and en['cap']:
            e = self.ex.ensure(en['cap'])
            if e:
                k = e['key']
                en = self.entry(k)
        self.node = {'k': k, **extra}
        return en

    def open_device(self, k):
        self.live = True
        prev = self.node
        en = self.select(k)
        self._push(prev)
        if en:
            self.gopen.add('n' + ('local' if en['net'] is None else str(en['net'])))
        self.win.goto('x')
        self.refresh()

    # --------------------------------------------------------------- redraw --
    def ex_changed(self):
        if self.win.cur_view == 'x':
            self.refresh(soft=True)

    def refresh(self, soft=False):
        self._stale = False
        armed = self.ex.armed()
        self.armpill.setVisible(armed)
        self.b_arm.setText('Write access ON – turn off' if armed else 'Enable write access…')
        self.b_arm.setStyleSheet('QPushButton{background:#c42b1c;color:white}' if armed else '')
        AL = sorted(self.sd_devs(), key=lambda a: (-1 if a['net'] is None else a['net'], a['id']))
        D = [d for d in AL if d['ex'] or d['key'] in self.vis]
        self.b_new.setVisible(bool(D))
        self.b_scan.setText('Stop scan' if self.ex.busy == 'scan' else 'Scan network')
        show_left = bool(self.pk) or (self.live and bool(D))
        self.left.setVisible(show_left)
        if self.ex.busy == 'scan':
            self.status.setText('⏳ ' + self.ex.msg)
        else:
            self.status.setText(self.status_text(D))
        if show_left:
            self.build_tree(AL, D)
        self.build_right(D, AL)

    def status_text(self, D):
        if self.pk:
            return 'Devices seen in the capture – tick the ones to discover.'
        n = len(D)
        on = sum(1 for d in D if d['ex'] and not d['ex'].get('old'))
        if not n:
            return 'No devices discovered yet.'
        if self.ex.scan_at and on:
            return f"{n} device{'' if n == 1 else 's'} · {on} answered the scan {ago(self.ex.scan_at)}"
        return f"{n} device{'' if n == 1 else 's'} from your capture. Press Scan network to see which are online."

    def _dot(self, d):
        e = d['ex']
        c = colors()
        if e and not e.get('old'):
            return '●', c['no'], 'Answered discovery'
        if d['cap']:
            return '●', '#0a84ff', 'Seen in the capture'
        return '○', c['mu'], 'From the last scan – did not answer this time'

    def build_tree(self, AL, D):
        self._building = True
        tr = self.tree
        y = tr.verticalScrollBar().value()
        tr.setUpdatesEnabled(False)
        tr.clear()
        q = self.tq.lower()
        bold = QFont(tr.font())
        bold.setBold(True)
        mu = QColor(colors()['mu'])
        cur = None
        if self.pk:
            run = self.pk.get('run')
            L0 = [d for d in AL if d['cap'] and (not q or q in f"{d['id']} {d['name']} {d['vendor']} {d['ip']}".lower())]
            groups = {}
            for d in L0:
                groups.setdefault('local' if d['net'] is None else d['net'], []).append(d)
            for k, L in groups.items():
                gk = 'n' + str(k)
                lab = self.win.labels.n(k) if k != 'local' else ''
                g = QTreeWidgetItem(tr, [('This network' if k == 'local' else f'Network {k}') + (f' “{lab}”' if lab else '')
                                         + f"  · {len(L)} device{'' if len(L) == 1 else 's'}"])
                g.setData(0, K_ROLE, ('g', gk))
                g.setFlags(g.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsAutoTristate)
                for d in L:
                    it = QTreeWidgetItem(g, [f"{d['id']}   {d['name']}" + (f"   — {d['vendor']}" if d['vendor'] else '')])
                    it.setData(0, K_ROLE, ('pk', d['key']))
                    it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    it.setCheckState(0, Qt.CheckState.Checked if d['key'] in self.pk['sel'] else Qt.CheckState.Unchecked)
                    if run:
                        it.setDisabled(True)
                g.setExpanded(gk in self.gopen or bool(q))
            if not groups:
                QTreeWidgetItem(tr, ['No devices in the capture yet.']).setForeground(0, mu)
        else:
            groups = {}
            for d in D:
                groups.setdefault('local' if d['net'] is None else d['net'], []).append(d)

            def pm(o):
                return q in f"{o['name']} {E.sd_ty(o['ty'])} {o['inst']}".lower()
            sel = self.node
            for k, L0 in groups.items():
                L = [d for d in L0 if not q or q in f"{d['id']} {d['name']} {d['vendor']} {d['model']}".lower()
                     or any(pm(o) for o in ((d['ex'] or {}).get('objs') or []))]
                if not L:
                    continue
                gk = 'n' + str(k)
                lab = self.win.labels.n(k) if k != 'local' else ''
                g = QTreeWidgetItem(tr, [('Local Network – BACnet/IP' if k == 'local' else f'Network {k}') + (f' “{lab}”' if lab else '')
                                         + f"  · {len(L)} device{'' if len(L) == 1 else 's'}"])
                g.setData(0, K_ROLE, ('g', gk))
                g.setFont(0, bold)
                for d in L:
                    e = d['ex']
                    dot, col, tip = self._dot(d)
                    it = QTreeWidgetItem(g, [f"{dot}  " + (f"{d['name']} {d['id']}" if d['name'] else f"Device {d['id']}")
                                             + (f"  – {d['ip']}" if d['ip'] else '')])
                    it.setToolTip(0, f"{tip}\n{d['vendor']}" if d['vendor'] else tip)
                    it.setForeground(0, QColor(colors()['fg']))
                    it.setData(0, K_ROLE, ('d', d['key']))
                    if sel and sel['k'] == d['key'] and sel.get('t') is None and sel.get('o') is None:
                        cur = it
                    if e and e.get('objs'):
                        for t, os_ in self.ex.cats(e):
                            os2 = [o for o in os_ if pm(o) or q in f"{d['id']} {d['name']}".lower()] if q else os_
                            if not os2:
                                continue
                            ck = e['key'] + '|' + str(t)
                            ci = QTreeWidgetItem(it, [f"{E.cat_name(t)}  ({len(os2)})"])
                            ci.setData(0, K_ROLE, ('c', e['key'], t))
                            ci.setForeground(0, mu)
                            if sel and sel['k'] == e['key'] and sel.get('t') == t and sel.get('o') is None:
                                cur = ci
                            for o in sorted(os2, key=lambda o: C.natural_key(o['name']))[:800]:
                                pi = QTreeWidgetItem(ci, [o['name'] or f"{E.sd_ty(o['ty'])} {o['inst']}"])
                                pi.setData(0, K_ROLE, ('p', e['key'], o['o']))
                                pi.setToolTip(0, f"{o['val']} {o['u']}".strip())
                                if sel and sel['k'] == e['key'] and sel.get('o') == o['o']:
                                    cur = pi
                            ci.setExpanded(ck in self.open or bool(q))
                        it.setExpanded(e['key'] in self.open or bool(q))
                g.setExpanded(gk in self.gopen or bool(q))
            if not tr.topLevelItemCount():
                QTreeWidgetItem(tr, ['No matches.' if D else 'Nothing here yet. Choose devices on the right to discover them.']).setForeground(0, mu)
        if cur is not None:
            tr.setCurrentItem(cur)
        tr.setUpdatesEnabled(True)
        QTimer.singleShot(0, lambda: tr.verticalScrollBar().setValue(y))
        self._building = False

    def _exp(self, it, on):
        if self._building:
            return
        d = it.data(0, K_ROLE)
        if not d:
            return
        key = d[1] if d[0] in ('g', 'd') else f'{d[1]}|{d[2]}' if d[0] == 'c' else None
        if key is None:
            return
        s = self.gopen if d[0] == 'g' else self.open
        if d[0] == 'd':
            en = self.entry(d[1])
            key = en['ex']['key'] if en and en['ex'] else key
        (s.add if on else s.discard)(key)

    def _tree_pick(self, it, _prev):
        if self._building or not it:
            return
        d = it.data(0, K_ROLE)
        if not d or d[0] in ('g', 'pk'):
            return
        prev = self.node
        if d[0] == 'd':
            self.select(d[1])
        elif d[0] == 'c':
            self.node = {'k': d[1], 't': d[2]}
        elif d[0] == 'p':
            self.node = {'k': d[1], 'o': d[2]}
        self._push(prev)
        self.build_right(None, None)

    def _checked(self, it, _col):
        if self._building or not self.pk or self.pk.get('run'):
            return
        d = it.data(0, K_ROLE)
        if d and d[0] == 'pk':
            (self.pk['sel'].add if it.checkState(0) == Qt.CheckState.Checked else self.pk['sel'].discard)(d[1])
            QTimer.singleShot(0, lambda: self.build_right(None, None))

    def _search(self, t):
        self.tq = t
        self._st = getattr(self, '_st', None) or QTimer(self, singleShot=True, timeout=self.refresh)
        self._st.start(200)

    # ----------------------------------------------------------- right side --
    def build_right(self, D, AL):
        if AL is None:
            AL = sorted(self.sd_devs(), key=lambda a: (-1 if a['net'] is None else a['net'], a['id']))
            D = [d for d in AL if d['ex'] or d['key'] in self.vis]
        p = self.right
        y = p.scroll.verticalScrollBar().value()
        p.setUpdatesEnabled(False)
        p.clear()
        n = self.node
        en = self.entry(n['k']) if n else None
        e = en['ex'] if en else None
        row = next((o for o in (e or {}).get('objs') or [] if o['o'] == n.get('o')), None) if en and n.get('o') is not None else None
        self.nav_bar(n, en, row)
        if not n or not en:
            self.start_page(p, D, AL)
        else:
            if row and e:
                self.point_page(p, en, e, row)
            elif n.get('t') is not None and e:
                self.cat_page(p, en, e, n['t'])
            else:
                self.device_page(p, en, e)
        p.end()
        p.setUpdatesEnabled(True)
        QTimer.singleShot(0, lambda: p.scroll.verticalScrollBar().setValue(y))

    def go_node(self, n):
        prev = self.node
        self.node = n
        self._push(prev)
        self.refresh()

    # ----------------------------------------------------------- navigation --
    def _push(self, prev):
        """Remember where we were (for Back) when the shown page changes."""
        if prev != self.node:
            self.hist.append(prev)
            del self.hist[:-60]

    def can_back(self):
        return bool(self.pk and not self.pk.get('run')) or bool(self.hist) or self.node is not None

    def back(self):
        """Back one step inside Discover. Returns False when there is nowhere to go back to."""
        if self.pk and not self.pk.get('run'):
            self.pk = None                       # leave the 'choose devices' step
        elif self.hist:
            self.node = self.hist.pop()
        elif self.node is not None:
            self.node = None
        else:
            return False
        self.refresh()
        return True

    def home(self):
        if self.node is None and not self.pk:
            return
        if self.pk and self.pk.get('run'):
            return self.win.toast('Wait for the discover to finish, or press Stop')
        self.pk = None
        prev = self.node
        self.node = None
        self._push(prev)
        self.refresh()

    def nav_bar(self, n, en, row):
        """Back / home buttons and a clickable path: Discover › Network › Device › Category › Point."""
        self.b_back.setEnabled(self.can_back())
        self.b_home.setEnabled(n is not None or bool(self.pk))
        self.win.update_back()
        while self.crumbs.count():
            w = self.crumbs.takeAt(0).widget()
            if w:
                w.setParent(None)                   # hide it now, not when Qt gets round to deleting it
                w.deleteLater()
        parts = [('Discover', self.home if (n or self.pk) else None)]
        if self.pk:
            parts.append(('Choose devices', None))
        elif n and en:
            parts.append(('This network' if en['net'] is None else f"Network {en['net']}", None))
            dev = f"Device {en['id']}" + (f" “{en['name']}”" if en['name'] else '')
            deeper = n.get('t') is not None or n.get('o') is not None
            parts.append((dev, (lambda k=n['k']: self.go_node({'k': k})) if deeper else None))
            t = n['t'] if n.get('t') is not None else E.o_t(n['o']) if n.get('o') is not None else None
            if t is not None:
                parts.append((E.cat_name(t), (lambda k=n['k'], t=t: self.go_node({'k': k, 't': t})) if n.get('o') is not None else None))
            if n.get('o') is not None:
                parts.append((row['name'] or f"{E.sd_ty(row['ty'])} {row['inst']}" if row else 'Point', None))
        for i, (text, fn) in enumerate(parts):
            if i:
                self.crumbs.addWidget(label('›', muted=True, wrap=False))
            if fn:
                b = QToolButton(text=text)
                b.setAutoRaise(True)
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                b.setStyleSheet(f"QToolButton{{color:{colors()['ac']}}}")
                b.clicked.connect(fn)
                self.crumbs.addWidget(b)
            else:
                self.crumbs.addWidget(label(text, bold=(i == len(parts) - 1), wrap=False))
        self.crumbs.addStretch(1)

    def start_page(self, p, D, AL):
        cap = [d for d in AL if d['cap']]
        pk = self.pk
        run = pk and pk.get('run')
        p.add(label('New discover', bold=True, size=17))
        p.add(label('Choose where the devices come from, pick the ones you want, then press Discover to read their points into a tree.', muted=True))
        cards = QHBoxLayout()

        def card(title, sub, fn, on=False, enabled=True):
            b = QPushButton(f'{title}\n{sub}')
            b.setMinimumHeight(64)
            b.setCheckable(True)
            b.setChecked(on)
            b.setEnabled(bool(enabled))
            b.setStyleSheet('QPushButton{text-align:left;padding:10px 14px}')
            b.clicked.connect(fn)
            cards.addWidget(b)
        card('Use devices from the capture',
             f"{len(cap)} device{'' if len(cap) == 1 else 's'} seen in the capture you have open" if cap else
             'No devices in the open capture yet – start or open a capture first',
             self.pick_capture, bool(pk and pk['src'] == 'cap'), not run)
        card('Stop scan' if self.ex.busy == 'scan' else 'Scan the network', 'Send a Who-Is and list who answers', lambda: self.scan(), False, not run)
        w = QWidget()
        w.setLayout(cards)
        p.add(w)
        if self.ex.busy == 'scan':
            p.add(label('⏳ ' + self.ex.msg, muted=True))
        if pk:
            L = [d for d in AL if d['ex']] if pk['src'] == 'scan' else cap
            sl = [d['id'] for d in L if d['key'] in pk['sel']]
            box = QFrame()
            box.setObjectName('pick')
            box.setStyleSheet(f"QFrame#pick{{border:1px solid {colors()['bd']};border-radius:10px}}")
            bv = QVBoxLayout(box)
            hr = QHBoxLayout()
            hr.addWidget(label('Discovering…' if run else 'Choose devices on the left', bold=True, wrap=False))
            hr.addWidget(label(f'{len(sl)} of {len(L)} selected', muted=True, wrap=False))
            hr.addStretch(1)
            ba = QPushButton('Select all')
            bn = QPushButton('Clear')
            ba.setEnabled(not run)
            bn.setEnabled(not run)
            ba.clicked.connect(lambda: (pk['sel'].update(d['key'] for d in L), self.refresh()))
            bn.clicked.connect(lambda: (pk['sel'].clear(), self.refresh()))
            hr.addWidget(ba)
            hr.addWidget(bn)
            bv.addLayout(hr)
            bv.addWidget(label(('Selected: ' + ', '.join(map(str, sl[:40])) + (' …' if len(sl) > 40 else '')) if sl else
                               'Open a network on the left, then tick the network or the devices you want.', muted=True))
            fr = QHBoxLayout()
            if run:
                st = QPushButton('Stop')
                st.clicked.connect(lambda: (pk.__setitem__('stop', True), setattr(self.ex, 'stop', True)))
                fr.addWidget(st)
                fr.addWidget(label(f"⏳ Reading {run['i']} of {run['n']}" + (f" – device {run['cur']}" if run['cur'] else '') + '…', muted=True))
            else:
                go = QPushButton(f"Discover {len(sl)} device{'' if len(sl) == 1 else 's'}" if sl else 'Discover')
                go.setDefault(True)
                go.setEnabled(bool(sl))
                go.clicked.connect(self.run_picked)
                fr.addWidget(go)
            fr.addStretch(1)
            bv.addLayout(fr)
            p.add(box)
        elif D:
            p.add(label(f"{len(D)} device{'' if len(D) == 1 else 's'} already discovered are on the left. Pick one to see its points, "
                        'or start another discover above.', muted=True))
            r = QHBoxLayout()
            b1 = QPushButton('Export device list (.csv)')
            b1.clicked.connect(lambda: self.save_csv('bacnet-devices.csv', self.csv_devices()))
            b2 = QPushButton('Use names as labels')
            b2.setToolTip('Use these device names as labels in the Packets and Findings tabs')
            b2.clicked.connect(self.names_as_labels)
            r.addWidget(b1)
            r.addWidget(b2)
            r.addStretch(1)
            ww = QWidget()
            ww.setLayout(r)
            p.add(ww)

    def info_grid(self, items):
        f = QFrame()
        f.setObjectName('info')
        f.setStyleSheet(f"QFrame#info{{background:{colors()['hd']};border-radius:10px}}")
        g = QGridLayout(f)
        g.setContentsMargins(16, 12, 16, 12)
        g.setHorizontalSpacing(18)
        for i, (k, v) in enumerate(items):
            g.addWidget(label(k, muted=True, wrap=False), i, 0, Qt.AlignmentFlag.AlignTop)
            g.addWidget(label(str(v), sel=True), i, 1)
        g.setColumnStretch(1, 1)
        f.setMaximumWidth(760)
        return f

    def device_page(self, p, en, e):
        busy = self.ex.busy
        p.add(label(f"Device {en['id']}" + (f" – {en['name']}" if en['name'] else ''), bold=True, size=17))
        p.add(label(' · '.join(x for x in [en['vendor'], en['model']] if x), muted=True))
        r = QHBoxLayout()
        b = QPushButton('Refresh points' if e and e.get('objs') else 'Read points')
        b.setEnabled(not busy and bool(e or en['cap']))
        b.clicked.connect(lambda: self.read_points(en))
        r.addWidget(b)
        b2 = QPushButton('Show packets')
        b2.clicked.connect(lambda: self.show_packets(en['filt']))
        r.addWidget(b2)
        if e and e.get('objs'):
            b3 = QPushButton('Export points (.csv)')
            b3.clicked.connect(lambda: self.save_csv(f"device-{e['id']}-points.csv", self.csv_points(e)))
            r.addWidget(b3)
        r.addWidget(label((e or {}).get('pm') or '', muted=True, wrap=False))
        r.addStretch(1)
        ww = QWidget()
        ww.setLayout(r)
        p.add(ww)
        if not (e and e.get('objs')):
            p.add(label('Press Read points to read this device’s objects and build its tree of points.', muted=True))
        info = [('Address', E.Explorer.addr(e) if e else en['ip']), ('Vendor', en['vendor']), ('Model', en['model']),
                ('Firmware', e and e.get('fw')), ('Software', e and e.get('sw')), ('Location', e and e.get('loc')),
                ('Description', e and e.get('desc')), ('Max APDU', e and e.get('mx')), ('Status', e and e.get('st'))]
        p.add(self.info_grid([(k, v) for k, v in info if v]))
        cats = self.ex.cats(e) if e else []
        if cats:
            p.add(heading('Points', 12))
            t = Table(['Category', 'Points'])
            t.fill([[E.cat_name(ty), len(os_)] for ty, os_ in cats], [{'k': e['key'], 't': ty} for ty, _ in cats])
            t.rowActivated.connect(lambda n: n and (self.open.add(f"{n['k']}|{n['t']}"), self.go_node(n)))
            t.fit_height()
            p.add(t)
        self.wlog(p, en['id'])

    def cat_page(self, p, en, e, ty):
        os_ = [o for o in e.get('objs') or [] if o['ty'] == ty]
        p.add(label(E.cat_name(ty), bold=True, size=17))
        p.add(label(f"{len(os_)} point{'' if len(os_) == 1 else 's'} in device {en['id']}" + (f" “{en['name']}”" if en['name'] else ''), muted=True))
        r = QHBoxLayout()
        b = QPushButton('Refresh values')
        b.setEnabled(not self.ex.busy)
        b.clicked.connect(lambda: self.ex.run(self.ex.values_all, e))
        r.addWidget(b)
        r.addWidget(label(e.get('pm') or '', muted=True, wrap=False))
        r.addStretch(1)
        ww = QWidget()
        ww.setLayout(r)
        p.add(ww)
        t = Table(['#', 'Name', 'Value', 'Description', ''])
        t.fill([[o['inst'], o['name'], (f"{o['val']} {o['u']}".strip(), {'bold': True}), (o['desc'], {'fg': colors()['mu']}),
                 'commandable – double-click to open' if o['ty'] in E.CMD_T else ''] for o in os_],
               [{'k': e['key'], 'o': o['o']} for o in os_])
        t.rowActivated.connect(lambda n: n and self.go_node(n))
        t.fit_height(40)
        p.add(t)
        self.wlog(p, en['id'])

    def point_page(self, p, en, e, o):
        if not o.get('pd') and not o.get('pdl'):
            o['pdl'] = 1
            self.ex.run(self._load_point, e, o)
        wr = o['ty'] in E.CMD_T
        nm = o['name'] or f"{E.sd_ty(o['ty'])} {o['inst']}"
        tn = E.cat_name(o['ty']).rstrip('s')
        ab = E.ABBR.get(o['ty']) or f"OBJ{o['ty']}"
        val = f"{o['val']} {o['u']}".strip()
        pd = o.get('pd')
        tabs = QTabWidget()
        tabs.setDocumentMode(False)
        # summary
        s = QWidget()
        sv = QVBoxLayout(s)
        hd = QHBoxLayout()
        hd.addWidget(label(f'BACnet {tn}', bold=True, wrap=False))
        hd.addStretch(1)
        hd.addWidget(label(f'RefName: {ab.lower()}{o["inst"]}', wrap=False, sel=True))
        sv.addLayout(hd)
        mid = QHBoxLayout()
        mid.addStretch(1)
        lcd = QLabel(val or '—')
        lcd.setMinimumSize(170, 78)
        lcd.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lcd.setStyleSheet("QLabel{background:#000;color:#c9d33a;border:3px solid #1d1d1d;border-radius:3px;"
                          "font:600 20px 'Cascadia Mono',Consolas;padding:0 14px}")
        mid.addWidget(lcd)
        mid.addSpacing(16)
        mid.addWidget(label(f'Present Value  =  {val or "?"}', bold=True, wrap=False, sel=True))
        mid.addStretch(1)
        sv.addLayout(mid)
        f = QFormLayout()
        for k, v in (('Display Name:', nm), ('Description:', o['desc'] or '')):
            le = QLineEdit(v)
            le.setReadOnly(True)
            f.addRow(k, le)
        sv.addLayout(f)
        sv.addLayout(self._point_buttons(en, e, o, wr))
        sv.addStretch(1)
        tabs.addTab(s, 'Summary')
        # details
        dw = QWidget()
        dv = QVBoxLayout(dw)
        if not pd:
            dv.addWidget(label('⏳ Reading the details from the device…', muted=True))
        elif pd.get('err'):
            er = label(pd['err'])
            er.setStyleSheet(f"color:{colors()['se']}")
            dv.addWidget(er)
        g = (pd or {})

        def ro(v):
            le = QLineEdit('' if v is None else str(v))
            le.setReadOnly(True)
            return le
        f1 = QFormLayout()
        f1.addRow('Display Name:', ro(nm))
        f1.addRow('Description:', ro(o['desc'] or ''))
        f1.addRow('Present Value =', ro(val))
        dv.addLayout(f1)
        dv.addLayout(self._point_buttons(en, e, o, wr, details=True))

        def section(t):
            b = label(t, bold=True)
            b.setStyleSheet('background:#6b6b6e;color:white;padding:5px 12px')
            dv.addWidget(b)
        section('Calibration')
        f2 = QFormLayout()
        f2.addRow('COV Increment:', ro(g.get('cov', '')))
        f2.addRow('Resolution:', ro(g.get('res') or '?'))
        f2.addRow('Scaling Range – Minimum:', ro(g.get('min', '')))
        f2.addRow('Scaling Range – Maximum:', ro(g.get('max', '')))
        dv.addLayout(f2)
        section('BACnet Configuration')
        f3 = QFormLayout()
        f3.addRow('Object Name:', ro(nm))
        f3.addRow('Object Id:', ro(f"{tn} {o['inst']}"))
        f3.addRow('Object Type:', ro(tn))
        addr = f"bacnet://{en['id']}/{ab}:{o['inst']}"
        ar = QHBoxLayout()
        ar.addWidget(ro(addr), 1)
        cb = QPushButton('Copy')
        cb.clicked.connect(lambda: (QApplication.clipboard().setText(addr), self.win.toast('Address copied')))
        ar.addWidget(cb)
        f3.addRow('Address:', ar)
        oos = QCheckBox()
        oos.setEnabled(False)
        oos.setChecked(bool(g.get('oos')))
        f3.addRow('Out of Service:', oos)
        f3.addRow('Reliability:', ro(g.get('rel') or '?'))
        f3.addRow('Profile Name:', ro(g.get('prof') or '?'))
        dv.addLayout(f3)
        plb = QToolButton(text='Property List ' + ('▴' if o.get('pl') else '▾'))
        plb.clicked.connect(lambda: self._toggle_pl(e, o))
        dv.addWidget(plb)
        if o.get('pl'):
            pl = QLabel('\n'.join(o['pl']))
            pl.setFont(QFont('Cascadia Mono', 9))
            pl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            dv.addWidget(pl)
        elif o.get('pll'):
            dv.addWidget(label('Reading…', muted=True))
        if wr:
            pa = g.get('pa')
            cp = next((i + 1 for i, v in enumerate(pa) if v['a']), 0) if pa else 0
            f4 = QFormLayout()
            f4.addRow('Relinquish Default:', ro(g.get('rd', '')))
            f4.addRow('Current Command Priority:', ro((cp if cp else 'none (at default)') if pa else '?'))
            dv.addLayout(f4)
            section('Priority Array')
            if pa:
                grid = QGridLayout()
                for c in range(4):
                    for i in range(4):
                        k = c * 4 + i + 1
                        v = pa[k - 1] if k - 1 < len(pa) else None
                        grid.addWidget(label(f'{k}:', muted=True, wrap=False), i, c * 2, Qt.AlignmentFlag.AlignRight)
                        grid.addWidget(label(v['s'] if v and v['a'] else '', bold=True, wrap=False), i, c * 2 + 1)
                dv.addLayout(grid)
            else:
                dv.addWidget(label('?', muted=True))
            dv.addWidget(label('To clear a priority level, use Write… and choose Release at that priority.', muted=True))
        dv.addStretch(1)
        tabs.addTab(dw, 'Details')
        tabs.setCurrentIndex(self.ptab)
        tabs.currentChanged.connect(lambda i: setattr(self, 'ptab', i))
        hdr = label(f"{en['name'] or 'Device ' + str(en['id'])}  /  {tn}  /  {nm}", bold=True)
        p.add(hdr)
        p.add(tabs)
        self.wlog(p, en['id'])

    def _point_buttons(self, en, e, o, wr, details=False):
        r = QHBoxLayout()
        b = QPushButton('Read now')
        b.setEnabled(not self.ex.busy)
        b.clicked.connect(lambda: self.ex.run(self.ex.read_one, e, o))
        r.addWidget(b)
        if wr:
            w = QPushButton('Write…')
            w.clicked.connect(lambda: write_dialog(self.win, e, o))
            r.addWidget(w)
        if not details:
            s = QPushButton('Show packets')
            s.setToolTip('Show the packets that mention this point')
            s.clicked.connect(lambda: self.show_packets(f"{en['filt']} && info contains \"{C.tyname(o['ty'])} {o['inst']}\""))
            r.addWidget(s)
        r.addStretch(1)
        return r

    def _load_point(self, e, o):
        self.ex.read_detail(e, o)
        o['pdl'] = 0

    def _toggle_pl(self, e, o):
        if o.get('pl'):
            o['pl'] = None
        elif not o.get('pll'):
            o['pll'] = 1
            self.ex.run(self.ex.read_prop_list, e, o)
        self.build_right(None, None)

    def wlog(self, p, dev_id):
        L = [w for w in self.ex.wlog if dev_id is None or w['dev'] == dev_id]
        if not L:
            return
        p.add(heading('Write log' + (' – this device' if dev_id is not None else ''), 12))
        b = QPushButton('Export write log (.csv)')
        b.clicked.connect(lambda: self.save_csv('bacnet-write-log.csv', self.csv_wlog()))
        r = QHBoxLayout()
        r.addWidget(b)
        r.addStretch(1)
        ww = QWidget()
        ww.setLayout(r)
        p.add(ww)
        c = colors()
        t = Table(['Time', 'Device', 'Point', 'Value', 'Priority', 'Result', 'Read back'])
        t.fill([[time.strftime('%H:%M:%S', time.localtime(w['t'] / 1000)), f"{w['dev']}" + (f" · {w['dname']}" if w['dname'] else ''),
                 w['obj'] + (f" · {w['pname']}" if w['pname'] else ''), w['val'], w['pri'],
                 (w['res'], {'fg': c['no'] if w['res'] == 'accepted' else c['se']}),
                 (w.get('rb') or '') + (f" (overridden by priority {w['hi']})" if w.get('ov') else '')] for w in L[:100]])
        t.fit_height()
        p.add(t)

    # -------------------------------------------------------------- actions --
    def new_discover(self):
        self.home()

    def pick_capture(self):
        self.live = True
        self.pk = {'src': 'cap', 'sel': set(), 'run': None, 'stop': False}
        self.refresh()

    def scan(self, quiet=False):
        ex = self.ex
        if ex.busy == 'scan':
            ex.stop = True
            return
        if ex.busy:
            return
        self.live = True
        self.pk = None
        ex.run(ex.scan, lambda n: self.win.on_ui(lambda: n and self.win.labels_changed()))
        self.refresh()

    def run_picked(self):
        pk = self.pk
        if not pk or pk.get('run'):
            return
        keys = list(pk['sel'])
        if not keys:
            return
        pk['run'] = {'i': 0, 'n': len(keys), 'cur': ''}
        self.refresh()

        def work():
            first = None
            for i, k in enumerate(keys):
                if pk.get('stop'):
                    break
                pk['run'].update(i=i + 1)
                a = self.entry(k)
                if not a:
                    continue
                e = a['ex'] or (a['cap'] and self.ex.ensure(a['cap']))
                if not e:
                    continue
                pk['run']['cur'] = e['id']
                first = first or e
                e['stale'] = 1
                self.ex.notify()
                try:
                    if not e.get('name'):
                        self.ex.info(e)
                    self.ex.browse(e)
                except Exception as x:
                    e['pm'] = f'Could not read: {x}'

            def done():
                self.ex.busy = ''
                self.pk = None
                self.gopen.clear()
                self.ex.cache()
                if first:
                    prev = self.node
                    self.node = {'k': first['key']}
                    self._push(prev)
                    self.open.add(first['key'])
                self.refresh()
            self.win.on_ui(done)
        self.ex.run(work)

    def read_points(self, en):
        e = en['ex'] or (en['cap'] and self.ex.ensure(en['cap']))
        if not e:
            return self.win.toast('This device is not reachable by IP')
        e['stale'] = 1
        self.open.add(e['key'])
        prev = self.node
        self.node = {'k': e['key']}
        self._push(prev)

        def work():
            self.ex.browse(e)
            for t, _ in self.ex.cats(e):
                self.open.add(f"{e['key']}|{t}")
            self.ex.notify()
        self.ex.run(work)
        self.refresh()

    def show_packets(self, f):
        if not self.win.ac:
            return self.win.toast("Open or start a capture to see this device's packets")
        self.win.go_packets(f)

    def names_as_labels(self):
        n = 0
        for d in list(self.ex.devs.values()):
            if d.get('name'):
                self.win.store.labels()['d'][str(d['id'])] = d['name']
                n += 1
        self.win.store.save_labels()
        self.win.labels_changed()
        self.win.toast(f'{n} device names added as labels')

    def _menu(self, pos):
        it = self.tree.itemAt(pos)
        d = it.data(0, K_ROLE) if it else None
        if not d or d[0] not in ('d',):
            return
        en = self.entry(d[1])
        if not en:
            return
        ex = en['ex']
        m = QMenu(self)
        m.addAction('Open in Discover', lambda: self.open_device(d[1]))
        a = m.addAction('Refresh points' if ex and ex.get('objs') else 'Read points', lambda: self.read_points(en))
        a.setEnabled(bool(ex or en['cap']))

        def ref():
            e2 = ex or self.ex.ensure(en['cap'])
            if e2:
                def w():
                    self.ex.info(e2)
                    self.ex.cache()
                    self.ex.labels_from_names()
                self.ex.run(w)
        m.addAction('Refresh name and details', ref).setEnabled(bool(ex or en['cap']))
        m.addSeparator()
        m.addAction('Show this device’s packets', lambda: self.show_packets(en['filt'])).setEnabled(bool(self.win.ac))
        m.addAction('Name this device…', lambda: self.win.edit_label('d', en['id']))
        m.addSeparator()
        m.addAction('Copy device ID', lambda: QApplication.clipboard().setText(str(en['id'])))
        ip = en['ip'] or (ex and ex.get('ip')) or ''
        m.addAction('Copy IP address', lambda: QApplication.clipboard().setText(ip)).setEnabled(bool(ip))
        m.addAction('Export points (.csv)', lambda: self.save_csv(f"device-{en['id']}-points.csv", self.csv_points(ex))).setEnabled(bool(ex and ex.get('objs')))
        m.addSeparator()

        def forget():
            self.ex.devs.pop(ex['key'], None)
            if self.node and self.node['k'] == ex['key']:
                self.node = None
            self.ex.cache()
            self.refresh()
        m.addAction('Forget this discovered device', forget).setEnabled(bool(ex) and not en['cap'])
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def options(self):
        o = self.ex.opt
        d = QDialog(self)
        d.setWindowTitle('Discovery options')
        v = QVBoxLayout(d)
        v.addWidget(label('Discovery only sends Who-Is and read requests – it never changes anything. Writing is a separate switch on the Discover tab.', muted=True))
        f = QFormLayout()
        to = QLineEdit(o.get('to', ''))
        to.setPlaceholderText('leave empty for automatic, or e.g. 10.0.255.255')
        lo = QLineEdit(o.get('lo', ''))
        lo.setPlaceholderText('from')
        hi = QLineEdit(o.get('hi', ''))
        hi.setPlaceholderText('to')
        rr = QHBoxLayout()
        rr.addWidget(lo)
        rr.addWidget(QLabel('–'))
        rr.addWidget(hi)
        bb_ = QLineEdit(o.get('bbmd', ''))
        bb_.setPlaceholderText('BBMD address, e.g. 10.20.0.5')
        f.addRow('Send to', to)
        f.addRow('Only device IDs', rr)
        f.addRow('Also scan other subnets through a BBMD\n(registers this PC as a foreign device for 5 minutes)', bb_)
        v.addLayout(f)
        lab = QCheckBox('Use discovered device names as labels in captures')
        lab.setChecked(bool(o.get('lab')))
        auto = QCheckBox('Discover automatically when a live capture starts')
        auto.setChecked(bool(o.get('auto')))
        v.addWidget(lab)
        v.addWidget(auto)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(d.accept)
        bb.rejected.connect(d.reject)
        v.addWidget(bb)
        d.resize(520, 260)
        if d.exec() == QDialog.DialogCode.Accepted:
            o.update(to=to.text().strip(), lo=lo.text().strip(), hi=hi.text().strip(), bbmd=bb_.text().strip(),
                     lab=1 if lab.isChecked() else 0, auto=1 if auto.isChecked() else 0)
            self.ex.save_opt()
            self.win.toast('Discovery options saved')

    # ---------------------------------------------------------------- export --
    def csv_devices(self):
        rows = [[d['id'], d.get('name') or '', d['ip'] + (' / ' + d['sa'] if d.get('sa') else ''), '' if d.get('sn') is None else d['sn'],
                 d.get('vendor') or C.VN.get(d.get('vn'), ''), d.get('vn'), d.get('model') or '', d.get('fw') or '', d.get('sw') or '',
                 d.get('desc') or '', d.get('loc') or '', d.get('mx')] for d in sorted(self.ex.devs.values(), key=lambda d: d['id'])]
        return csv_text('Device ID,Name,Address,Network,Vendor,Vendor ID,Model,Firmware,Software version,Description,Location,Max APDU', rows)

    @staticmethod
    def csv_points(d):
        return csv_text('Device ID,Device name,Object type,Instance,Object name,Present value,Units,Description',
                        [[d['id'], d.get('name') or '', E.sd_ty(o['ty']), o['inst'], o['name'], o['val'], o['u'], o['desc']] for o in d.get('objs') or []])

    def csv_wlog(self):
        return csv_text('Time,Device,Device name,Point,Value,Priority,Result,Read back,Highest active priority',
                        [[time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(w['t'] / 1000)), w['dev'], w['dname'],
                          w['obj'] + (f" ({w['pname']})" if w['pname'] else ''), w['val'], w['pri'], w['res'], w.get('rb') or '',
                          w.get('hi') or ''] for w in self.ex.wlog])

    def save_csv(self, name, text):
        p, _ = QFileDialog.getSaveFileName(self, 'Save', name, 'Spreadsheet (*.csv)')
        if p:
            try:
                with open(p, 'w', encoding='utf-8-sig', newline='') as f:
                    f.write(text)
                self.win.toast('Saved ' + p)
            except OSError as e:
                self.win.toast(f'Save failed: {e.strerror}')

    def formats(self):
        def html():
            rows = [[d['id'], esc(d.get('name') or ''), esc(E.Explorer.addr(d)), esc(d.get('vendor') or C.VN.get(d.get('vn'), '')),
                     esc(d.get('model') or ''), esc(d.get('st') or '')] for d in sorted(self.ex.devs.values(), key=lambda d: d['id'])]
            return doc('Discovered devices', f'<h3>Discovered devices</h3><p class="mu">Saved {stamp()}</p>' +
                       html_table(['Device ID', 'Name', 'Address', 'Vendor', 'Model', 'Status'], rows))
        return [('html', 'Web page – the discovered devices (*.html)', 'html', html),
                ('csv', 'Spreadsheet – one row per device (*.csv)', 'csv', lambda: '﻿' + self.csv_devices())]


# ============================================================ dialogs --
def arm_dialog(win):
    d = QDialog(win)
    d.setWindowTitle('Turn on write access?')
    v = QVBoxLayout(d)
    v.addWidget(label('This lets you send Write Property commands (present-value, with a priority) to devices from the Discover '
                      'tab. A wrong value can start or stop real equipment.'))
    v.addWidget(label('• Only one point at a time, to one device, and each write asks you to confirm.\n'
                      '• It switches itself off after the time you choose, and a red bar stays on screen while it is on.\n'
                      '• Every write is recorded in the write log (and in writes.log next to the app’s settings).', muted=True))
    ok = QCheckBox('I understand this changes live equipment')
    v.addWidget(ok)
    row = QHBoxLayout()
    row.addWidget(QLabel('Switch off after'))
    mins = QComboBox()
    for m in (5, 15, 30, 60):
        mins.addItem(f'{m} minutes', m)
    mins.setCurrentIndex(1)
    row.addWidget(mins)
    row.addStretch(1)
    v.addLayout(row)
    bb = QDialogButtonBox()
    go = bb.addButton('Turn on write access', QDialogButtonBox.ButtonRole.AcceptRole)
    go.setStyleSheet('QPushButton{background:#c42b1c;color:white} QPushButton:disabled{background:#d9a9a4}')
    go.setEnabled(False)
    bb.addButton(QDialogButtonBox.StandardButton.Cancel)
    ok.toggled.connect(go.setEnabled)
    bb.accepted.connect(d.accept)
    bb.rejected.connect(d.reject)
    v.addWidget(bb)
    d.resize(520, 240)
    if d.exec() != QDialog.DialogCode.Accepted:
        return False
    try:
        win.explorer.arm(mins.currentData())
    except Exception:
        win.toast('Could not turn on write access')
        return False
    win.explorer.pump()
    return True


PRI = {1: ' – manual life safety', 2: ' – automatic life safety', 5: ' – critical equipment', 6: ' – minimum on/off',
       8: ' – manual operator (usual for technicians)', 16: ' – lowest (schedules)'}


def write_dialog(win, dev, row):
    ex = win.explorer
    if not ex.armed():
        if not arm_dialog(win):
            return
        win.wb_draw()
    binary = row['ty'] in (4, 5)
    ms = row['ty'] in (14, 19)
    tn = f"{E.sd_ty(row['ty'])} {row['inst']}"
    nm = row.get('name') or tn
    dn = dev.get('name') or f"device {dev['id']}"
    d = QDialog(win)
    d.setWindowTitle(f'Write to {nm}')
    v = QVBoxLayout(d)
    v.addWidget(label(f"Device {dev['id']}" + (f" “{dev['name']}”" if dev.get('name') else '') + f' · {tn} · present-value', muted=True))
    v.addWidget(label(f"Current value: {(str(row.get('val') or '').strip() or 'unknown')} {row.get('u') or ''}", bold=True))
    f = QFormLayout()
    if binary:
        val = QComboBox()
        val.addItem('active (on)', 'active')
        val.addItem('inactive (off)', 'inactive')
    else:
        val = QLineEdit()
        val.setPlaceholderText('state number, e.g. 2' if ms else 'number, e.g. 21.5')
    f.addRow('New value', val)
    pri = QComboBox()
    for i in range(1, 17):
        pri.addItem(f'{i}{PRI.get(i, "")}', i)
    pri.setCurrentIndex(7)
    f.addRow('Priority', pri)
    v.addLayout(f)
    rel = QCheckBox('Release – remove my command at this priority (writes NULL)')
    rel.toggled.connect(lambda on: val.setEnabled(not on))
    v.addWidget(rel)
    msg = QLabel()
    msg.setWordWrap(True)
    msg.setTextFormat(Qt.TextFormat.RichText)
    v.addWidget(msg)
    bb = QDialogButtonBox()
    go = bb.addButton('Write…', QDialogButtonBox.ButtonRole.ActionRole)
    go.setStyleSheet('QPushButton{background:#c42b1c;color:white;padding:4px 14px}')
    close = bb.addButton(QDialogButtonBox.StandardButton.Close)
    close.clicked.connect(d.reject)
    v.addWidget(bb)
    st = {'step': 0}
    c = colors()

    def text():
        return val.currentData() if binary else val.text().strip()

    def click():
        p = pri.currentData()
        release = rel.isChecked()
        if release:
            enc = [0]
        else:
            enc = E.ex_enc(row['ty'], text())
            if not enc:
                msg.setText(f'<span style="color:{c["se"]}">That is not a valid value for this kind of point.</span>')
                return
        shown = 'RELEASE (null)' if release else (text() if binary else f"{text()} {row.get('u') or ''}")
        if st['step'] == 0:
            st['step'] = 1
            go.setText(f"Confirm: {'release' if release else 'write ' + shown.strip()} at priority {p}")
            msg.setText(f"<b>Check before you confirm:</b> {'release your command on' if release else 'set'} <b>{esc(nm)}</b> in "
                        f"<b>{esc(dn)}</b>{'' if release else ' to <b>' + esc(shown.strip()) + '</b>'} at priority <b>{p}</b>.")
            for w in (val, pri, rel):
                w.setEnabled(False)
            return
        go.setEnabled(False)
        go.setText('Writing…')

        def work():
            _e, m, ok = ex.write(dev, row, enc, p, release, shown)

            def done():
                msg.setText(f'<span style="color:{c["no"] if ok else c["se"]}"><b>{esc(m.split(". ")[0])}.</b></span> ' + esc('. '.join(m.split('. ')[1:])))
                go.hide()
                close.setText('Done')
                if 'x' in win.views:
                    win.views['x'].refresh()
            win.on_ui(done)
        ex.run(work)
    go.clicked.connect(click)
    d.resize(560, 300)
    d.exec()


def read_now(win, d, ob):
    """Right-click a packet: read that point straight from the device (read-only)."""
    ex = win.explorer
    e = ex.ensure(d)
    if not e:
        return win.toast('This device is not reachable by IP')
    dlg = QDialog(win)
    lab = win.labels.d(d['id'])
    dlg.setWindowTitle(f"Device {d['id']}" + (f' “{lab}”' if lab else '') + f" – {E.sd_ty(ob['ty'])} {ob['inst']}")
    v = QVBoxLayout(dlg)
    v.addWidget(label('Read just now from the network (read-only).', muted=True))
    body = QLabel('⏳ Reading…')
    body.setTextFormat(Qt.TextFormat.RichText)
    body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    body.setWordWrap(True)
    v.addWidget(body)
    bb = QDialogButtonBox()
    again = bb.addButton('Read again', QDialogButtonBox.ButtonRole.ActionRole)
    wr = bb.addButton('Write…', QDialogButtonBox.ButtonRole.ActionRole)
    wr.setVisible(False)
    bb.addButton(QDialogButtonBox.StandardButton.Close).clicked.connect(dlg.reject)
    v.addWidget(bb)
    row = {'o': ob['o'], 'ty': ob['ty'], 'inst': ob['inst'], 'name': '', 'val': '', 'u': '', 'desc': ''}

    def go():
        body.setText('⏳ Reading…')

        def work():
            r = ex.req(e, E.ex_rpm([[ob['o'], [77, 85, 117, 28]]]), 3.0)
            ok = False
            if r.get('d'):
                L = E.ex_dec_rpm(r['d'], r['k'], r['L'])
                if L:
                    ex._fill(row, L[0]['pr'])
                    ok = True

            def done():
                if ok:
                    body.setText(f"<table cellpadding='4'><tr><td>Name</td><td><b>{esc(row['name'])}</b></td></tr>"
                                 f"<tr><td>Present value</td><td><b>{esc(row['val'] or '(no present value)')} {esc(row['u'])}</b></td></tr>"
                                 f"<tr><td>Description</td><td>{esc(row['desc'])}</td></tr></table>")
                    wr.setVisible(ob['ty'] in E.CMD_T)
                else:
                    body.setText(f"<span style='color:{colors()['se']}'>" +
                                 esc('No answer from the device.' if r.get('to') else (r.get('err') or 'Could not read')) + '</span>')
            win.on_ui(done)
        ex.run(work)
    again.clicked.connect(go)
    wr.clicked.connect(lambda: (dlg.accept(), write_dialog(win, e, row)))
    go()
    dlg.resize(460, 220)
    dlg.exec()

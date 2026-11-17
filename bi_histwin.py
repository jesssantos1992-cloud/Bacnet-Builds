"""
bi_histwin.py - the History tab in Discover: the last discovers kept on this computer (how many is a setting).
It looks and works like the Devices tab - the same tree (network, device, category, point), the same pages on the
right - but shows a saved discover, read-only. Pick which discover at the top; compare it with the one before it or
with the Devices tab now; reopen it in the Devices tab; export; delete. Storage and comparison are in bi_history.py.
"""
from __future__ import annotations

import time

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit, QMenu,
                               QPushButton, QSpinBox, QSplitter, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
                               QWidget)

import bi_core as C
import bi_explore as E
import bi_history as H
import bi_ui as U
from bi_common import Page, RowDelegate, Table, colors, csv_text, dev_name, heading, label, semibold

K_ROLE = Qt.ItemDataRole.UserRole


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
    def __init__(self, dv):
        super().__init__()
        self.dv, self.win, self.ex = dv, dv.win, dv.ex
        self.idx = []                     # bi_history.index(), newest first
        self.snap = None                  # the discover shown, loaded
        self.node = None                  # like Discover: {'g'} / {'k'} / {'k','t'} / {'k','o'} / {'chg': 1 or 2}
        self.open, self.gopen = set(), set()
        self.tq = ''
        self.rows, self.head = [], []     # what the right side's table shows, for Export
        self.seen = None
        self._building = False
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        # ---- which discover (where the Devices tab has its Connection bar)
        bar = QFrame()
        bv = QVBoxLayout(bar)
        bv.setContentsMargins(24, 0, 24, 12)
        bv.setSpacing(8)
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(label('Discover from', bold=True, wrap=False))
        self.pick = QComboBox()
        self.pick.setMinimumWidth(380)
        self.pick.currentIndexChanged.connect(self.picked)
        row.addWidget(self.pick)
        self.open_b = QPushButton('Open in Discover')
        self.open_b.setToolTip('Put these devices and the points read then back in the Devices tab (marked as from '
                               'History until they answer again)')
        self.open_b.clicked.connect(self.open_in_discover)
        row.addWidget(self.open_b)
        self.cmp_b = QPushButton('Compare')
        m = QMenu(self.cmp_b)
        m.addAction('With the discover before it', lambda: self.go({'chg': 1}))
        m.addAction('With the Devices tab now', lambda: self.go({'chg': 2}))
        self.cmp_b.setMenu(m)
        row.addWidget(self.cmp_b)
        self.exp_b = QPushButton('Export…')
        self.exp_b.clicked.connect(self.export)
        row.addWidget(self.exp_b)
        row.addStretch(1)
        row.addWidget(QLabel('Keep the last'))
        self.keep = QSpinBox()
        self.keep.setRange(0, 100)
        self.keep.setValue(self.ex.hist_keep())
        self.keep.setToolTip('How many discovers to keep. Older ones are deleted. 0 switches History off.')
        self.keep.valueChanged.connect(self.keep_changed)
        row.addWidget(self.keep)
        row.addWidget(QLabel('discovers'))
        self.del_b = QPushButton('Delete this discover')
        self.del_b.clicked.connect(self.delete)
        row.addWidget(self.del_b)
        bv.addLayout(row)
        self.empty = label('', muted=True)
        bv.addWidget(self.empty)
        v.addWidget(bar)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        v.addWidget(line)
        # ---- the same split as the Devices tab
        self.split = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 10, 6, 8)
        ll.setSpacing(8)
        self.status = label('', muted=True)
        ll.addWidget(self.status)
        self.q = QLineEdit()
        self.q.setPlaceholderText('Search devices and points')
        self.q.setClearButtonEnabled(True)
        self.q.textChanged.connect(self._search)
        ll.addWidget(self.q)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setAnimated(True)
        self.tree.setItemDelegate(RowDelegate(self.tree))
        self.tree.setIconSize(QSize(12, 12))
        self.tree.setFrameShape(QFrame.Shape.NoFrame)
        self.tree.currentItemChanged.connect(self._tree_pick)
        self.tree.itemExpanded.connect(lambda it: self._exp(it, True))
        self.tree.itemCollapsed.connect(lambda it: self._exp(it, False))
        ll.addWidget(self.tree, 1)
        leg = QWidget()
        lg = QHBoxLayout(leg)
        lg.setContentsMargins(4, 0, 0, 0)
        lg.setSpacing(4)
        il = QLabel()
        il.setPixmap(U.dot(colors()['no']).pixmap(QSize(12, 12)))
        lg.addWidget(il)
        lg.addWidget(label('answered in this discover', muted=True, wrap=False))
        lg.addStretch(1)
        ll.addWidget(leg)
        self.split.addWidget(left)
        rightw = QWidget()
        rv = QVBoxLayout(rightw)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(0)
        nav = QWidget()
        nl = QHBoxLayout(nav)
        nl.setContentsMargins(16, 6, 16, 6)
        nl.setSpacing(6)
        self.b_home = U.tool(QToolButton(), 'home', 'Home', 'Back to this discover’s overview')
        self.b_home.clicked.connect(lambda: self.go(None))
        nl.addWidget(self.b_home)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        nl.addWidget(sep)
        self.crumb = label('', muted=True, wrap=False)
        nl.addWidget(self.crumb, 1)
        rv.addWidget(nav)
        ln = QFrame()
        ln.setFrameShape(QFrame.Shape.HLine)
        rv.addWidget(ln)
        self.right = Page(1100)
        rv.addWidget(self.right, 1)
        self.split.addWidget(rightw)
        self.split.setSizes([320, 900])
        self.split.setStretchFactor(1, 1)
        v.addWidget(self.split, 1)
        self.vals = None                  # the "Include point value changes" box on the Changes page

    # ------------------------------------------------------- which discover --
    def reload(self):
        self.seen = getattr(self.ex, 'hist_seq', 0)
        sel = self.snap['meta']['id'] if self.snap else None
        if sel and self.idx and self.idx[0]['id'] == sel:
            sel = None                                  # on the newest: follow to the newest (a new discover was saved)
        self.idx = H.index()
        self.pick.blockSignals(True)
        self.pick.clear()
        for x in self.idx:
            self.pick.addItem(f"{when(x['at'])}  ({ago(x.get('upd') or x['at'])})  ·  "
                              f"{x.get('where') or ('MS/TP' if x.get('mode') == 'mstp' else 'BACnet/IP')}  ·  "
                              f"{x.get('n', 0)} device{'' if x.get('n') == 1 else 's'}", x['id'])
        i = next((i for i, x in enumerate(self.idx) if x['id'] == sel), 0 if self.idx else -1)
        self.pick.setCurrentIndex(i)
        self.pick.blockSignals(False)
        keep = self.ex.hist_keep()
        self.empty.setText('History is off. Set “Keep the last” to 1 or more to keep your discovers.' if keep <= 0 else
                           '' if self.idx else 'No discovers saved yet. Scan the network on the Devices tab: each discover '
                                               'is kept here, with the points you read.')
        self.empty.setVisible(bool(self.empty.text()))
        for w in (self.pick, self.open_b, self.cmp_b, self.exp_b, self.del_b):
            w.setEnabled(bool(self.idx))
        self.split.setVisible(bool(self.idx))
        self.picked(keep_node=True)

    def maybe_reload(self):
        if getattr(self.ex, 'hist_seq', 0) != self.seen:
            self.reload()

    def keep_changed(self, n):
        self.win.store.set('bi_hist_keep', n)
        if n < len(self.idx):
            H.prune(n)
        self.reload()

    def picked(self, _i=None, keep_node=False):
        i = self.pick.currentIndex()
        m = self.idx[i] if 0 <= i < len(self.idx) else None
        same = bool(m and self.snap and self.snap['meta']['id'] == m['id'])
        if not m:
            self.snap = None
        elif not same or self.snap['meta'].get('upd') != m.get('upd'):
            self.snap = H.load(m['id'])
        if not (same and keep_node):
            self.node = None
        if self.node and self.node.get('k') and not self.dev(self.node['k']):
            self.node = None
        self.refresh()

    def delete(self):
        if not self.snap:
            return
        sid = self.snap['meta']['id']
        H.delete([sid])
        if getattr(self.ex, 'hist_id', None) == sid:
            self.ex.new_history()                       # the next save makes a new entry instead
        self.snap = None
        self.reload()
        self.win.toast('Deleted that discover')

    # ------------------------------------------------------------- the data --
    def devs(self):
        return sorted((self.snap or {}).get('devs') or [], key=lambda d: (-1 if d.get('sn') is None else d['sn'], d['id']))

    def dev(self, k):
        return next((d for d in (self.snap or {}).get('devs') or [] if d['key'] == k), None)

    @staticmethod
    def grp(d):
        if d.get('sn') is not None:
            return d['sn']
        return 'mstp' if d.get('via') == 'mstp' else 'local'

    def grp_name(self, k, short=False):
        if k == 'mstp':
            w = (self.snap or {}).get('meta', {}).get('where') or ''
            port = w[6:].strip() if w.startswith('MS/TP') else ''
            return 'MS/TP trunk' + (f' ({port})' if port else '')
        if k == 'local':
            return 'This network' if short else 'Local Network – BACnet/IP'
        return f'Network {k}'

    def entry(self, d):
        """A saved device in the shape Discover's labels expect (the name you gave it wins, as in Discover)."""
        return {**d, 'name': self.win.labels.d(d['id']) or d.get('name') or '', 'vendor': d.get('vendor') or C.VN.get(d.get('vn'), '')}

    # ------------------------------------------------------------- the tree --
    def refresh(self):
        self.status.setText(self.status_text())
        self.build_tree()
        self.build_right()

    def status_text(self):
        if not self.snap:
            return ''
        m = self.snap['meta']
        return (f"{m.get('n', 0)} device{'' if m.get('n') == 1 else 's'} · {m.get('pts', 0):,} points · "
                f"saved {when(m.get('upd') or m['at'])}")

    def _search(self, t):
        self.tq = t.strip()
        self.build_tree()

    def build_tree(self):
        """The same tree as the Devices tab: network › device › category › point."""
        self._building = True
        tr = self.tree
        tr.setUpdatesEnabled(False)
        tr.clear()
        q = self.tq.lower()
        bold = semibold(QFont(tr.font()))
        mu = QColor(colors()['mu'])
        sel = self.node or {}
        cur = None
        groups = {}
        for d in self.devs():
            groups.setdefault(self.grp(d), []).append(self.entry(d))

        def pm(o):
            return q in f"{o.get('name') or ''} {E.sd_ty(o['ty'])} {o['inst']}".lower()
        for k, L0 in groups.items():
            L = [d for d in L0 if not q or q in f"{d['id']} {d['name']} {d['vendor']} {d.get('model') or ''}".lower()
                 or any(pm(o) for o in d.get('objs') or [])]
            if not L:
                continue
            gk = 'n' + str(k)
            lab = self.win.labels.n(k) if isinstance(k, int) else ''
            g = QTreeWidgetItem(tr, [self.grp_name(k) + (f' “{lab}”' if lab else '') + f"  · {len(L)} device{'' if len(L) == 1 else 's'}"])
            g.setData(0, K_ROLE, ('g', k))
            g.setFont(0, bold)
            if sel.get('g') == k:
                cur = g
            for d in L:
                ip = d.get('ip') or ''
                it = QTreeWidgetItem(g, [self.dv.dev_label(d) + (f'  – {ip}' if ip else '')])
                it.setIcon(0, U.dot(colors()['no']))
                it.setToolTip(0, '\n'.join(str(x) for x in ('Answered in this discover', d['name'], d['vendor'], ip) if x))
                it.setForeground(0, QColor(colors()['fg']))
                it.setData(0, K_ROLE, ('d', d['key']))
                if sel.get('k') == d['key'] and sel.get('t') is None and sel.get('o') is None:
                    cur = it
                if d.get('objs'):
                    for t, os_ in E.Explorer.cats(d):
                        os2 = [o for o in os_ if pm(o) or q in f"{d['id']} {d['name']}".lower()] if q else os_
                        if not os2:
                            continue
                        ck = d['key'] + '|' + str(t)
                        ci = QTreeWidgetItem(it, [f"{E.cat_name(t)}  ({len(os2)})"])
                        ci.setData(0, K_ROLE, ('c', d['key'], t))
                        ci.setForeground(0, mu)
                        if sel.get('k') == d['key'] and sel.get('t') == t and sel.get('o') is None:
                            cur = ci
                        for o in sorted(os2, key=lambda o: C.natural_key(o.get('name') or ''))[:800]:
                            pi = QTreeWidgetItem(ci, [o.get('name') or f"{E.sd_ty(o['ty'])} {o['inst']}"])
                            pi.setData(0, K_ROLE, ('p', d['key'], o['o']))
                            pi.setToolTip(0, E.value_text(o))
                            if sel.get('k') == d['key'] and sel.get('o') == o['o']:
                                cur = pi
                        ci.setExpanded(ck in self.open or bool(q))
                    it.setExpanded(d['key'] in self.open or bool(q))
            g.setExpanded(gk in self.gopen or bool(q) or len(groups) == 1)
        if not tr.topLevelItemCount():
            QTreeWidgetItem(tr, ['No matches.' if self.snap else '']).setForeground(0, mu)
        if cur is not None:
            tr.setCurrentItem(cur)
        tr.setUpdatesEnabled(True)
        self._building = False

    def _exp(self, it, on):
        if self._building:
            return
        d = it.data(0, K_ROLE)
        if not d:
            return
        if d[0] == 'g':
            (self.gopen.add if on else self.gopen.discard)('n' + str(d[1]))
        elif d[0] in ('d', 'c'):
            key = d[1] if d[0] == 'd' else f'{d[1]}|{d[2]}'
            (self.open.add if on else self.open.discard)(key)

    def _tree_pick(self, it, _prev):
        if self._building or not it:
            return
        d = it.data(0, K_ROLE)
        if not d:
            return
        self.node = {'g': d[1]} if d[0] == 'g' else {'k': d[1]} if d[0] == 'd' else \
            {'k': d[1], 't': d[2]} if d[0] == 'c' else {'k': d[1], 'o': d[2]}
        self.build_right()

    def go(self, n):
        """Show a node (as Discover's go_node): open its branch in the tree and its page on the right."""
        self.node = n
        if n and n.get('k'):
            self.open.add(n['k'])
            d = self.dev(n['k'])
            if d is not None:
                self.gopen.add('n' + str(self.grp(d)))
            o = next((x for x in (d or {}).get('objs') or [] if x['o'] == n.get('o')), None) if n.get('o') is not None else None
            t = n.get('t') if n.get('t') is not None else (o['ty'] if o else None)
            if t is not None:
                self.open.add(f"{n['k']}|{t}")
        self.build_tree()
        self.build_right()

    # ------------------------------------------------------------ the pages --
    def build_right(self):
        p = self.right
        p.setUpdatesEnabled(False)
        p.clear()
        self.rows, self.head = [], []
        n = self.node or {}
        s = self.snap
        d = self.dev(n['k']) if n.get('k') else None
        crumbs = [f"{when(s['meta']['at'])}" if s else 'History']
        if not s:
            pass
        elif n.get('chg'):
            crumbs.append('Changes since the discover before' if n['chg'] == 1 else 'Changes compared with now')
            self.changes_page(p, n['chg'])
        elif n.get('g') is not None:
            crumbs.append(self.grp_name(n['g']))
            self.net_page(p, n['g'])
        elif d is None:
            self.home_page(p)
        else:
            en = self.entry(d)
            crumbs.append(self.grp_name(self.grp(d)))
            crumbs.append(dev_name(en['name'], d['id']) or f"Device {d['id']}")
            o = next((x for x in d.get('objs') or [] if x['o'] == n.get('o')), None) if n.get('o') is not None else None
            if o:
                crumbs += [E.cat_name(o['ty']), o.get('name') or f"{E.sd_ty(o['ty'])} {o['inst']}"]
                self.point_page(p, en, o)
            elif n.get('t') is not None:
                crumbs.append(E.cat_name(n['t']))
                self.cat_page(p, en, n['t'])
            else:
                self.device_page(p, en)
        self.crumb.setText('  ›  '.join(crumbs))
        p.end()
        p.setUpdatesEnabled(True)

    def _table(self, head, rows, data=None, styled=None):
        t = Table(head)
        t.fill(styled or rows, data)
        t.rowActivated.connect(lambda x: x and self.go(x))
        t.fit_height()
        self.rows, self.head = rows, head
        return t

    def dev_rows(self, L):
        return [[d['id'], dev_name(self.entry(d)['name'], d['id']) or '', self.entry(d)['vendor'], d.get('model') or '',
                 d.get('fw') or '', addr(d), len(d['objs']) if d.get('objs') is not None else 'not read'] for d in L]

    def home_page(self, p):
        m = self.snap['meta']
        p.add(label(f"Discover of {when(m['at'])}", bold=True, size=17))
        p.add(label(' · '.join(x for x in [m.get('where') or '', self.status_text()] if x), muted=True))
        p.add(label('Pick a device on the left to see it as it was then, or press Compare to see what has changed since.',
                    muted=True))
        L = self.devs()
        p.add(heading('Devices', 13))
        p.add(self._table(['Device ID', 'Name', 'Manufacturer', 'Model', 'Firmware', 'Address', 'Points'], self.dev_rows(L),
                          [{'k': d['key']} for d in L]))

    def net_page(self, p, k):
        L = [d for d in self.devs() if self.grp(d) == k]
        p.add(label(self.grp_name(k), bold=True, size=17))
        p.add(label(f"{len(L)} device{'' if len(L) == 1 else 's'} in this discover", muted=True))
        p.add(self._table(['Device ID', 'Name', 'Manufacturer', 'Model', 'Firmware', 'Address', 'Points'], self.dev_rows(L),
                          [{'k': d['key']} for d in L]))

    def device_page(self, p, d):
        nm_ = dev_name(d['name'], d['id'])
        p.add(label(nm_ or f"Device {d['id']}", bold=True, size=17))
        p.add(label(' · '.join(str(x) for x in [f"Device {d['id']}" if nm_ else '', d['vendor'], d.get('model')] if x), muted=True))
        info = [('Address', addr(d)), ('Manufacturer', d['vendor']), ('Model', d.get('model')), ('Location', d.get('loc')),
                ('Description', d.get('desc')), ('Saved', when((self.snap['meta'].get('upd') or self.snap['meta']['at'])))]
        tech = [('Firmware', d.get('fw')), ('Software', d.get('sw')), ('Max APDU', d.get('mx')),
                ('Device object', f"device {d['id']}"), ('Vendor ID', d.get('vn'))]
        p.add(self.dv.info_grid([(k, v) for k, v in info if v], tech))
        cats = E.Explorer.cats(d) if d.get('objs') else []
        if cats:
            p.add(heading('Points', 13))
            p.add(self._table(['Category', 'Points'], [[E.cat_name(ty), len(os_)] for ty, os_ in cats],
                              [{'k': d['key'], 't': ty} for ty, _ in cats]))
        else:
            p.add(label('The points of this device were not read in this discover.', muted=True))

    def cat_page(self, p, d, ty):
        os_ = [o for o in d.get('objs') or [] if o['ty'] == ty]
        p.add(label(E.cat_name(ty), bold=True, size=17))
        nm_ = dev_name(d['name'], d['id'])
        p.add(label(f"{len(os_)} point{'' if len(os_) == 1 else 's'} in device {d['id']}" + (f" “{nm_}”" if nm_ else '')
                    + f" · as read on {when(self.snap['meta'].get('upd') or self.snap['meta']['at'])}", muted=True))
        ms = ty in E.MS_T
        head = ['#', 'Name', 'Value', 'Description'] + (['States'] if ms else [])
        rows = [[o['inst'], o.get('name') or '', E.value_text(o), o.get('desc') or '']
                + ([E.states_text(o) if o.get('states') else ''] if ms else []) for o in os_]
        mu = colors()['mu']
        styled = [[r[0], r[1], (r[2], {'bold': True}), (r[3], {'fg': mu})] + ([(r[4], {'fg': mu})] if ms else []) for r in rows]
        t = self._table(head, rows, [{'k': d['key'], 'o': o['o']} for o in os_], styled)
        t.setMaximumHeight(100000)
        p.add(t)

    def point_page(self, p, d, o):
        nm = o.get('name') or f"{E.sd_ty(o['ty'])} {o['inst']}"
        ab = E.ABBR.get(o['ty']) or f"OBJ{o['ty']}"
        p.add(label(nm, bold=True, size=17))
        p.add(label(f"{E.cat_name(o['ty']).rstrip('s')} · {ab.lower()}{o['inst']} · device {d['id']}"
                    + (f" “{dev_name(d['name'], d['id'])}”" if dev_name(d['name'], d['id']) else ''), muted=True))
        big = QLabel(E.value_text(o) or '—')
        bf = big.font()
        bf.setPointSizeF(26)
        bf.setWeight(QFont.Weight.DemiBold)
        big.setFont(bf)
        big.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        big.setToolTip(f"Present value as read on {when(self.snap['meta'].get('upd') or self.snap['meta']['at'])}")
        p.add(big)
        w = QWidget()
        f = QFormLayout(w)
        f.setContentsMargins(0, 0, 0, 0)

        def ro(v):
            le = QLineEdit('' if v is None else str(v))
            le.setReadOnly(True)
            return le
        f.addRow('Display name:', ro(nm))
        f.addRow('Description:', ro(o.get('desc') or ''))
        f.addRow('Units:', ro(E.unit_of(o)))
        f.addRow('Object ID:', ro(f"{E.sd_ty(o['ty'])} {o['inst']}"))
        if o.get('states'):
            f.addRow('States:', ro(E.states_text(o, 64)))
        w.setMaximumWidth(760)
        p.add(w)
        b = QPushButton('Open this point in Discover')
        b.setToolTip('Read it live: opens the device in the Devices tab (from this discover if it is not there yet)')
        b.clicked.connect(lambda: self.open_point(d, o))
        r = QHBoxLayout()
        r.addWidget(b)
        r.addStretch(1)
        rw = QWidget()
        rw.setLayout(r)
        p.add(rw)

    def changes_page(self, p, which):
        s = self.snap
        c = colors()
        p.add(label('Changes since the discover before it' if which == 1 else 'Changes compared with the Devices tab now',
                    bold=True, size=17))
        self.vals = QCheckBox('Include point value changes')
        self.vals.setToolTip('Values change all the time; tick this to list them too')
        self.vals.setChecked(bool(getattr(self, '_vals_on', False)))
        self.vals.toggled.connect(lambda on: (setattr(self, '_vals_on', on), self.build_right()))
        if which == 1:
            i = next((i for i, x in enumerate(self.idx) if x['id'] == s['meta']['id']), -1)
            old = H.load(self.idx[i + 1]['id']) if 0 <= i < len(self.idx) - 1 else None
            if not old:
                p.add(label('This is the oldest discover kept, so there is nothing before it to compare with.', muted=True))
                return
            ch = H.diff(old['devs'], s['devs'], self.vals.isChecked())
            what = f"between {when(old['meta']['at'])} and {when(s['meta']['at'])}"
        else:
            ms = self.ex.mode == 'mstp'
            now = H.slim([d for d in self.ex.devs.values() if E.is_mstp(d) == ms and not d.get('hist')])
            if not now:
                p.add(label('The Devices tab is empty: scan the network first, then compare.', muted=True))
                return
            ch = H.diff(s['devs'], now, self.vals.isChecked())
            what = f"between {when(s['meta']['at'])} and the Devices tab now"
        nd = sum(1 for _k, _d, w, _a, _b in ch if w == 'device found')
        ng = sum(1 for _k, _d, w, _a, _b in ch if w == 'device did not answer')
        p.add(label((f"{len(ch)} change{'' if len(ch) == 1 else 's'} {what}" +
                     (f" · {nd} new device{'' if nd == 1 else 's'}" if nd else '') +
                     (f" · {ng} device{'' if ng == 1 else 's'} missing" if ng else '')) if ch else f'No changes {what}.',
                    muted=True))
        p.add(self.vals)
        if ch:
            word = {'new': 'Added', 'gone': 'Missing', 'changed': 'Changed'}
            col = {'new': c['no'], 'gone': c['se'], 'changed': c['wa']}
            rows = [[word[k], dev, w, a, b] for k, dev, w, a, b in ch]
            styled = [[(word[k], {'fg': col[k], 'bold': True}), dev, w, a, b] for k, dev, w, a, b in ch]
            t = Table(['Change', 'Device', 'What', 'Before', 'Now'])
            t.fill(styled)
            t.fit_height()
            self.rows, self.head = rows, ['Change', 'Device', 'What', 'Before', 'Now']
            p.add(t)

    # -------------------------------------------------------------- actions --
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

    def open_point(self, d, o):
        if d['key'] not in self.ex.devs:
            self.ex.open_history(self.snap)
        self.dv.live = True
        self.dv.show_tab('dev')
        self.dv.go_node({'k': d['key'], 'o': o['o']})

    def export(self):
        if not self.snap:
            return
        stamp = time.strftime('%Y%m%d-%H%M', time.localtime(self.snap['meta']['at']))
        if not self.rows:                                 # a point page: export the whole discover
            L = self.devs()
            self.head = ['Device ID', 'Name', 'Manufacturer', 'Model', 'Firmware', 'Address', 'Points']
            self.rows = self.dev_rows(L)
        n = self.node or {}
        name = 'changes' if n.get('chg') else 'discover'
        self.dv.save_csv(f'{name}-{stamp}.csv', csv_text(','.join(self.head), self.rows))

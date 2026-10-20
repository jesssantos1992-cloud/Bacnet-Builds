"""
bi_views.py - the analysis views of the native BACnet Inspector (Findings, Devices, Changes,
Traffic, Response times, Online board, Network map, Available IDs / networks, MS/TP trunk,
Bus speed, Compare), the plain-English report, the names dialog and the help pages.
"""
from __future__ import annotations

import json
import math
import re
import time

from PySide6.QtCore import QByteArray, QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QFontMetricsF, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFrame,
                               QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QPlainTextEdit,
                               QPushButton, QScrollArea, QTextBrowser, QToolButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

import bi_core as C
from bi_common import (CellGrid, HighlightDelegate, Page, Table, colors, flow_row, colors_light, csv_text, dev_name, doc, esc, heading, html_table, is_dark,
                       label, stamp, summary_row)

VN = C.VN


def who(win, k, km=None):
    """'address · Device 12 “name”' as plain text."""
    km = km if km is not None else C.kid_map(win.FD)
    ids = sorted(km.get(k, []))
    return k + ((' · ' + ', '.join(win.labels.lz(f'Device {i}') for i in ids)) if ids else '')


def rel(win, t):
    return C.tofixed(t - win.T0, 1) + ' s'


class BaseView(QWidget):
    key = '?'
    title = ''

    def __init__(self, win):
        super().__init__()
        self.win = win
        self._stale = True

    def refresh(self):
        pass

    def formats(self):
        return []

    def go(self, f):
        if f:
            self.win.go_packets(f)


class PageView(BaseView):
    """A view that rebuilds a scrolling page of widgets."""
    max_width = 1200

    def __init__(self, win):
        super().__init__(win)
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        self.page = Page(self.max_width)
        v.addWidget(self.page)

    def refresh(self):
        sb = self.page.scroll.verticalScrollBar()
        y = sb.value()
        self.page.setUpdatesEnabled(False)
        self.page.clear()
        self.build(self.page)
        self.page.end()
        self.page.setUpdatesEnabled(True)
        QTimer.singleShot(0, lambda: sb.setValue(y))
        self._stale = False

    def build(self, p):
        pass

    def table(self, p, headers, rows, data=None, fit=True, max_rows=None):
        t = Table(headers)
        t.fill(rows, data)
        t.rowActivated.connect(self.go)
        if fit:
            t.fit_height(max_rows)
        p.add(t)
        return t

    def savef(self, title, body_html, csv_fn):
        w = self.win
        return [('html', f'Web page – {title} as shown (*.html)', 'html',
                 lambda: doc(f'{title} – {w.ac.n if w.ac else ""}',
                             f'<h3>{esc(w.ac.n if w.ac else "")} – {esc(title)}</h3><p class="mu">Saved {stamp()}</p>' + body_html())),
                ('csv', f'Spreadsheet – {title} for Excel (*.csv)', 'csv', lambda: '﻿' + csv_fn())]


def hint(text):
    return label(text, muted=True)


# =============================================================== findings --
def findings_html(win, F, for_export=False):
    c = colors_light() if for_export else colors()
    hl = lambda s: win.labels.hl(s, for_export)  # noqa: E731
    cnt = {}
    for f in F:
        cnt[f['s']] = cnt.get(f['s'], 0) + 1
    head = ('Looks healthy – no problems found' if not F else 'Needs attention' if cnt.get('SERIOUS') or cnt.get('WARNING') else 'Looks OK')

    def pill(k, l):
        if not cnt.get(k):
            return ''
        col = {'SERIOUS': c['se'], 'WARNING': c['wa'], 'NOTE': c['no']}[k]
        if l != 'serious' and cnt[k] == 1:
            l = l[:-1]                                    # 1 warning, 1 note
        return f' &nbsp;<span style="color:{col};font-weight:600">● {cnt[k]} {l}</span>'
    h = [f'<p style="font-size:15pt;margin:0 0 16px 0"><b>{head}</b>{pill("SERIOUS", "serious")}{pill("WARNING", "warnings")}{pill("NOTE", "notes")}</p>']
    lb = lambda t: f'<p style="margin:12px 0 4px 0;font-size:8pt;color:{c["mu"]}"><b>{t}</b></p>'  # noqa: E731
    for f in F:
        col = {'SERIOUS': c['se'], 'WARNING': c['wa'], 'NOTE': c['no']}[f['s']]
        ev = ''
        if f.get('ev'):
            ev = lb('WHERE') + '<ul style="margin-top:0">' + ''.join(f'<li style="margin:3px 0">{hl(e)}</li>' for e in f['ev']) + '</ul>'
        steps = '<ol style="margin-top:0">' + ''.join(f'<li style="margin:4px 0">{hl(x)}</li>' for x in f['f']) + '</ol>'
        body = (f'<p style="margin:0"><span style="color:{col};font-size:8pt;font-weight:700">{f["s"]}</span> &nbsp; '
                f'<span style="font-size:12pt;font-weight:600">{hl(f["t"])}</span></p>'
                f'{lb("WHAT WE FOUND")}<p style="margin:0">{hl(f["w"])}</p>{ev}'
                f'{lb("WHY IT MATTERS")}<p style="margin:0">{hl(f["y"])}</p>{lb("HOW TO TROUBLESHOOT")}{steps}')
        h.append(f'<table width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:18px"><tr>'
                 f'<td width="5" style="background-color:{col}"></td>'
                 f'<td style="background-color:{c["hd"]}"><table width="100%" cellpadding="12"><tr><td>{body}</td></tr></table></td></tr></table>')
    return ''.join(h)


class FindingsView(BaseView):
    key, title = 'f', 'Findings'

    def __init__(self, win):
        super().__init__(win)
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        self.tb = QTextBrowser()
        self.tb.setFrameShape(QFrame.Shape.NoFrame)
        self.tb.document().setDocumentMargin(22)
        v.addWidget(self.tb)
        self._last = None

    def refresh(self):
        h = findings_html(self.win, self.win.FD)
        if h != self._last:
            y = self.tb.verticalScrollBar().value()
            self.tb.setHtml(h)
            self.tb.verticalScrollBar().setValue(y)
            self._last = h
        self._stale = False

    def formats(self):
        w = self.win
        F = w.FD
        n = w.ac.n if w.ac else ''

        def txt():
            if not F:
                body = 'No problems found.'
            else:
                parts = []
                for i, f in enumerate(F):
                    s = f"[{f['s']}] {i + 1}. {f['t']}\n  What we found: {f['w']}\n"
                    if f.get('ev'):
                        s += '  Where:\n' + '\n'.join('    - ' + e for e in f['ev']) + '\n'
                    s += f"  Why it matters: {f['y']}\n  How to troubleshoot:\n" + '\n'.join(f'    {j + 1}. {x}' for j, x in enumerate(f['f']))
                    parts.append(s)
                body = '\n\n'.join(parts)
            return f'BACnet Inspector – findings for {n}\nSaved {stamp()}\n\n' + body
        return [('html', 'Web page – as shown, with highlighted addresses and all troubleshooting steps (*.html)', 'html',
                 lambda: doc('Findings – ' + n, f'<h3>{esc(n)} – findings</h3><p class="mu">Saved {stamp()}</p>' + findings_html(w, F, True))),
                ('txt', 'Text file – plain text, easy to paste into a ticket or email (*.txt)', 'txt', txt),
                ('json', 'JSON file – for other tools (*.json)', 'json',
                 lambda: json.dumps({'capture': n, 'saved': time.strftime('%Y-%m-%dT%H:%M:%S'),
                                     'findings': [{'severity': f['s'], 'title': f['t'], 'what': f['w'], 'where': f.get('ev') or [],
                                                   'why': f['y'], 'steps': f['f']} for f in F]}, indent=2, ensure_ascii=False))]


# ================================================================ devices --
def device_tree(F):
    """{gateway: {network: [devices]}} plus the directly connected devices (the original's rdv)."""
    D = sorted(F.dv or [], key=lambda d: d['id'])
    via, adv, gws = F.via or {}, F.adv or {}, F.gws or {}
    T = {}

    def add(g, n):
        return T.setdefault(g, {}).setdefault(n, [])
    for d in D:
        if d['sn'] is not None:
            for g in (gws.get(d['key']) or [d['gw']]):
                add(g, d['sn']).append(d)
    for n in via:
        for g in via[n]:
            add(g, n)
    for n in adv:
        for g in adv[n]:
            add(g, n)
    loc = [d for d in D if d['sn'] is None]
    return T, loc, D


class DevicesView(BaseView):
    key, title = 'd', 'Devices'
    COLS = ['Gateway / network / device', 'Address', 'Manufacturer', 'Device name', 'Model', 'Firmware', 'Details']

    def __init__(self, win):
        super().__init__(win)
        v = QVBoxLayout(self)
        v.setContentsMargins(18, 14, 18, 10)
        v.setSpacing(8)
        self.top = QHBoxLayout()
        v.addLayout(self.top)
        row = QHBoxLayout()
        b1 = QPushButton('Expand all')
        b2 = QPushButton('Collapse all')
        b1.clicked.connect(lambda: self.expand(True))
        b2.clicked.connect(lambda: self.expand(False))
        row.addWidget(b1)
        row.addWidget(b2)
        row.addWidget(hint('Double-click a gateway, network or device to see the packets it sent or received. Right-click to give it a name.'), 1)
        v.addLayout(row)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(self.COLS))
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setItemDelegate(HighlightDelegate(self.tree))
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree.setColumnWidth(0, 320)
        for i, w in enumerate([200, 220, 180, 140, 100], 1):
            self.tree.setColumnWidth(i, w)
        self.tree.itemDoubleClicked.connect(lambda it, _c: self.go(it.data(0, Qt.ItemDataRole.UserRole)))
        self.tree.itemExpanded.connect(lambda it: self.ST.__setitem__(it.data(1, Qt.ItemDataRole.UserRole), True))
        self.tree.itemCollapsed.connect(lambda it: self.ST.__setitem__(it.data(1, Qt.ItemDataRole.UserRole), False))
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.menu)
        v.addWidget(self.tree, 1)
        self.empty = hint('')
        v.addWidget(self.empty)
        self.ST = {}
        self._last = None

    def expand(self, on):
        def walk(it):
            for i in range(it.childCount()):
                ch = it.child(i)
                ch.setExpanded(on)
                walk(ch)
        walk(self.tree.invisibleRootItem())

    def refresh(self):
        win = self.win
        F = win.FD
        T, loc, D = device_tree(F)
        nm = F.nm or {}
        cnt = {}
        for d in D:
            cnt[d['id']] = cnt.get(d['id'], 0) + 1
        sig = (id(F), len(D), json.dumps(win.store.labels(), sort_keys=True), is_dark())
        if sig == self._last:
            return
        self._last = sig
        while self.top.count():
            w = self.top.takeAt(0).widget()
            if w:
                w.setParent(None)                   # hide it now, not when Qt gets round to deleting it
                w.deleteLater()
        ng = len(T)
        nn = sum(len(x) for x in T.values())
        dup = sum(1 for c in cnt.values() if c > 1)
        pills = [(C.pl(ng, 'gateway'), 'NOTE'), (C.pl(nn, 'network'), 'NOTE'), (C.pl(len(D), 'device'), 'NOTE')]
        if dup:
            pills.append((C.pl(dup, 'duplicate ID'), 'SERIOUS'))
        self.top.addWidget(summary_row('Network layout', pills))
        self.tree.clear()
        bold = QFont(self.tree.font())
        bold.setBold(True)
        mu = QColor(colors()['mu'])
        se = QColor(colors()['se'])

        def mk(parent, cols, f, key, default_open=False):
            it = QTreeWidgetItem(parent, cols)
            it.setData(0, Qt.ItemDataRole.UserRole, f)
            it.setData(1, Qt.ItemDataRole.UserRole, key)
            if key is not None:
                it.setExpanded(self.ST.get(key, default_open))
            return it

        def dev(parent, d):
            m = nm.get(d['id'], {})
            vn = m.get('vendor') or VN.get(d['v']) or f"Vendor ID {d['v']}"
            lab = win.labels.d(d['id'])
            it = mk(parent, [f"Device {d['id']}" + (f' “{lab}”' if lab else ''),
                             d['sa'] if d['sn'] is not None else d['key'], vn, m.get('name', ''),
                             m.get('model') or 'not in this capture', m.get('fw', ''),
                             f"vendor ID {d['v']} · announced {d['n']}×" + ('   ⚠ duplicate device ID' if cnt[d['id']] > 1 else '')],
                    f'host == "{d["key"]}"', None)
            it.setData(2, Qt.ItemDataRole.UserRole, ('d', d['id']))
            if not m.get('model'):
                it.setForeground(4, mu)
            if cnt[d['id']] > 1:
                it.setForeground(6, se)
            it.setToolTip(0, 'Double-click to see every packet this device sent or received')
            return it
        for g in sorted(T):
            nets = sorted(T[g])
            cd = sum(len(T[g][n]) for n in nets)
            gi = mk(self.tree, [f'Gateway {g}', '', '', '', '', '', f"{C.pl(len(nets), 'network')}, {C.pl(cd, 'device')}"],
                    f'gateway == "{g}" || host == "{g}"', 'g|' + g, True)
            gi.setFont(0, bold)
            for n in nets:
                ds = sorted(T[g][n], key=lambda d: d['id'])
                lab = win.labels.n(n)
                ni = mk(gi, [f'network {n}' + (f' “{lab}”' if lab else ''), '', '', '', '', '', C.pl(len(ds), 'device')],
                        f'net == {n} && gateway == "{g}" || dnet == {n} && gateway == "{g}"', f'n|{g}|{n}')
                ni.setData(2, Qt.ItemDataRole.UserRole, ('n', n))
                if ds:
                    for d in ds:
                        dev(ni, d)
                else:
                    e = QTreeWidgetItem(ni, ['No devices seen on this network yet'])
                    e.setForeground(0, mu)
        if loc:
            li = mk(self.tree, ['This network', '', '', '', '', '', f"directly connected, no gateway · {C.pl(len(loc), 'device')}"],
                    '!gateway', 'local', False)
            li.setFont(0, bold)
            for d in loc:
                dev(li, d)
        msg = []
        if not T and not loc:
            msg.append('No devices have announced themselves yet.')
        if not T:
            msg.append('No routed traffic seen – every device is directly on this network.')
        self.empty.setText(' '.join(msg))
        self.empty.setVisible(bool(msg))
        self._stale = False

    def menu(self, pos):
        it = self.tree.itemAt(pos)
        if not it:
            return
        m = QMenu(self)
        f = it.data(0, Qt.ItemDataRole.UserRole)
        kind = it.data(2, Qt.ItemDataRole.UserRole)
        if f:
            m.addAction('Show packets', lambda: self.go(f))
        if kind:
            k, n = kind
            m.addAction('Name this device…' if k == 'd' else 'Name this network…', lambda: self.win.edit_label(k, n))
            if k == 'd':
                m.addAction('Open in Discover', lambda: self.win.open_device_from_packet(
                    next((d for d in self.win.FD.dv or [] if d['id'] == n), None)))
        m.addAction('Copy', lambda: QApplication.clipboard().setText('\t'.join(it.text(i) for i in range(self.tree.columnCount())).strip()))
        m.exec(self.tree.viewport().mapToGlobal(pos))
        self._last = None

    def formats(self):
        w = self.win

        def rows():
            F = w.FD
            nm, gws = F.nm or {}, F.gws or {}
            cnt = {}
            for d in F.dv or []:
                cnt[d['id']] = cnt.get(d['id'], 0) + 1
            out = []
            for d in sorted(F.dv or [], key=lambda d: d['id']):
                m = nm.get(d['id'], {})
                out.append([' / '.join(gws.get(d['key']) or [d['gw']]) if d['sn'] is not None else '', d['sn'] if d['sn'] is not None else '',
                            d['id'], d['sa'] if d['sn'] is not None else d['key'], m.get('vendor') or VN.get(d['v']) or '', d['v'],
                            m.get('model', ''), m.get('name', ''), m.get('fw', ''), d['n'], 'yes' if cnt[d['id']] > 1 else ''])
            return out

        def html():
            T, loc, D = device_tree(w.FD)
            nm = w.FD.nm or {}
            hl = lambda s: w.labels.hl(s, True)  # noqa: E731

            def dv(d):
                m = nm.get(d['id'], {})
                vn = m.get('vendor') or VN.get(d['v']) or f"Vendor ID {d['v']}"
                return (f"<li>{hl('Device ' + str(d['id']))} {hl(d['sa'] if d['sn'] is not None else d['key'])} <b>{esc(vn)}</b>"
                        f"{' “' + esc(m['name']) + '”' if m.get('name') else ''} · Model: {esc(m.get('model') or 'not in this capture')}"
                        f"{' · firmware ' + esc(m['fw']) if m.get('fw') else ''} <span class=\"mu\">vendor ID {d['v']} · announced {d['n']}×</span></li>")
            b = ''
            for g in sorted(T):
                b += f'<li><b>Gateway</b> {hl(g)}<ul>'
                for n in sorted(T[g]):
                    ds = sorted(T[g][n], key=lambda d: d['id'])
                    b += f'<li>{hl("network " + str(n))} <span class="mu">– {C.pl(len(ds), "device")}</span><ul>' + ''.join(dv(d) for d in ds) + '</ul></li>'
                b += '</ul></li>'
            if loc:
                b += '<li><b>This network</b> <span class="mu">– directly connected</span><ul>' + ''.join(dv(d) for d in loc) + '</ul></li>'
            n = w.ac.n if w.ac else ''
            return doc('Devices – ' + n, f'<h3>{esc(n)} – devices</h3><p class="mu">Saved {stamp()}</p><ul>{b}</ul>')
        return [('html', 'Web page – the gateway ▸ network ▸ device tree, fully expanded (*.html)', 'html', html),
                ('csv', 'Spreadsheet – one row per device with gateway, network, manufacturer and model (*.csv)', 'csv',
                 lambda: '﻿' + csv_text('Gateway,Network,Device ID,Address,Manufacturer,Vendor ID,Model,Device name,Firmware,Announced,Duplicate ID', rows()))]


# ================================================================ changes --
class ChangesView(BaseView):
    key, title = 'w', 'Changes'

    def __init__(self, win):
        super().__init__(win)
        v = QVBoxLayout(self)
        v.setContentsMargins(18, 14, 18, 10)
        v.setSpacing(8)
        self.top = QHBoxLayout()
        v.addLayout(self.top)
        v.addWidget(hint('Every change request sent on the network: who sent it, which device and point, the new value, the '
                         'priority and whether the device accepted it. “Commands” are restarts, communication on/off and '
                         'object create/delete. Double-click a row to see the packet.'))
        row = QHBoxLayout()
        row.addWidget(QLabel('Show'))
        self.wf = QComboBox()
        for t, k in [('Everything', 'all'), ('Point writes', 'w'), ('Restarts and commands', 'c'), ('Refused only', 'r')]:
            self.wf.addItem(t, k)
        row.addWidget(self.wf)
        self.wq = QLineEdit()
        self.wq.setPlaceholderText('Search address, point or value')
        self.wq.setClearButtonEnabled(True)
        self.wq.setMaximumWidth(320)
        row.addWidget(self.wq)
        row.addStretch(1)
        v.addLayout(row)
        self.tbl = Table(['Time', 'From', 'To', 'Action', 'Point', 'New value', 'Priority', 'Result'])
        self.tbl.rowActivated.connect(self.go)
        v.addWidget(self.tbl, 1)
        self.more = hint('')
        v.addWidget(self.more)
        self.wf.currentIndexChanged.connect(self.refresh)
        self.wq.textChanged.connect(self.refresh)

    def rows(self):
        L = self.win.FD.wr or []
        WF = self.wf.currentData()
        WQ = self.wq.text().lower()
        R = [w for w in L if WF == 'all' or (WF == 'w' and w['sev'] == 0) or (WF == 'c' and w['sev'] >= 1) or
             (WF == 'r' and re.match(r'^(failed|rejected|cancelled)', w['res']))]
        if WQ:
            R = [w for w in R if WQ in f"{w['from']} {w['to']} {w['obj']} {w['prop']} {w['val']} {w['svc']}".lower()]
        return R

    def refresh(self):
        win = self.win
        L = win.FD.wr or []
        while self.top.count():
            w = self.top.takeAt(0).widget()
            if w:
                w.setParent(None)                   # hide it now, not when Qt gets round to deleting it
                w.deleteLater()
        cmd = sum(1 for w in L if w['sev'] >= 1)
        rf = sum(1 for w in L if re.match(r'^(failed|rejected|cancelled)', w['res']))
        pills = []
        if L:
            pills.append((C.pl(len(L), 'request'), 'NOTE'))
        if cmd:
            pills.append((C.pl(cmd, 'command'), 'WARNING'))
        if rf:
            pills.append((f'{rf} refused', 'SERIOUS'))
        self.top.addWidget(summary_row('Writes and commands' if L else 'No writes or commands in this capture', pills))
        km = C.kid_map(win.FD)
        c = colors()
        R = self.rows()
        rows, data = [], []
        for w in R[:3000]:
            bad = re.match(r'^(failed|rejected|cancelled)', w['res'])
            res = w['res'] or 'no answer seen'
            rows.append([rel(win, w['t']), who(win, w['from'], km), who(win, w['to'], km), w['svc'], (w['obj'] + ' ' + w['prop']).strip(),
                         (w['val'], {'bold': True}) if w['sev'] else w['val'], '' if w['pri'] is None else w['pri'],
                         (res, {'fg': c['se'] if bad else c['no'] if res == 'accepted' else c['mu'], 'bold': bool(bad)})])
            data.append(f"no == {w['no']}")
        self.tbl.fill(rows, data)
        self.more.setText('Showing the first 3,000. Save as a spreadsheet for the full list.' if len(R) > 3000 else '')
        self._stale = False

    def formats(self):
        w = self.win

        def html():
            rows = [[rel(w, x['t']), esc(x['from']), esc(x['to']), esc(x['svc']), esc((x['obj'] + ' ' + x['prop']).strip()),
                     esc(x['val']), '' if x['pri'] is None else x['pri'], esc(x['res'] or 'no answer seen')] for x in self.rows()]
            return html_table(['Time', 'From', 'To', 'Action', 'Point', 'New value', 'Priority', 'Result'], rows)

        def csv():
            return csv_text('Time (s),Packet,From,To,Action,Point,Property,New value,Priority,Result',
                            [[C.tofixed(x['t'] - w.T0, 3), x['no'], x['from'], x['to'], x['svc'], x['obj'], x['prop'], x['val'],
                              '' if x['pri'] is None else x['pri'], x['res'] or 'no answer seen'] for x in (w.FD.wr or [])])
        return PageView.savef(self, 'Changes', html, csv)


# ================================================================ traffic --
class TrafficView(PageView):
    key, title = 't', 'Traffic'

    def data(self):
        F = self.win.FD
        tf = sorted((F.tf or {}).items(), key=lambda x: -x[1]['n'])
        pr = sorted([{**e, 'iv': (e['l'] - e['f']) / (e['n'] - 1)} for e in (F.pairs or []) if e['n'] >= 5], key=lambda e: e['iv'])[:25]
        cv = sorted([{**e, 'rate': e['n'] / max(1, e['l'] - e['f'])} for e in (F.covs or [])], key=lambda e: -e['n'])[:15]
        return tf, pr, cv

    def build(self, p):
        win = self.win
        tf, pr, cv = self.data()
        tot = len(win.P) or 1
        km = C.kid_map(win.FD)
        c = colors()
        p.add(summary_row('Traffic', [(C.pl(len(tf), 'sender'), 'NOTE'), (f'{C.locale_int(len(win.P))} packets', 'NOTE')]))
        p.add(hint('Who is sending the most, who is asking whom for what, and which points send the most change-of-value (COV) '
                   'notifications. Double-click a row to see its packets.'))
        p.add(heading('Busiest senders'))
        if tf:
            self.table(p, ['Sender', 'Packets', 'Share', 'Bytes', 'Requests sent', 'Broadcasts', 'COV sent'],
                       [[who(win, k, km), (C.locale_int(e['n']), {'num': 1}), (C.tofixed(100 * e['n'] / tot, 1) + '%', {'num': 1}),
                         (C.locale_int(e['b']), {'num': 1}), (C.locale_int(e['rq']) if e['rq'] else '', {'num': 1}),
                         (C.locale_int(e['bc']) if e['bc'] else '', {'num': 1}), (C.locale_int(e['cov']) if e['cov'] else '', {'num': 1})]
                        for k, e in tf[:30]], [f'host == "{k}"' for k, _ in tf[:30]])
        else:
            p.add(hint('No traffic.'))
        p.add(heading('Who asks whom, and how often'))
        if pr:
            self.table(p, ['From', 'To', 'Request', 'Times', 'Repeats every'],
                       [[who(win, e['from'], km), who(win, e['to'], km), e['sig'], C.locale_int(e['n']),
                         (f"{C.jsround(e['iv'] * 1000)} ms" if e['iv'] < 1 else f"{C.tofixed(e['iv'], 1)} s",
                          {'fg': c['se'], 'bold': True} if e['iv'] <= .5 else {})] for e in pr],
                       [f'from == "{e["from"]}" && to == "{e["to"]}"' for e in pr])
            p.add(hint('Fastest repeating requests first. Anything under a second is usually a screen, graphic or trend polling too fast.'))
        else:
            p.add(hint('No request is repeated at least 5 times.'))
        p.add(heading('Change-of-value (COV) notifications'))
        if cv:
            self.table(p, ['Sent by', 'Point', 'Count', 'Rate'],
                       [[who(win, e['from'], km), e['obj'], C.locale_int(e['n']),
                         (f"{C.tofixed(e['rate'], 1)} / s", {'fg': c['se'], 'bold': True} if e['rate'] >= 2 else {})] for e in cv],
                       [f'host == "{e["from"]}" && info contains "COV"' for e in cv])
        else:
            p.add(hint('No COV notifications in this capture.'))

    def formats(self):
        w = self.win

        def html():
            tf, pr, cv = self.data()
            tot = len(w.P) or 1
            return ('<h3>Busiest senders</h3>' + html_table(['Sender', 'Packets', 'Share', 'Bytes', 'Requests sent', 'Broadcasts', 'COV sent'],
                    [[esc(k), e['n'], C.tofixed(100 * e['n'] / tot, 1) + '%', e['b'], e['rq'] or '', e['bc'] or '', e['cov'] or ''] for k, e in tf[:30]]) +
                    '<h3>Who asks whom, and how often</h3>' + html_table(['From', 'To', 'Request', 'Times', 'Repeats every'],
                    [[esc(e['from']), esc(e['to']), esc(e['sig']), e['n'], C.tofixed(e['iv'], 2) + ' s'] for e in pr]) +
                    '<h3>COV notifications</h3>' + html_table(['Sent by', 'Point', 'Count', 'Rate'],
                    [[esc(e['from']), esc(e['obj']), e['n'], C.tofixed(e['rate'], 1) + ' / s'] for e in cv]))

        def csv():
            F = w.FD
            o = []
            for k, e in sorted((F.tf or {}).items(), key=lambda x: -x[1]['n']):
                o.append(['Sender', k, '', f"packets {e['n']}, requests {e['rq']}, broadcasts {e['bc']}, COV {e['cov']}", e['n'],
                          C.tofixed(100 * e['n'] / (len(w.P) or 1), 1) + '%'])
            for e in F.pairs or []:
                if e['n'] >= 5:
                    o.append(['Request', e['from'], e['to'], e['sig'], e['n'], C.tofixed((e['l'] - e['f']) / (e['n'] - 1), 2) + ' s'])
            for e in F.covs or []:
                o.append(['COV', e['from'], '', e['obj'], e['n'], C.tofixed(e['n'] / max(1, e['l'] - e['f']), 1) + '/s'])
            return csv_text('Section,Sender / From,To,What,Count,Share or interval', o)
        return self.savef('Traffic', html, csv)


# ========================================================= response times --
class ResponseView(PageView):
    key, title = 's', 'Response times & errors'

    def build(self, p):
        win = self.win
        L = win.FD.sl or []
        bad = sum(1 for e in L if e['slow'] or e['silent'])
        pills = []
        if bad:
            pills.append((f"{C.pl(bad, 'device')} to check", 'WARNING'))
        pills.append((f"{C.pl(len(L), 'device')} measured", 'NOTE'))
        p.add(summary_row('No request / answer pairs found' if not L else 'Some devices are slow or silent' if bad else
                          'Everything answered promptly', pills))
        p.add(hint('Each request is matched to its answer (same two devices, same request number) and the wait is measured. '
                   'Controllers usually answer in well under half a second; a typical time over 1 second, or many unanswered '
                   'requests, points to an overloaded device or a poor connection. Double-click a row to see its packets.'))
        c = colors()
        if L:
            rows = []
            for e in L:
                verdict = ('slow and silent' if e['slow'] and e['silent'] else 'slow' if e['slow'] else 'often silent' if e['silent'] else 'fine')
                rows.append([', '.join(win.labels.lz(f'Device {i}') for i in e['ids']) or ('not announced in this capture', {'fg': c['mu']}),
                             e['key'], e['n'], e['miss'] or '', C.fmt_ms(e['med']) if e['n'] else '', C.fmt_ms(e['p95']) if e['n'] else '',
                             (C.fmt_ms(e['max']) + (f" ({e['w']['svc']})" if e['w'] else '')) if e['n'] else '',
                             (verdict, {'fg': c['wa'] if verdict != 'fine' else c['mu'], 'bold': verdict != 'fine'})])
            self.table(p, ['Device', 'Address', 'Requests answered', 'No answer', 'Typical', 'Slowest 5%', 'Worst', ''], rows,
                       [f'host == "{e["key"]}"' for e in L])
        else:
            p.add(hint('This capture has no confirmed requests (such as Read Property) with answers. Capture while a front-end or tool is polling the devices.'))
        E = win.FD.er or []
        if E:
            km = C.kid_map(win.FD)
            p.add(heading('Errors, refusals and cancelled requests'))
            p.add(hint('Devices that answered a request with an error, a reject or an abort — with the likely cause and what to do. Double-click a row to see its packets.'))
            t = self.table(p, ['Device', 'What the device said', 'Times', 'Requests affected', 'What it means / what to do'],
                           [[who(win, e['who'], km), (e['why'], {'fg': c['mu'] if e['k'] == 'error' else c['se'], 'bold': e['k'] != 'error'}),
                             e['n'], ', '.join(map(str, e['svc'])), e['fix']] for e in E],
                           [f'host == "{e["who"]}" && error' for e in E])
            t.setWordWrap(True)
            t.resizeRowsToContents()
            t.fit_height()

    def formats(self):
        w = self.win

        def html():
            L = w.FD.sl or []
            return html_table(['Device', 'Address', 'Answered', 'No answer', 'Typical', 'Slowest 5%', 'Worst', ''],
                              [[', '.join(f'Device {i}' for i in e['ids']), esc(e['key']), e['n'], e['miss'] or '',
                                C.fmt_ms(e['med']) if e['n'] else '', C.fmt_ms(e['p95']) if e['n'] else '', C.fmt_ms(e['max']) if e['n'] else '',
                                'slow and silent' if e['slow'] and e['silent'] else 'slow' if e['slow'] else 'often silent' if e['silent'] else 'fine'] for e in L])

        def csv():
            return csv_text('Device ID,Address,Answered,No answer,Typical (ms),Average (ms),Slowest 5% (ms),Worst (ms),Worst service,Verdict',
                            [[' '.join(map(str, e['ids'])), e['key'], e['n'], e['miss'], C.jsround(e['med']), C.jsround(e['avg']),
                              C.jsround(e['p95']), C.jsround(e['max']), e['w']['svc'] if e['w'] else '',
                              'slow and silent' if e['slow'] and e['silent'] else 'slow' if e['slow'] else 'often silent' if e['silent'] else 'fine']
                             for e in (w.FD.sl or [])])
        return self.savef('Response times', html, csv)


# ============================================================ online board --
class OnlineView(PageView):
    key, title = 'o', 'Online board'

    def build(self, p):
        win = self.win
        live = bool(win.ac and win.ac.live and win.run)
        R = C.online_rows(win.FD, live)
        c = {'on': 0, 'sil': 0, 'few': 0, 'quiet': 0}
        for r in R:
            c[r['st']] += 1
        pills = [(f"{c['on']} online", 'NOTE')]
        if c['sil']:
            pills.append((f"{c['sil']} silent", 'SERIOUS'))
        if c['quiet']:
            pills.append((f"{c['quiet']} announced but never heard again", 'WARNING'))
        p.add(summary_row('Nothing heard yet' if not R else f"{C.pl(c['sil'], 'device')} gone silent" if c['sil'] else 'Everyone is talking', pills))
        p.add(hint('A device counts as online while it keeps sending within about 6 times its usual rhythm (at least 60 '
                   'seconds). A device that was active and then stopped is silent. ' +
                   ('This updates live.' if live else 'For a saved capture, “silent” means it stopped talking before the end of the capture.')))
        box = QWidget()
        cfg = win.watch_cfg()
        boxes = [label('Alert me when', bold=True, wrap=False)]
        for k, t in [('dev', 'a new device appears'), ('sil', 'a device goes silent'), ('prob', 'a new problem is found'),
                     ('busy', 'a router says it is busy'), ('snd', 'play a sound'), ('ntf', 'desktop notification')]:
            cb = QCheckBox(t)
            cb.setChecked(bool(cfg[k]))
            cb.toggled.connect(lambda on, k=k: self.set_cfg(k, on))
            boxes.append(cb)
        box.deleteLater()
        p.add(flow_row(boxes, 14, 4))
        p.add(hint('Alerts work while a live capture is running (the first 15 seconds only learn what is on the network).'))
        if win.ALR:
            p.add(heading('Alerts'))
            t = QPlainTextEdit('\n'.join(f"{time.strftime('%H:%M:%S', time.localtime(a['t']))}  {a['m']}" for a in reversed(win.ALR[-100:])))
            t.setReadOnly(True)
            t.setMaximumHeight(200)
            p.add(t)
        if R:
            col = colors()
            st = {'on': ('● Online', col['no']), 'sil': ('● Silent', col['se']), 'few': ('Too little traffic to judge', col['mu']),
                  'quiet': ('Announced, never heard again', col['mu'])}

            def tm(t):
                return time.strftime('%H:%M:%S', time.localtime(t)) if live else rel(win, t)
            self.table(p, ['Status', 'Device', 'Packets sent', 'First heard', 'Last heard', 'Usual rhythm', 'Silent for'],
                       [[(st[r['st']][0], {'fg': st[r['st']][1], 'bold': r['st'] == 'sil'}), who(win, r['k']), C.locale_int(r['n']),
                         tm(r['f']) if r['n'] else '', tm(r['l']) if r['n'] else '', 'every ' + C.gap(r['gp']) if r['gp'] else '',
                         C.gap(r['si']) if r['n'] and r['si'] >= 1 else ''] for r in R],
                       [f'host == "{r["k"]}"' for r in R])

    def set_cfg(self, k, on):
        cfg = self.win.watch_cfg()
        cfg[k] = 1 if on else 0
        self.win.store.set('bi_watch', cfg)

    def formats(self):
        w = self.win

        def rows():
            return C.online_rows(w.FD, bool(w.ac and w.ac.live and w.run))

        def html():
            return html_table(['Status', 'Address', 'Device IDs', 'Packets sent', 'Usual rhythm', 'Silent for'],
                              [[r['st'], esc(r['k']), ' '.join(map(str, r['ids'])), r['n'], C.gap(r['gp']) if r['gp'] else '',
                                C.gap(r['si']) if r['n'] else ''] for r in rows()])

        def csv():
            return csv_text('Status,Address,Device IDs,Packets sent,First heard (s),Last heard (s),Usual rhythm (s),Silent for (s)',
                            [[r['st'], r['k'], ' '.join(map(str, r['ids'])), r['n'], C.tofixed(r['f'] - w.T0, 1) if r['n'] else '',
                              C.tofixed(r['l'] - w.T0, 1) if r['n'] else '', C.tofixed(r['gp'], 1) if r['gp'] else '',
                              C.tofixed(r['si'], 0) if r['n'] else ''] for r in rows()])
        return self.savef('Online board', html, csv)


# ============================================================ network map --
def map_svg(win, dark=None):
    """The network map as SVG text plus clickable regions [(QRectF, filter, tooltip)]."""
    F = win.FD
    T = C.map_model(F)
    nmv = F.nm or {}
    gs = sorted(T, key=lambda g: (g == '', g))
    if not gs:
        return '', [], 0, 0
    dk = is_dark() if dark is None else dark
    Cc = ({'bg': '#1c1c1e', 'gF': '#12301e', 'gS': '#30d158', 'gT': '#6ee7a0', 'rF': '#14213d', 'rS': '#5b9bff', 'rT': '#8ab4ff',
           'nF': '#3a2a10', 'nS': '#ff9f0a', 'nT': '#ffb340', 'dF': '#12301e', 'dS': '#30d158', 'dT': '#e6f7ec', 'd2': '#9fc3ad',
           'mu': '#a1a1aa', 'l1': '#636a76', 'l2': '#4a515c'} if dk else
          {'bg': '#fff', 'gF': '#e6f6ec', 'gS': '#16a34a', 'gT': '#15803d', 'rF': '#e8f0fe', 'rS': '#2563eb', 'rT': '#1d4ed8',
           'nF': '#fff7e6', 'nS': '#d97706', 'nT': '#b45309', 'dF': '#e6f6ec', 'dS': '#16a34a', 'dT': '#14532d', 'd2': '#4b6b57',
           'mu': '#4b5b6b', 'l1': '#94a3b8', 'l2': '#cbd5e1'})
    fms = {}

    def mw(t, b=False, z=12):
        k = (b, z)
        if k not in fms:
            f = QFont('Segoe UI')
            f.setPixelSize(z)
            f.setBold(b)
            fms[k] = QFontMetricsF(f)
        return fms[k].horizontalAdvance(str(t)) + 3

    def fit(t, mx, b=False, z=12):
        t = str(t)
        if mw(t, b, z) <= mx:
            return t
        while len(t) > 1 and mw(t + '…', b, z) > mx:
            t = t[:-1]
        return t + '…'

    def hip(a):
        return re.sub(r':\d+$', '', str(a or ''))

    def gidL(g):
        if not g:
            return []
        m = {}
        for d in F.dv or []:
            if hip(d['key']) == hip(g) and d['id'] is not None:
                m[d['id']] = (nmv.get(d['id']) or {}).get('name', '')
        for e in list(win.explorer.devs.values()):
            if hip(e.get('ip')) == hip(g) and e.get('id') is not None and e['id'] not in m:
                m[e['id']] = e.get('name') or ''
        a = [f'Device {i}' + (f' · {dev_name(n, i)}' if dev_name(n, i) else '') for i, n in m.items()]
        return a[:3] + [f'+ {len(a) - 3} more'] if len(a) > 3 else a

    def dl(d):
        m = nmv.get(d['id']) or {}
        vn = m.get('vendor') or VN.get(d['v']) or ''
        addr = hip(d['key']) if d['sn'] is None else re.sub(r'^(\d)', r'MAC \1', str(d['sa'] if d['sa'] is not None else 'network ' + str(d['sn'])))
        return [f"Device {d['id']} · {addr}", ' · '.join(x for x in [dev_name(m.get('name'), d['id']), vn] if x)]
    dmax = gmax = 0
    for g in gs:
        for n in T[g]:
            for d in T[g][n].values():
                l = dl(d)
                dmax = max(dmax, mw(l[0]), mw(l[1], False, 11))
        cand = [mw('Router / gateway' if g else 'This network', True), mw(g or 'directly connected')] + [mw(x, True) for x in gidL(g)]
        if g and not gidL(g):
            cand.append(mw('Device ID: not seen (no I-Am)'))
        gmax = max([gmax] + cand)
    X0 = 20
    GW = min(340, max(210, math.ceil(gmax) + 26))
    NW = 170
    DW = min(380, max(190, math.ceil(dmax) + 20))
    DH, GAP = 40, 14
    y = 20
    out, lines, regs = [], [], []

    def tx(x, y, t, c, b=False, z=None):
        return f'<text x="{x}" y="{y}" {"font-weight=\"700\" " if b else ""}{f"font-size=\"{z}\" " if z else ""}fill="{c}">{esc(t)}</text>'
    for g in gs:
        nets = sorted(T[g], key=lambda a: (isinstance(a, str), a if not isinstance(a, str) else 0))
        gy0 = y
        rows = []
        for n in nets:
            ds = sorted(T[g][n].values(), key=lambda d: d['id'])
            hgt = max(1, len(ds)) * DH
            rows.append({'n': n, 'ds': ds, 'y': y, 'h': hgt})
            y += hgt + GAP
        gh = y - GAP - gy0
        gcy = gy0 + gh / 2
        gl = (gidL(g) or ['Device ID: not seen (no I-Am)']) if g else []
        bh = 30 + 15 * (1 + len(gl)) if g else 44
        by = gcy - bh / 2
        tw = GW - 20
        gf = f'gateway == "{g}" || host == "{g}"' if g else '!gateway'
        regs.append((QRectF(X0, by, GW, bh), gf, '\n'.join([g] + gl) if g else 'This network – directly connected'))
        out.append(f'<g><rect x="{X0}" y="{by}" width="{GW}" height="{bh}" rx="8" fill="{Cc["rF"] if g else Cc["gF"]}" stroke="{Cc["rS"] if g else Cc["gS"]}"/>'
                   + tx(X0 + 10, by + 19, 'Router / gateway' if g else 'This network', Cc['rT'] if g else Cc['gT'], True)
                   + tx(X0 + 10, by + (34 if g else 35), fit(g or 'directly connected', tw), Cc['mu'])
                   + (''.join(tx(X0 + 10, by + 49 + i * 15, fit(t, tw, True), Cc['rT'], t.startswith('Device')) for i, t in enumerate(gl)) if g else '')
                   + '</g>')
        for r in rows:
            ny = r['y'] + r['h'] / 2
            nx = X0 + GW + 60
            lines.append(f'<path d="M{X0 + GW},{gcy} C{X0 + GW + 30},{gcy} {nx - 30},{ny} {nx},{ny}" fill="none" stroke="{Cc["l1"]}"/>')
            if g:
                sub = (f"{len(r['ds'])} device{'s' if len(r['ds']) > 1 else ''}" if r['ds'] else
                       'no devices seen' if ((F.via or {}).get(r['n']) or {}).get(g) else 'announced only')
                nf = f'net == {r["n"]} && gateway == "{g}" || dnet == {r["n"]} && gateway == "{g}" || reach == {r["n"]} && announcer == "{g}"'
                regs.append((QRectF(nx, ny - 18, NW, 36), nf, f'Network {r["n"]}'))
                out.append(f'<g><rect x="{nx}" y="{ny - 18}" width="{NW}" height="36" rx="18" fill="{Cc["nF"]}" stroke="{Cc["nS"]}"/>'
                           + tx(nx + 14, ny - 2, f'Network {r["n"]}', Cc['nT'], True) + tx(nx + 14, ny + 12, sub, Cc['mu']) + '</g>')
            dx = nx + NW + 50 if g else nx
            for i, d in enumerate(r['ds']):
                dy = r['y'] + i * DH + DH / 2
                l = dl(d)
                sx, sy = (nx + NW, ny) if g else (X0 + GW, gcy)
                lines.append(f'<path d="M{sx},{sy} C{dx - 25},{sy} {dx - 25},{dy} {dx},{dy}" fill="none" stroke="{Cc["l2"]}"/>')
                regs.append((QRectF(dx, dy - 16, DW, 32), f'host == "{d["key"]}"', l[0] + ('\n' + l[1] if l[1] else '') + '\n' + d['key']))
                out.append(f'<g><rect x="{dx}" y="{dy - 16}" width="{DW}" height="32" rx="6" fill="{Cc["dF"]}" stroke="{Cc["dS"]}"/>'
                           + tx(dx + 8, dy - 2, fit(l[0], DW - 16, True), Cc['dT'], True)
                           + (tx(dx + 8, dy + 11, fit(l[1], DW - 16, False, 11), Cc['d2'], False, 11) if l[1] else '') + '</g>')
    W = X0 + GW + 60 + NW + 50 + DW + 20
    H = y + 10
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
           f'font-family="\'Segoe UI\',Arial,sans-serif" font-size="12"><rect width="100%" height="100%" fill="{Cc["bg"]}"/>'
           + ''.join(lines) + ''.join(out) + '</svg>')
    return svg, regs, W, H


class MapCanvas(QWidget):
    def __init__(self, view):
        super().__init__()
        self.view = view
        self.svg = ''
        self.regs = []
        self.r = None
        self.setMouseTracking(True)

    def set_svg(self, svg, regs, W, H):
        self.svg, self.regs = svg, regs
        self.r = QSvgRenderer(QByteArray(svg.encode('utf-8'))) if svg else None
        self.setFixedSize(int(W), int(H))
        self.update()

    def paintEvent(self, _e):
        if self.r:
            p = QPainter(self)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            self.r.render(p, QRectF(0, 0, self.width(), self.height()))
            p.end()

    def _hit(self, pos):
        for rc, f, tip in reversed(self.regs):
            if rc.contains(QPointF(pos)):
                return f, tip
        return None, None

    def mouseMoveEvent(self, e):
        f, tip = self._hit(e.position())
        self.setCursor(Qt.CursorShape.PointingHandCursor if f else Qt.CursorShape.ArrowCursor)
        self.setToolTip(tip or '')

    def mousePressEvent(self, e):
        f, _ = self._hit(e.position())
        if f:
            self.view.go(f)


class MapView(BaseView):
    key, title = 'g', 'Network map'

    def __init__(self, win):
        super().__init__(win)
        v = QVBoxLayout(self)
        v.setContentsMargins(18, 14, 18, 10)
        v.addWidget(summary_row('Network map', []))
        v.addWidget(hint('Routers, the networks behind them and the devices on each network, drawn from what was seen in this '
                         'capture. Click a box to see its packets. A network marked “announced only” was listed by a router '
                         '(in its list of reachable networks) but nobody on it sent anything in this capture; clicking it shows the '
                         'router’s announcement. Use File ▸ Save As for a picture (PNG or SVG) or web page.'))
        self.sa = QScrollArea()
        self.sa.setWidgetResizable(False)
        self.canvas = MapCanvas(self)
        self.sa.setWidget(self.canvas)
        v.addWidget(self.sa, 1)
        self.empty = hint('No devices or routers seen yet.')
        v.addWidget(self.empty)

    def refresh(self):
        svg, regs, W, H = map_svg(self.win)
        self.canvas.set_svg(svg, regs, W, H)
        self.sa.setVisible(bool(svg))
        self.empty.setVisible(not svg)
        self._stale = False

    def formats(self):
        w = self.win

        def png():
            svg, _r, W, H = map_svg(w, False)
            if not svg:
                raise ValueError('the map is empty')
            img = QImage(int(W * 2), int(H * 2), QImage.Format.Format_ARGB32)
            img.fill(QColor('white'))
            p = QPainter(img)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            QSvgRenderer(QByteArray(svg.encode('utf-8'))).render(p, QRectF(0, 0, W * 2, H * 2))
            p.end()
            ba = QByteArray()
            from PySide6.QtCore import QBuffer
            buf = QBuffer(ba)
            buf.open(QBuffer.OpenModeFlag.WriteOnly)
            img.save(buf, 'PNG')
            return bytes(ba)
        n = w.ac.n if w.ac else ''
        return [('png', 'Picture – the map as an image (*.png)', 'png', png),
                ('svg', 'Vector drawing – scalable, opens in Visio/Inkscape/browsers (*.svg)', 'svg', lambda: map_svg(w, False)[0]),
                ('html', 'Web page – the map as shown (*.html)', 'html',
                 lambda: doc('Network map – ' + n, f'<h3>{esc(n)} – network map</h3><p class="mu">Saved {stamp()}</p>{map_svg(w, False)[0]}'))]


# ====================================================== available IDs/nets --
def tile(big, title, small, go=False):
    f = QFrame()
    c = colors()
    col = c['no'] if go else c['fg']
    f.setObjectName('tile')
    f.setStyleSheet(f"QFrame#tile{{background:{'rgba(36,138,61,0.12)' if go else c['hd']};border:1px solid {c['bd']};border-radius:10px}}")
    v = QVBoxLayout(f)
    v.setContentsMargins(14, 10, 14, 10)
    v.setSpacing(1)
    b = label(str(big), bold=True, size=20, wrap=False)
    b.setStyleSheet(f'color:{col}')
    v.addWidget(b)
    v.addWidget(label(title, bold=True))
    v.addWidget(label(small, muted=True))
    return f


def tiles(items):
    w = QWidget()
    g = QGridLayout(w)
    g.setContentsMargins(0, 0, 0, 0)
    g.setSpacing(10)
    for i, t in enumerate(items):
        g.addWidget(t, 0, i)
    return w


def card():
    f = QFrame()
    f.setObjectName('card')
    f.setStyleSheet(f"QFrame#card{{border:1px solid {colors()['bd']};border-radius:10px}}")
    v = QVBoxLayout(f)
    v.setContentsMargins(14, 12, 14, 12)
    v.setSpacing(8)
    return f, v


def list_box(text, copy_fn, toast):
    """'Show as a list' expander with a Copy button."""
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(0, 0, 0, 0)
    row = QHBoxLayout()
    b = QToolButton(text='Show as a list ▾', checkable=True)
    row.addWidget(b)
    row.addStretch(1)
    if copy_fn:
        cp = QPushButton('Copy')
        cp.clicked.connect(lambda: (QApplication.clipboard().setText(copy_fn()), toast('Copied')))
        row.addWidget(cp)
    v.addLayout(row)
    t = QPlainTextEdit(text)
    t.setReadOnly(True)
    t.setMaximumHeight(160)
    t.setFont(QFont('Cascadia Mono', 9))
    t.hide()
    v.addWidget(t)
    b.toggled.connect(lambda on: (t.setVisible(on), b.setText('Show as a list ' + ('▴' if on else '▾'))))
    return w


def legend_row(items):
    """'square + explanation' items in a box; wraps onto more lines on narrow windows."""
    parts = []
    for txt, st, expl in items:
        it = QWidget()
        sub = QHBoxLayout(it)
        sub.setContentsMargins(0, 0, 0, 0)
        sub.setSpacing(6)
        g = CellGrid([(txt, st, '')], cols=1, cell_w=30)
        g.setFixedSize(30, 24)
        sub.addWidget(g)
        sub.addWidget(label(expl, wrap=False, muted=True))
        parts.append(it)
    w = flow_row(parts, 18, 6)
    w.layout().setContentsMargins(10, 6, 10, 6)
    w.setObjectName('leg')
    w.setStyleSheet(f"QWidget#leg{{border:1px solid {colors()['bd']};border-radius:8px}}")
    return w


class Settings(QWidget):
    """A collapsible 'Settings' box."""

    def __init__(self, title='Settings', open_=False):
        super().__init__()
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        self.btn = QToolButton(text=title + ' ▾', checkable=True)
        self.btn.setChecked(open_)
        f = self.btn.font()
        f.setBold(True)
        self.btn.setFont(f)
        v.addWidget(self.btn)
        self.body = QFrame()
        self.body.setObjectName('set')
        self.body.setStyleSheet(f"QFrame#set{{border:1px solid {colors()['bd']};border-radius:10px}}")
        self.grid = QGridLayout(self.body)
        self.grid.setContentsMargins(14, 10, 14, 10)
        self.grid.setHorizontalSpacing(18)
        v.addWidget(self.body)
        self.body.setVisible(open_)
        self.btn.toggled.connect(lambda on: (self.body.setVisible(on), self.btn.setText(title + (' ▴' if on else ' ▾'))))

    def field(self, r, c, title, w, small=''):
        box = QVBoxLayout()
        box.addWidget(label(title, bold=True))
        box.addWidget(w)
        if small:
            box.addWidget(label(small, muted=True))
        self.grid.addLayout(box, r, c)


def plan_all(win):
    """The available-IDs and available-networks plans for the current capture and settings."""
    st = win.store.get('bi_av2') or {}
    sn = win.store.get('bi_nv') or {}

    def gi(v, d):
        try:
            return int(str(v).strip())
        except ValueError:
            return d
    ds = gi(st.get('ds'), 2)
    lo = max(0, gi(st.get('lo'), 0))
    hi = max(lo, gi(st.get('hi'), 999999) or 999999)
    rd = C.parse_res(st.get('rs') or '')
    ln = gi(st.get('ln'), None) or None
    pn = gi(win._av_pn if hasattr(win, '_av_pn') else '', None) or None
    F = win.FD
    ids = {d['id'] for d in F.dv or []}
    P = C.dev_plan(F.dv or [], ids, rd, ln, pn, ds, lo, hi)
    nlo = max(0, gi(sn.get('lo'), 0))
    nhi = min(65534, max(nlo, gi(sn.get('hi'), 9999)))
    lnn = gi(st.get('ln'), None)
    seen = set(F.nets or set())
    if lnn is not None:
        seen.add(lnn)
    rsv = C.parse_res(sn.get('rn') or '')
    N = C.net_plan(seen, nlo, nhi, rsv, getattr(win, '_nvc', None))
    AF = C.all_free(ids, rd, P['rows'], P['mult'], lo, hi)
    return {'P': P, 'N': N, 'AF': AF, 'ids': ids, 'rd': rd, 'ln': ln, 'pn': pn, 'lo': lo, 'hi': hi, 'ds': ds, 'ea': bool(st.get('ea')),
            'nlo': nlo, 'nhi': nhi, 'seen': seen, 'rsv': rsv, 'nea': bool(sn.get('ea')), 'lnn': lnn}


class AvailIdsView(PageView):
    key, title = 'a', 'Available IDs'

    def build(self, p):
        win = self.win
        st = win.store.get('bi_av2') or {}
        p.add(label('Available device IDs', bold=True, size=16))
        p.add(label('Every device on a BACnet system needs its own unique number, its Device ID. This page shows which IDs are '
                    'already taken and which are still available, so you can pick a safe one for a new device.', muted=True))
        s = Settings('Settings', getattr(self, '_set_open', False))
        s.btn.toggled.connect(lambda on: setattr(self, '_set_open', on))
        ln = QLineEdit(st.get('ln') or '')
        ln.setPlaceholderText('optional')
        pn = QLineEdit(getattr(win, '_av_pn', ''))
        pn.setPlaceholderText('e.g. 2400')
        rs = QLineEdit(st.get('rs') or '')
        rs.setPlaceholderText('e.g. 240010-240019')
        s.field(0, 0, "Your own network's number", ln, 'Only needed for devices that are not behind a router. Leave blank if unsure.')
        s.field(0, 1, 'Plan a new device on network', pn, 'Type a network number to get the next free ID on it.')
        s.field(0, 2, 'Also treat as taken', rs, 'Device IDs you know are used but were not in the capture.')
        dg = QComboBox()
        dg.addItem('network × 100 + MAC (MAC 1–99)', 2)
        dg.addItem('network × 1000 + MAC (MAC 1–127)', 3)
        dg.setCurrentIndex(1 if str(st.get('ds')) == '3' else 0)
        ea = QCheckBox('List every ID instead of ranges')
        ea.setChecked(bool(st.get('ea')))
        imn = QLineEdit(str(st.get('lo') or '0'))
        imx = QLineEdit(str(st.get('hi') or '999999'))
        s.field(1, 0, 'Device ID scheme', dg)
        s.field(1, 1, 'Lowest device ID', imn)
        s.field(1, 2, 'Highest device ID', imx)
        s.grid.addWidget(ea, 2, 0)
        p.add(s)

        def save():
            win.store.set('bi_av2', {'ds': dg.currentData(), 'ea': ea.isChecked(), 'lo': imn.text(), 'hi': imx.text(),
                                     'ln': ln.text(), 'rs': rs.text()})
            win._av_pn = pn.text()
            self._t.start(350)
        if not hasattr(self, '_t'):
            self._t = QTimer(self, singleShot=True, timeout=self.refresh)
        for e in (ln, pn, rs, imn, imx):
            e.textEdited.connect(save)
        dg.currentIndexChanged.connect(save)
        ea.toggled.connect(save)
        A = plan_all(win)
        P, N, AF, ids = A['P'], A['N'], A['AF'], A['ids']
        mult, mx = P['mult'], P['mx']
        pr = P['rows']
        cols = 16 if mx > 99 else 10
        nv = N
        if A['pn']:
            newest = next((r for r in pr if r['net'] == A['pn']), None)
        elif nv and nv['main']:
            lst = [r for r in pr if nv['main']['lo'] <= r['net'] <= nv['main']['hi']]
            newest = lst[-1] if lst else None
        else:
            newest = None
        newest = newest or (pr[-1] if pr else None)
        nn = nv['nx'] if nv else None
        m1 = None if nn is None else next((m for m in range(1, mx + 1) if nn * mult + m not in ids), None)
        p.add(tiles([tile(len(ids), 'Device IDs taken', 'seen in this capture'),
                     tile(newest['id'] if newest and newest['id'] is not None else '–',
                          f"Add a device to network {newest['net']}" if newest else 'Add a device to a network',
                          (f"the next free ID on {'the network you typed' if A['pn'] else 'your newest network'} (MAC {newest['mac']})" if newest
                           else 'no devices seen yet, or type a network under Settings'), True),
                     tile(nn * mult + m1 if m1 is not None else '–', f'Start a new network: {nn}' if nn is not None else 'Start a new network',
                          (f'network {nn} is the next free number on the Available networks tab, so its first device is {nn} × {mult} + {m1}'
                           if nn is not None else 'no free network number'), True)]))
        p.add(label(f'Most sites build the ID from the network and the device\'s address: device ID = network number × {mult} + MAC '
                    f'address. For example network 2400, MAC 5 → {2400 * mult + 5}. The MAC is the MS/TP address, or the last '
                    f'number of the IP address. Allowed IDs: {A["lo"]}–{A["hi"]}.', muted=True))
        fmt = (lambda l: ', '.join(map(str, l))) if A['ea'] else (lambda l: ', '.join(C.ranges(l)))
        self.AVL = []
        if pr:
            p.add(legend_row([('5', 't', 'Taken – already in use'), ('6', 'f', 'Available – free to use'),
                              ('7', 'b', 'Blocked – that ID belongs to another device, or you marked it as taken'),
                              ('6', 'nx', 'Suggested – the next one to use')]))
            nmOf = lambda d: ((win.FD.nm or {}).get(d['id']) or {}).get('name') or win.labels.d(d['id'])  # noqa: E731
            for r in pr:
                mm = {C.MACOF(d['sa'] if d['sn'] is not None else d['key']): d for d in r['dv']}
                fs = set(r['free'])
                blocked = mx + 1 - len(r['used']) - len(r['free'])
                cells = []
                for m in range(0, mx + 1):
                    did = r['net'] * mult + m
                    d = mm.get(m)
                    if m in r['used']:
                        nmx = nmOf(d) if d else ''
                        cells.append((m, 't', f"MAC {m} – taken by device {d['id'] if d else did}{' “' + nmx + '”' if nmx else ''}"))
                    elif did in fs:
                        cells.append((m, 'nx' if m == r['mac'] else 'f', f"MAC {m} – available, device ID {did}{' (suggested next)' if m == r['mac'] else ''}"))
                    else:
                        cells.append((m, 'b', f'MAC {m} – blocked: device ID {did} is already used by another device, marked taken, or outside the allowed range'))
                fr, v = card()
                hd = QHBoxLayout()
                lab = win.labels.n(r['net'])
                left = QVBoxLayout()
                left.addWidget(label(f"Network {r['net']}" + (f' “{lab}”' if lab else ''), bold=True, size=11))
                left.addWidget(label(f"{len(r['used'])} taken · {len(r['free'])} available" + (f' · {blocked} blocked' if blocked > 0 else ''), muted=True))
                hd.addLayout(left, 1)
                right = QVBoxLayout()
                if r['id'] is not None:
                    right.addWidget(label('Next free ID', muted=True), 0, Qt.AlignmentFlag.AlignRight)
                    big = label(str(r['id']), bold=True, size=15, wrap=False, sel=True)
                    big.setStyleSheet(f"color:{colors()['no']}")
                    right.addWidget(big, 0, Qt.AlignmentFlag.AlignRight)
                else:
                    right.addWidget(label('No free ID left', muted=True))
                hd.addLayout(right)
                v.addLayout(hd)
                v.addWidget(CellGrid(cells, cols, max_width=640 if cols == 16 else 560))
                v.addWidget(label(f"Each square is a MAC address on this network (0–{mx}). Its device ID is {r['net']} × {mult} + the number in the square."
                                  + ('' if r['fit'] else ' This network number is too high for the chosen scheme.'), muted=True))
                txt = fmt(r['free']) if r['free'] else ''
                self.AVL.append(txt)
                v.addWidget(list_box(txt or 'none left', (lambda t=txt: t) if r['free'] else None, win.toast))
                p.add(fr)
            if len(pr) > 1:
                b = QPushButton('Copy all networks')
                b.clicked.connect(lambda: (QApplication.clipboard().setText(self.all_text(pr)), win.toast('Copied')))
                p.add(b)
        else:
            fr, v = card()
            un = P['un']
            v.addWidget(label(f'{len(un)} devices seen, but their network number is not known' if un else 'No devices seen on a network yet', bold=True))
            v.addWidget(label(('These devices are directly on your network, not behind a router, so the capture has no network number for '
                               'them. Type your own network\'s number under Settings above and they will be placed. ' if un else
                               'Capture for a minute (use Who-Is on the Live capture tab) so devices announce themselves. If your devices are '
                               'not behind a router, type your own network\'s number under Settings. ') +
                              'You can also type a network number under “Plan a new device” to see what would be free on it.', muted=True))
            p.add(fr)
        hi2 = min(A['hi'], 4194302)
        afl = (', '.join(str(n) for r0 in AF['r'] for n in range(r0[0], r0[1] + 1)) if A['ea'] and AF['n'] <= 5000 else
               ', '.join(str(a) if a == b else f'{a}–{b}' for a, b in AF['r']))
        self.AVG = afl
        fr, v = card()
        v.addWidget(label('Free device IDs anywhere', bold=True, size=11))
        v.addWidget(label(f"{C.locale_int(AF['n'])} available between {A['lo']} and {hi2}, including networks not seen in this capture", muted=True))
        v.addWidget(list_box(afl or 'none left', (lambda: afl) if AF['n'] else None, win.toast))
        if A['ea'] and AF['n'] > 5000:
            v.addWidget(label('Too many to list one by one, so ranges are shown.', muted=True))
        p.add(fr)
        if P['off']:
            fr, v = card()
            v.addWidget(label('Devices that do not follow the numbering', bold=True, size=11))
            v.addWidget(label(f"{C.pl(len(P['off']), 'device')} whose ID is not what the pattern would give. Worth a look, but not necessarily wrong.", muted=True))
            t = Table(['Device ID now', 'Network', 'MAC', 'Pattern says', ''])
            t.fill([[o['d']['id'], o['net'], o['mac'], o['exp'],
                     ('does not fit the pattern (MAC too large, or ID outside the allowed range)' if o['big'] else
                      '⚠ that ID is already used by another device' if o['clash'] else '')]
                    for o in sorted(P['off'], key=lambda o: (o['net'], o['mac']))])
            t.fit_height()
            v.addWidget(t)
            p.add(fr)
        elif pr:
            ok = label('✓ Every device with a network and MAC follows the numbering pattern.', bold=True)
            ok.setStyleSheet(f"color:{colors()['no']}")
            p.add(ok)
        if P['un'] and pr:
            un = P['un']
            p.add(hint(f"{C.pl(len(un), 'device')} could not be placed because the network number is not known (enter your own network's number under Settings): "
                       + ', '.join(str(d['id']) for d in un[:8]) + (', …' if len(un) > 8 else '')))
        p.add(hint('Devices that were silent during the capture are not counted. Capture a little longer, then check again before you give out an ID.'))

    def all_text(self, pr):
        return '\n'.join(f"Network {r['net']}: " + (self.AVL[i] if i < len(self.AVL) and self.AVL[i] else 'none') for i, r in enumerate(pr))

    def formats(self):
        w = self.win

        def html():
            A = plan_all(w)
            P = A['P']
            fmt = (lambda l: ', '.join(map(str, l))) if A['ea'] else (lambda l: ', '.join(C.ranges(l)))
            afl = ', '.join(str(a) if a == b else f'{a}–{b}' for a, b in A['AF']['r'])
            h = (f"<p class=\"mu\">Scheme: <b>device ID = network number × {P['mult']} + MAC address</b>. Allowed device IDs: "
                 f"{A['lo']}–{A['hi']}. Based on {len(A['ids'])} device IDs seen in this capture.</p>"
                 f"<h3>All available device IDs</h3><p><b>{A['lo']}–{min(A['hi'], 4194302)}</b> – {C.locale_int(A['AF']['n'])} available</p>"
                 f"<p class=\"mono\">{esc(afl or 'none left')}</p><h3>Available device IDs by network</h3>")
            for r in P['rows']:
                nxt = f" · next in sequence {r['id']}" if r['id'] is not None else ''
                h += (f"<p><b>Network {r['net']}</b> <span class=\"mu\">– {len(r['free'])} available (MAC 0–{P['mx']}), "
                      f"{len(r['used'])} in use{nxt}</span></p>"
                      f"<p class=\"mono\">{esc(fmt(r['free']) if r['free'] else 'none left')}</p>")
            if P['off']:
                h += '<h3>Devices that do not follow the scheme</h3>' + html_table(['Device ID now', 'Network', 'MAC', 'Scheme says', ''],
                    [[o['d']['id'], o['net'], o['mac'], o['exp'], 'does not fit' if o['big'] else 'ID already used' if o['clash'] else ''] for o in P['off']])
            n = w.ac.n if w.ac else ''
            return doc('Available device IDs – ' + n, f'<h3>{esc(n)} – available device IDs</h3><p class="mu">saved {stamp()}</p>{h}')

        def csv():
            A = plan_all(w)
            P = A['P']
            afl = ', '.join(str(a) if a == b else f'{a}–{b}' for a, b in A['AF']['r'])
            o = [['All available device IDs', '', '', '', '', '', '', '', afl]]
            for r in P['rows']:
                o.append(['Available device IDs', r['net'], '', '', ' '.join(C.ranges(r['used'])), r['hi'], '' if r['mac'] is None else r['mac'],
                          '' if r['id'] is None else r['id'], ' '.join(map(str, r['free']))])
            for x in P['off']:
                o.append(['Off scheme', x['net'], '', '', '', x['mac'], '', x['exp'],
                          f"now {x['d']['id']}{'; ID already used' if x['clash'] else ''}{'; does not fit' if x['big'] else ''}"])
            return '﻿' + csv_text('Type,Network,Block start,Block end,MACs in use,Highest,Next free MAC,Next ID,Available IDs / note', o)
        return [('html', 'Web page – the suggestions exactly as shown (*.html)', 'html', html),
                ('csv', 'Spreadsheet – one row per block, for Excel (*.csv)', 'csv', csv)]


class AvailNetsView(PageView):
    key, title = 'n', 'Available networks'

    def build(self, p):
        win = self.win
        sn = win.store.get('bi_nv') or {}
        p.add(label('Available network numbers', bold=True, size=16))
        p.add(label('Each separate BACnet network (a trunk of devices behind a router) needs its own unique network number. This page '
                    'shows which numbers are already taken and which are still available, so a new network does not clash with an existing one.', muted=True))
        s = Settings('Settings', getattr(self, '_set_open', False))
        s.btn.toggled.connect(lambda on: setattr(self, '_set_open', on))
        nmn = QLineEdit(str(sn.get('lo') or '0'))
        nmx = QLineEdit(str(sn.get('hi') or '9999'))
        rn = QLineEdit(sn.get('rn') or '')
        rn.setPlaceholderText('e.g. 2500-2510')
        nea = QCheckBox('List every number instead of ranges')
        nea.setChecked(bool(sn.get('ea')))
        s.field(0, 0, 'Lowest network number', nmn, 'Numbers below this are ignored.')
        s.field(0, 1, 'Highest network number', nmx, 'BACnet allows up to 65534.')
        s.field(0, 2, 'Also treat as taken', rn, 'Numbers you know are used but were not in the capture.')
        s.grid.addWidget(nea, 1, 0)
        p.add(s)
        if not hasattr(self, '_t'):
            self._t = QTimer(self, singleShot=True, timeout=self.refresh)

        def save():
            win.store.set('bi_nv', {'lo': nmn.text(), 'hi': nmx.text(), 'rn': rn.text(), 'ea': nea.isChecked()})
            self._t.start(350)
        for e in (nmn, nmx, rn):
            e.textEdited.connect(save)
        nea.toggled.connect(save)
        A = plan_all(win)
        N = A['N']
        lo, hi = A['nlo'], A['nhi']
        fmt = (lambda l: ', '.join(map(str, l))) if A['nea'] else (lambda l: ', '.join(C.ranges(l)))
        us, top = set(N['used']), N['main']['hi'] if N['main'] else None
        mult = A['P']['mult']
        p.add(tiles([tile(len(N['used']), f"Network number{'' if len(N['used']) == 1 else 's'} taken",
                          'seen in this capture' + (f" + {N['res']} you marked" if N['res'] else '')),
                     tile(C.locale_int(len(N['free'])), 'Available', f'of {C.locale_int(hi - lo + 1)} between {lo} and {hi}'),
                     tile(N['nx'] if N['nx'] is not None else '–', 'Next free network number',
                          ('none left in this range' if N['nx'] is None else 'nothing seen yet, so this is the first one' if top is None
                           else f"right after {top}, the top of your main group ({N['main']['lo']}–{top})") +
                          (f" · its first device ID would be {N['nx'] * mult + 1}" if N['nx'] is not None else ''), True)]))
        if len(N['cls']) > 1:
            g = QWidget()
            gl = QHBoxLayout(g)
            gl.setContentsMargins(0, 0, 0, 0)
            gl.addWidget(label(f"Your numbers fall into {len(N['cls'])} separate groups. The suggestion continues the group marked ✓ "
                               '(the biggest). Click another group to continue that one instead.', muted=True), 1)
            p.add(g)
            g2 = QWidget()
            gl2 = QHBoxLayout(g2)
            gl2.setContentsMargins(0, 0, 0, 0)
            for c in N['cls']:
                b = QPushButton(('✓ ' if c is N['main'] else '') + (str(c['lo']) if c['lo'] == c['hi'] else f"{c['lo']}–{c['hi']}")
                                + f"  ({C.pl(c['n'], 'network')})")
                b.setCheckable(True)
                b.setChecked(c is N['main'])
                b.clicked.connect(lambda _=False, lo_=c['lo']: (setattr(win, '_nvc', lo_), self.refresh(), win.view('a').refresh() if 'a' in win.views else None))
                gl2.addWidget(b)
            gl2.addStretch(1)
            p.add(g2)
        p.add(hint('A network only shows up here if the capture saw it: announced by a router, or used by a device that came through one. '
                   'A network whose router stayed silent can still exist, so capture a bit longer, use Who-Is-Router on the Live capture '
                   'tab, or add numbers you know under Settings.' + (f" Your own network {A['lnn']} is included." if A['lnn'] is not None else '')))
        if N['used'] or N['res']:
            p.add(legend_row([('01', 't', 'Taken – already in use'), ('07', 'f', 'Available – free to use'),
                              ('08', 'b', 'Blocked – you marked it as taken, but it was not seen'),
                              ('07', 'nx', 'Suggested – the next one to use')]))
            bl = sorted({(n // 100) * 100 for n in N['used']})
            SH = 12
            for b in bl[:SH]:
                used = 0
                cells = []
                for k in range(100):
                    n = b + k
                    if n < lo or n > hi or n > 65534:
                        cells.append((k, 'x', f'{n} – outside your range'))
                    elif n in us:
                        used += 1
                        cells.append((n % 100, 't', f'Network {n} – taken (seen in this capture)'))
                    elif n in A['rsv']:
                        cells.append((n % 100, 'b', f'Network {n} – you marked it as taken'))
                    else:
                        cells.append((n % 100, 'nx' if n == N['nx'] else 'f', f"Network {n} – available{' (suggested next)' if n == N['nx'] else ''}"))
                fr, v = card()
                v.addWidget(label(f'Networks {b}–{b + 99}', bold=True, size=11))
                v.addWidget(label(f'{used} taken · {100 - used} not seen', muted=True))
                v.addWidget(CellGrid(cells, 10))
                v.addWidget(label(f'Each square is one network number: {b} + the number in the square.', muted=True))
                p.add(fr)
            if len(bl) > SH:
                p.add(hint(f"{len(bl) - SH} more block{'' if len(bl) - SH == 1 else 's'} of numbers in use are not drawn here, see the lists below."))
        else:
            fr, v = card()
            v.addWidget(label('No network numbers seen yet', bold=True))
            v.addWidget(label('Everything in your range is free as far as this capture knows. Capture long enough to include router '
                              'announcements, or use Who-Is-Router on the Live capture tab.', muted=True))
            p.add(fr)
        NVL = fmt(N['free']) if N['free'] else ''
        fr, v = card()
        v.addWidget(label('Available numbers', bold=True, size=11))
        v.addWidget(label(f"{C.locale_int(len(N['free']))} free", muted=True))
        v.addWidget(list_box(NVL or 'none left', (lambda: NVL) if N['free'] else None, win.toast))
        p.add(fr)
        fr, v = card()
        v.addWidget(label('Taken numbers', bold=True, size=11))
        v.addWidget(label(f"{len(N['used'])}" + (f" + {N['res']} you marked" if N['res'] else ''), muted=True))
        v.addWidget(list_box(fmt(N['used']) if N['used'] else 'none seen', None, win.toast))
        p.add(fr)
        if N['outside']:
            p.add(hint(f"Also seen outside {lo}–{hi}: " + fmt(N['outside'])))
        if lo == 0:
            p.add(hint('Network number 0 is reserved in the BACnet standard. Set the lowest number to 1 under Settings to leave it out.'))

    def formats(self):
        w = self.win

        def html():
            A = plan_all(w)
            N = A['N']
            fmt = (lambda l: ', '.join(map(str, l))) if A['nea'] else (lambda l: ', '.join(C.ranges(l)))
            h = (f"<p class=\"mu\">Network numbers {A['nlo']}–{A['nhi']}. Based on {len(A['seen'])} network numbers seen in this capture.</p>" +
                 (f"<p>Next network number after the highest in use: <b>{N['nx']}</b></p>" if N['nx'] is not None else '') +
                 f"<h3>Available – {C.locale_int(len(N['free']))} of {C.locale_int(A['nhi'] - A['nlo'] + 1)} numbers</h3>"
                 f"<p class=\"mono\">{esc(fmt(N['free']) or 'none left')}</p><h3>In use – {len(N['used'])}</h3>"
                 f"<p class=\"mono\">{esc(fmt(N['used']) if N['used'] else 'none seen')}</p>")
            n = w.ac.n if w.ac else ''
            return doc('Available networks – ' + n, f'<h3>{esc(n)} – available network numbers</h3><p class="mu">saved {stamp()}</p>{h}')

        def csv():
            N = plan_all(w)['N']
            o = [['Available', a, b, b - a + 1] for a, b in C.rg(N['free'])] + [['In use', a, b, b - a + 1] for a, b in C.rg(N['used'])]
            return '﻿' + csv_text('Status,From,To,Count', o)
        return [('html', 'Web page – the available network numbers exactly as shown (*.html)', 'html', html),
                ('csv', 'Spreadsheet – one row per range, available and in use (*.csv)', 'csv', csv)]


# ============================================================= MS/TP trunk --
class MstpView(PageView):
    key, title = 'm', 'MS/TP trunk'

    def build(self, p):
        win = self.win
        T = win.FD.trk or []
        km = C.kid_map(win.FD)
        p.add(summary_row('MS/TP trunk', [(C.pl(len(T), 'trunk'), 'NOTE')] if T else []))
        p.add(hint('Which addresses are alive on the trunk, how long the token takes to go round, and which master holds it longest. '
                   'Needs MS/TP frames in the capture (use a serial adapter in Live capture).'))
        if not T:
            p.add(hint('No MS/TP frames in this capture.'))
        for t in T:
            nm = f"Trunk (capture interface {t['ifc'] + 1})" if len(T) > 1 else 'Trunk'
            dur = max(1, t['t1'] - t['t0'])
            pills = ([(C.pl(len(t['masters']), 'master'), 'NOTE'), (f"highest master: MAC {t['hi']}", 'NOTE')] if t['masters']
                     else [('no token passing seen', 'WARNING')])
            if t['rot']:
                pills.append((f"token lap {C.jsround(t['rot'] * 1000)} ms" if t['rot'] < 1 else f"token lap {C.tofixed(t['rot'], 2)} s",
                              'WARNING' if t['rot'] >= 1 else 'NOTE'))
            if t['dead']:
                pills.append((f"{len(t['dead'])} dead address{'' if len(t['dead']) == 1 else 'es'}", 'SERIOUS'))
            p.add(heading(nm, 13))
            row = summary_row('', pills)
            row.layout().addWidget(label(f"{C.locale_int(t['n'])} frames · {C.tofixed(t['n'] / dur, 1)} per second", muted=True, wrap=False))
            p.add(row)
            p.add(legend_row([('', 'master', 'master (passes the token)'), ('', 'slave', 'slave / answers only'),
                              ('', 'joining', 'joining (answered a poll)'), ('', 'dead', 'token offered, no answer'),
                              ('', 'polled', 'polled, nothing there')]))
            tip = {'master': 'Master', 'slave': 'Slave or answers only', 'joining': 'Joining the token ring',
                   'dead': 'Token offered but nothing answered', 'polled': 'Polled but nothing answered', '': 'Not seen'}
            cells = [(m, t['st'].get(m, ''), f"MAC {m}: {tip[t['st'].get(m, '')]}") for m in range(128)]
            g = CellGrid(cells, 16, cell_w=30)
            g.cell_h = 30
            p.add(g)
            sl = sorted(m for m in t['st'] if m > 127 and t['st'][m] == 'slave')
            if sl:
                p.add(hint('Slaves above MAC 127: ' + ', '.join(map(str, sl))))
            if not t['masters']:
                msg = ('No Token or Poll-For-Master frames were captured, so the masters (and the Max Master setting) cannot be '
                       'worked out. The capture probably only recorded data frames – for example a router’s own capture of '
                       'the trunk. Capture the trunk with a USB RS-485 adapter (Live capture) to see the token.')
            elif t['pfmMax'] > t['hi'] and t['pfmTotal']:
                msg = (f"Masters poll as far as MAC {t['pfmMax']} but the highest device is MAC {t['hi']}. " +
                       (f"Set Max Master = {t['hi']} on every master to stop {C.jsround(100 * t['waste'] / t['pfmTotal'])}% of the polling being wasted."
                        if t['waste'] and t['waste'] / t['pfmTotal'] >= .2 else 'That is a small amount of wasted polling.'))
            else:
                msg = f"The Max Master setting looks right: polling stops at the highest working device (MAC {t['hi']})."
            p.add(label(msg))
            if t['masters']:
                def ms(s):
                    return f'{C.jsround(s * 1000)} ms' if s else ''
                self.table(p, ['MAC', 'Device', 'Token passes', 'Data frames', 'Holds token (avg)', 'Holds token (longest)', 'Token returns every'],
                           [[(f"MAC {x['mac']}", {'bold': True}), ', '.join(win.labels.lz(f'Device {i}') for i in km.get(f"MS/TP MAC {x['mac']}", [])) or '–',
                             x['tok'], x['data'], ms(x['hold']), ms(x['holdMax']), ms(x['rot'])] for x in t['masters']],
                           [f'src == "MAC {x["mac"]}"' for x in t['masters']])

    def formats(self):
        w = self.win

        def rows():
            o = []
            for t in w.FD.trk or []:
                for m in sorted(t['st']):
                    x = next((q for q in t['masters'] if q['mac'] == m), None)
                    o.append([t['ifc'] + 1, m, t['st'][m], x['tok'] if x else '', x['data'] if x else '', C.jsround(x['hold'] * 1000) if x else '',
                              C.jsround(x['holdMax'] * 1000) if x else '', C.jsround(x['rot'] * 1000) if x else ''])
            return o
        return self.savef('MS/TP trunk', lambda: html_table(['Trunk', 'MAC', 'Role', 'Token passes', 'Data frames', 'Hold avg (ms)', 'Hold max (ms)', 'Token lap (ms)'], rows()),
                          lambda: csv_text('Trunk,MAC,Role,Token passes,Data frames,Hold avg (ms),Hold max (ms),Token lap (ms)', rows()))


# =============================================================== bus speed --
class BusSpeedView(PageView):
    key, title = 'b', 'Bus speed'

    def baudsel(self):
        try:
            return int(self.win.store.get('bi_baud') or 0)
        except ValueError:
            return 0

    def build(self, p):
        win = self.win
        S = win.FD.sp or {'m': [], 'ip': [], 'dur': 1}
        B = self.baudsel()
        p.add(summary_row('Bus speed', []))
        p.add(hint('A capture file does not record the speed the bus ran at, so MS/TP baud rates are estimated from the timing: a frame '
                   'cannot arrive sooner than the time it takes to send it. The estimate is reliable when the trunk was busy (frames close '
                   'together), and only a minimum when it was quiet. Use the box below if you know the real rate.'))
        row = QWidget()
        rl = QHBoxLayout(row)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(QLabel('MS/TP baud rate'))
        cb = QComboBox()
        cb.addItem('Automatic (estimate)', 0)
        for b in C.BAUDS:
            cb.addItem(str(b), b)
        cb.setCurrentIndex(max(0, cb.findData(B)))
        cb.currentIndexChanged.connect(lambda _i: (win.store.set('bi_baud', cb.currentData()), self.refresh()))
        rl.addWidget(cb)
        rl.addStretch(1)
        p.add(row)
        p.add(heading('MS/TP trunks'))
        c = colors()

        def pc(x):
            return f'{C.jsround(min(x, 9.99) * 100)}%'
        if not S['m']:
            p.add(hint('No MS/TP frames in this capture.'))
        else:
            rows = []
            for o in S['m']:
                b = B or (o['est'] if o['est'] and o['est'] > 0 else 0)
                u = C.util(o, b, S['dur']) if b else None
                dur = max(1, o['t1'] - o['t0'])
                if B:
                    bt = f'{B} (you set)'
                elif o['est'] and o['est'] > 0:
                    bt = f"{o['est']} estimated" if o['conf'] else f"{o['est']} or faster – too quiet to tell"
                elif o['est'] == -1:
                    bt = 'faster than 115200, or the capture timestamps are not accurate enough'
                else:
                    bt = 'not enough frames to estimate'
                sure = B or o['conf']
                full = u and sure and u['avg'] >= .5
                rows.append([o['name'], (bt, {'bold': bool(o['conf']) and not B}), C.locale_int(o['n']), C.tofixed(o['n'] / dur, 1),
                             (pc(u['avg']) + ('' if sure else ' (at least)'), {'fg': c['wa'], 'bold': True} if full else {}) if u else ('needs a baud rate', {'fg': c['mu']}),
                             pc(u['peak']) + ('' if sure else ' (at least)') if u else '',
                             f"{C.locale_int(o['bad'])} ({C.tofixed(100 * o['bad'] / o['n'], 1)}%)" if o['bad'] else ''])
            self.table(p, ['Trunk', 'Baud rate', 'Frames', 'Frames / second', 'Busy (average)', 'Busy (peak second)', 'Damaged'], rows)
            p.add(hint('“Busy” is the share of time the wire was in use. Under about 30% is comfortable; above 50% replies start to get slow.'))
        p.add(heading('IP and Ethernet ports'))
        if not S['ip']:
            p.add(hint('No IP or Ethernet traffic in this capture.'))
        else:
            self.table(p, ['Port', 'Packets', 'Average', 'Peak (1 second)', 'Broadcasts'],
                       [[o['k'], C.locale_int(o['n']), f"{C.tofixed(o['bytes'] * 8 / max(1, o['t1'] - o['t0']) / 1000, 1)} kbit/s",
                         f"{C.tofixed(max([0] + list(o['s'].values())) * 8 / 1000, 1)} kbit/s", f"{C.jsround(100 * o['bc'] / o['n'])}%"] for o in S['ip']])
            p.add(hint('The link speed of a network port is not stored in a capture file. For comparison: ordinary Ethernet runs at '
                       '100,000 kbit/s (100 Mbit/s) or 1,000,000 kbit/s (1 Gbit/s), so BACnet/IP traffic is rarely a problem by volume. '
                       'A high share of broadcasts is what to watch, because every device has to process each one.'))

    def formats(self):
        w = self.win

        def rows():
            S = w.FD.sp or {'m': [], 'ip': [], 'dur': 1}
            B = self.baudsel()
            o = []
            for t in S['m']:
                b = B or (t['est'] if t['est'] and t['est'] > 0 else 0)
                u = C.util(t, b, S['dur']) if b else None
                o.append(['MS/TP trunk', t['name'], b or '', 'set by you' if B else 'yes' if t['conf'] else 'no', t['n'],
                          C.tofixed(t['n'] / max(1, t['t1'] - t['t0']), 1), C.jsround(u['avg'] * 100) if u else '',
                          C.jsround(u['peak'] * 100) if u else '', '', ''])
            for t in S['ip']:
                o.append(['IP port', t['k'], '', '', t['n'], C.tofixed(t['bytes'] * 8 / max(1, t['t1'] - t['t0']) / 1000, 1), '', '',
                          C.tofixed(max([0] + list(t['s'].values())) * 8 / 1000, 1), C.jsround(100 * t['bc'] / t['n'])])
            return o
        hdr = 'Type,Name,Baud,Estimate confident,Frames/packets,Per second / avg kbit/s,Busy avg %,Busy peak %,Peak kbit/s,Broadcast %'
        return self.savef('Bus speed', lambda: html_table(hdr.split(','), rows()), lambda: csv_text(hdr, rows()))


# ================================================================= compare --
class CompareView(BaseView):
    key, title = 'c', 'Compare captures'

    def __init__(self, win):
        super().__init__(win)
        v = QVBoxLayout(self)
        v.setContentsMargins(18, 14, 18, 10)
        v.addWidget(summary_row('Compare captures', []))
        row = QHBoxLayout()
        row.addWidget(QLabel('Before'))
        self.a = QComboBox()
        self.a.setMinimumWidth(240)
        row.addWidget(self.a)
        sw = QToolButton(text='⇄')
        sw.setToolTip('Swap')
        row.addWidget(sw)
        row.addWidget(QLabel('After'))
        self.b = QComboBox()
        self.b.setMinimumWidth(240)
        row.addWidget(self.b)
        row.addStretch(1)
        self.ctl = QWidget()
        self.ctl.setLayout(row)
        v.addWidget(self.ctl)
        self.tb = QTextBrowser()
        self.tb.setFrameShape(QFrame.Shape.NoFrame)
        v.addWidget(self.tb, 1)
        self.A = self.B = None
        self.R = None
        sw.clicked.connect(self.swap)
        self.a.activated.connect(lambda _i: self.pick())
        self.b.activated.connect(lambda _i: self.pick())

    def swap(self):
        self.A, self.B = self.B, self.A
        self.refresh()

    def pick(self):
        self.A, self.B = self.a.currentData(), self.b.currentData()
        self.refresh()

    def refresh(self):
        win = self.win
        TB = win.TB
        self._stale = False
        if len(TB) < 2:
            self.ctl.hide()
            self.tb.setHtml('<p>Open two captures (for example one from before a change and one from after) and they can be compared '
                            'here: new devices, missing devices, changed addresses or IDs, network changes, and which problems appeared or went away.</p>')
            self.R = None
            return
        self.ctl.show()
        ids = [t.id for t in TB]
        if self.B not in ids:
            self.B = (win.ac or TB[-1]).id
        if self.A not in ids or self.A == self.B:
            i = ids.index(self.B)
            self.A = TB[i - 1].id if i > 0 else TB[min(1, len(TB) - 1)].id
        for cb, sel in ((self.a, self.A), (self.b, self.B)):
            cb.blockSignals(True)
            cb.clear()
            for t in TB:
                cb.addItem(t.n, t.id)
            cb.setCurrentIndex(ids.index(sel))
            cb.blockSignals(False)
        A = next(t for t in TB if t.id == self.A)
        B = next(t for t in TB if t.id == self.B)
        if A is B:
            self.tb.setHtml('<p>Pick two different captures.</p>')
            self.R = None
            return
        self.R = R = C.compare(A.FD, B.FD)
        self.tb.setHtml(self.html(A, B, R, False))

    def html(self, A, B, R, export):
        hl = lambda s: self.win.labels.hl(s, export)  # noqa: E731
        c = colors_light() if export else colors()

        def dd(i, ks):
            return f"{hl('Device ' + str(i))} at {', '.join(hl(k) for k in ks)}"

        def ul(l, f):
            return '<ul>' + ''.join(f'<li>{f(x)}</li>' for x in l) + '</ul>' if l else ''

        def sec(t, n, body, cls):
            col = {'SERIOUS': c['se'], 'WARNING': c['wa'], 'NOTE': c['no']}[cls if n else 'NOTE']
            return f'<h3>{t} <span style="color:{col}">({n})</span></h3>' + (body if n else f'<p style="color:{c["mu"]}">None.</p>')
        tot = sum(len(R[k]) for k in ('newD', 'gone', 'moved', 'renum', 'newN', 'goneN', 'gwN', 'newF', 'fixedF'))
        h = (f"<p><b>{esc(A.n)}</b> ({C.pl(R['na'], 'device')}, {C.pl(R['fa'], 'finding')}) → <b>{esc(B.n)}</b> "
             f"({C.pl(R['nb'], 'device')}, {C.pl(R['fb'], 'finding')})</p>" +
             ('' if tot else '<p><b>No differences found.</b> The same devices, addresses and networks appear in both captures.</p>'))
        h += sec('New devices', len(R['newD']), ul(R['newD'], lambda x: dd(x['id'], x['keys'])), 'WARNING')
        h += sec('Missing devices', len(R['gone']), ul(R['gone'], lambda x: dd(x['id'], x['keys']) + ' <i>was in the first capture only</i>'), 'WARNING')
        h += sec('Devices that changed address', len(R['moved']), ul(R['moved'], lambda x: f"{hl('Device ' + str(x['id']))}: {', '.join(map(hl, x['from']))} → {', '.join(map(hl, x['to']))}"), 'WARNING')
        h += sec('Addresses that now have a different device ID', len(R['renum']), ul(R['renum'], lambda x: f"{hl(x['key'])}: device {', '.join(map(str, x['was']))} → device {', '.join(map(str, x['now']))}"), 'WARNING')
        h += sec('New networks', len(R['newN']), ul(R['newN'], lambda n: hl('network ' + str(n))), 'NOTE')
        h += sec('Networks no longer seen', len(R['goneN']), ul(R['goneN'], lambda n: hl('network ' + str(n))), 'NOTE')
        h += sec('Networks reached through a different gateway', len(R['gwN']), ul(R['gwN'], lambda x: f"{hl('network ' + str(x['n']))}: {', '.join(map(hl, x['from']))} → {', '.join(map(hl, x['to']))}"), 'WARNING')
        h += sec('New problems', len(R['newF']), ul(R['newF'], lambda f: f"<b>{esc(f['s'])}</b> {hl(f['t'])}"), 'SERIOUS')
        h += sec('Problems that went away', len(R['fixedF']), ul(R['fixedF'], lambda f: f"<b>{esc(f['s'])}</b> {hl(f['t'])}"), 'NOTE')
        return h

    def formats(self):
        def html():
            if not self.R:
                return doc('Compare', '<p>Pick two different captures.</p>')
            A = next(t for t in self.win.TB if t.id == self.A)
            B = next(t for t in self.win.TB if t.id == self.B)
            return doc('Compare – ' + B.n, '<h3>Compare captures</h3>' + self.html(A, B, self.R, True))

        def csv():
            o = []
            R = self.R
            if R:
                for x in R['newD']:
                    o.append(['New device', f"Device {x['id']}", '', ' | '.join(x['keys'])])
                for x in R['gone']:
                    o.append(['Missing device', f"Device {x['id']}", ' | '.join(x['keys']), ''])
                for x in R['moved']:
                    o.append(['Changed address', f"Device {x['id']}", ' | '.join(x['from']), ' | '.join(x['to'])])
                for x in R['renum']:
                    o.append(['Changed device ID', x['key'], ' '.join(map(str, x['was'])), ' '.join(map(str, x['now']))])
                for n in R['newN']:
                    o.append(['New network', f'Network {n}', '', 'present'])
                for n in R['goneN']:
                    o.append(['Missing network', f'Network {n}', 'present', ''])
                for x in R['gwN']:
                    o.append(['Changed gateway', f"Network {x['n']}", ' | '.join(x['from']), ' | '.join(x['to'])])
                for f in R['newF']:
                    o.append(['New problem', f['t'], '', f['s']])
                for f in R['fixedF']:
                    o.append(['Resolved problem', f['t'], f['s'], ''])
            return '﻿' + csv_text('Category,Item,Before,After', o)
        return [('html', 'Web page – the comparison as shown (*.html)', 'html', html),
                ('csv', 'Spreadsheet – one row per difference, for Excel (*.csv)', 'csv', csv)]


# ================================================================== report --
def rep_model(win):
    F = win.FD
    dv = sorted(F.dv or [], key=lambda d: d['id'])
    nmv, gws = F.nm or {}, F.gws or {}
    cnt = {}
    for d in dv:
        cnt[d['id']] = cnt.get(d['id'], 0) + 1
    cs = {'SERIOUS': 0, 'WARNING': 0, 'NOTE': 0}
    for f in F:
        cs[f['s']] += 1
    pr = {}
    for r in win.P:
        pr[r.proto] = pr.get(r.proto, 0) + 1
    P = win.P
    dur = P[-1].t - P[0].t if P else 0
    du = f'{C.tofixed(dur / 3600, 1)} hours' if dur >= 3600 else f'{C.tofixed(dur / 60, 1)} minutes' if dur >= 60 else f'{C.tofixed(dur, 1)} seconds'
    fix = [{'addr': x['k'], 'from': f['id'], 'to': x['s']['id'], 'why': x['s']['why']} for f in F for x in (f.get('sg') or [])]
    A = plan_all(win)
    AVr = [{'net': r['net'], 'id': r['id']} for r in A['P']['rows'] if r['id'] is not None][:12]
    N = A['N']
    if not F:
        head = 'Looks healthy – no problems found.'
    elif cs['SERIOUS']:
        head = f"Needs attention – {C.pl(cs['SERIOUS'], 'serious problem')}" + (f", {C.pl(cs['WARNING'], 'warning')}" if cs['WARNING'] else '') + '.'
    elif cs['WARNING']:
        head = f"Worth a look – {C.pl(cs['WARNING'], 'warning')}."
    else:
        head = 'Looks OK – only notes.'
    return {'name': win.ac.n, 'when': stamp(), 'pk': len(P), 'du': du,
            'pr': ', '.join(f'{k} {C.locale_int(v)}' for k, v in sorted(pr.items(), key=lambda x: -x[1])), 'cs': cs, 'head': head,
            'finds': list(F), 'fix': fix, 'AVr': AVr, 'nx': N['nx'],
            'nfree': ', '.join(str(a) if a == b else f'{a}–{b}' for a, b in C.rg(N['free'])[:6]),
            'devs': [{'id': d['id'], 'name': win.labels.d(d['id']) or (nmv.get(d['id']) or {}).get('name', ''),
                      'vendor': (nmv.get(d['id']) or {}).get('vendor') or VN.get(d['v']) or f"Vendor {d['v']}",
                      'model': (nmv.get(d['id']) or {}).get('model', ''), 'addr': str(d['sa']) if d['sn'] is not None else d['key'],
                      'net': d['sn'] if d['sn'] is not None else '', 'gw': ' / '.join(gws.get(d['key']) or [d['gw']]) if d['sn'] is not None else '',
                      'dup': cnt[d['id']] > 1} for d in dv],
            'slow': [e for e in (F.sl or []) if e['slow'] or e['silent']],
            'notes': [{'no': r.no, 't': C.tofixed(r.t - win.T0, 3), 'info': r.info, 'note': r.note or ''} for r in P if r.bm]}


def html_report(win):
    R = rep_model(win)
    H = lambda x: win.labels.hl(str(x), True)  # noqa: E731
    b = (f'<div style="max-width:900px"><h1>BACnet network report</h1><p class="mu">{esc(R["name"])} · {esc(R["when"])} · '
         f'{C.locale_int(R["pk"])} packets over {esc(R["du"])} ({esc(R["pr"])})</p><h2>Summary</h2><p style="font-size:16px"><b>{esc(R["head"])}</b></p>')
    if R['finds']:
        b += '<ol>' + ''.join(f"<li><b>{esc(f['s'])}</b> – {H(f['t'])}</li>" for f in R['finds']) + '</ol>'
        b += '<h2>What we found and what to do</h2>'
        for i, f in enumerate(R['finds']):
            ev = ''
            if f.get('ev'):
                ev = '<ul class="ev">' + ''.join(f'<li>{H(e)}</li>' for e in f['ev'][:5]) + (f"<li class=\"mu\">… and {len(f['ev']) - 5} more</li>" if len(f['ev']) > 5 else '') + '</ul>'
            b += (f"<section class=\"card {f['s']}\"><p><span class=\"tag\">{f['s']}</span> <b>{i + 1}. {H(f['t'])}</b></p><p>{H(f['w'])}</p>{ev}"
                  f"<p class=\"lb\">Why it matters</p><p>{H(f['y'])}</p><p class=\"lb\">What to do</p><ol>" + ''.join(f'<li>{H(x)}</li>' for x in f['f']) + '</ol></section>')
    b += '<h2>Suggested device IDs and network numbers</h2>'
    if R['fix']:
        b += '<p>To fix duplicate device IDs, give these devices a new ID:</p>' + html_table(['Device at', 'Now', 'Change to', 'Why'],
             [[H(x['addr']), x['from'], f"<b>{x['to']}</b>", esc(x['why'])] for x in R['fix']])
    else:
        b += '<p class="mu">No duplicate device IDs need a new number.</p>'
    if R['AVr']:
        b += '<p>Next free device ID on each network:</p>' + html_table(['Network', 'Next device ID'], [[H('network ' + str(x['net'])), f"<b>{x['id']}</b>"] for x in R['AVr']])
    if R['nx'] is not None:
        b += f"<p>Next free network number: <b>{R['nx']}</b>" + (f" · free ranges start: {esc(R['nfree'])}" if R['nfree'] else '') + '</p>'
    b += f"<h2>Devices ({len(R['devs'])})</h2>" + (html_table(['ID', 'Name', 'Manufacturer', 'Model', 'Address', 'Network', 'Gateway', ''],
          [[f"<b>{d['id']}</b>", esc(d['name']), esc(d['vendor']), esc(d['model']), H(d['addr']), d['net'], H(d['gw']), '⚠ duplicate ID' if d['dup'] else '']
           for d in R['devs']]) if R['devs'] else '<p class="mu">No devices announced themselves in this capture.</p>')
    if R['slow']:
        b += '<h2>Slow or silent devices</h2>' + html_table(['Device', 'Address', 'Answered', 'No answer', 'Typical', 'Worst'],
             [[', '.join(H('Device ' + str(i)) for i in e['ids']) or '—', H(e['key']), e['n'], e['miss'] or '',
               C.fmt_ms(e['med']) if e['n'] else '', C.fmt_ms(e['max']) if e['n'] else ''] for e in R['slow']])
    if R['notes']:
        b += '<h2>Notes and bookmarked packets</h2>' + html_table(['Packet', 'Time (s)', 'What', 'Note'],
             [[n['no'], n['t'], H(n['info']), esc(n['note'])] for n in R['notes']])
    b += ('<p class="mu" style="margin-top:30px">Created with BACnet Inspector. Findings are based only on what was visible in this '
          'capture; a device that stayed silent is not listed.</p></div>')
    return doc('Network report – ' + R['name'], b)


def txt_report(win):
    R = rep_model(win)
    L = ['BACnet network report', f"{R['name']} – {R['when']}", f"{R['pk']} packets over {R['du']} ({R['pr']})", '', 'SUMMARY', R['head']]
    for i, f in enumerate(R['finds']):
        L += ['', f"{i + 1}. [{f['s']}] {f['t']}", f"   {f['w']}"]
        L += ['   - ' + e for e in (f.get('ev') or [])[:5]]
        L += [f"   Why it matters: {f['y']}", '   What to do:'] + [f'     {j + 1}. {x}' for j, x in enumerate(f['f'])]
    L += ['', 'SUGGESTED IDS']
    if R['fix']:
        L += [f"  Device at {x['addr']}: {x['from']} -> {x['to']} ({x['why']})" for x in R['fix']]
    else:
        L.append('  No duplicate device IDs need a new number.')
    L += [f"  Network {x['net']}: next device ID {x['id']}" for x in R['AVr']]
    if R['nx'] is not None:
        L.append(f"  Next free network number: {R['nx']}")
    L += ['', f"DEVICES ({len(R['devs'])})"]
    for d in R['devs']:
        name = f' "{d["name"]}"' if d['name'] else ''
        model = ', ' + d['model'] if d['model'] else ''
        where = f"network {d['net']} via {d['gw']}, {d['addr']}" if d['net'] != '' else d['addr']
        L.append(f"  {d['id']}{name} - {d['vendor']}{model} - {where}{' - DUPLICATE ID' if d['dup'] else ''}")
    if R['slow']:
        L += ['', 'SLOW OR SILENT DEVICES'] + [f"  {e['key']}: typical {C.fmt_ms(e['med'])}, worst {C.fmt_ms(e['max'])}, {e['miss']} unanswered" for e in R['slow']]
    if R['notes']:
        L += ['', 'NOTES'] + [f"  Packet {n['no']} ({n['t']}s) {n['info']}{' - ' + n['note'] if n['note'] else ''}" for n in R['notes']]
    return '\n'.join(L)


# ============================================================ names dialog --
class LabelsDialog(QDialog):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setWindowTitle('Names & labels')
        v = QVBoxLayout(self)
        v.addWidget(label('Give device IDs and networks readable names. They appear in the Packets, Findings, Devices and Available '
                          'tabs and in reports.', muted=True))
        self.t = Table(['Type', 'Number', 'Name'])
        self.t.setSelectionMode(Table.SelectionMode.ExtendedSelection)
        v.addWidget(self.t, 1)
        row = QHBoxLayout()
        self.k = QComboBox()
        self.k.addItem('Device ID', 'd')
        self.k.addItem('Network', 'n')
        self.n = QLineEdit()
        self.n.setPlaceholderText('number')
        self.n.setFixedWidth(100)
        self.nm = QLineEdit()
        self.nm.setPlaceholderText('name')
        add = QPushButton('Add')
        rm = QPushButton('Remove selected')
        for w in (self.k, self.n, self.nm, add, rm):
            row.addWidget(w)
        v.addLayout(row)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        ex = bb.addButton('Export…', QDialogButtonBox.ButtonRole.ActionRole)
        im = bb.addButton('Import…', QDialogButtonBox.ButtonRole.ActionRole)
        ic = bb.addButton('Import CSV…', QDialogButtonBox.ButtonRole.ActionRole)
        ic.setToolTip('CSV or text: type, number, name — e.g. device,1001,AHU-1 Controller')
        v.addWidget(bb)
        bb.rejected.connect(self.reject)
        add.clicked.connect(self.add)
        rm.clicked.connect(self.remove)
        ex.clicked.connect(self.export)
        im.clicked.connect(self.import_json)
        ic.clicked.connect(self.import_csv)
        self.nm.returnPressed.connect(self.add)
        self.resize(560, 480)
        self.fill()

    def fill(self):
        lb = self.win.store.labels()
        rows = sorted([('d', n, v) for n, v in lb['d'].items()] + [('n', n, v) for n, v in lb['n'].items()],
                      key=lambda x: (x[0], int(x[1]) if str(x[1]).isdigit() else 0))
        self.rows = rows
        self.t.fill([['Device' if k == 'd' else 'Network', n, v] for k, n, v in rows])

    def add(self):
        try:
            n = int(self.n.text().strip())
        except ValueError:
            return self.win.toast('Enter a number and a name')
        if not self.nm.text().strip():
            return self.win.toast('Enter a number and a name')
        self.win.store.set_label(self.k.currentData(), n, self.nm.text())
        self.n.clear()
        self.nm.clear()
        self.fill()

    def remove(self):
        for i in sorted({ix.row() for ix in self.t.selectedIndexes()}, reverse=True):
            k, n, _v = self.rows[i]
            self.win.store.set_label(k, n, '')
        self.fill()

    def export(self):
        p, _ = QFileDialog.getSaveFileName(self, 'Export names', 'bacnet-names.json', 'Names file (*.json)')
        if p:
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(self.win.store.labels(), f, indent=2, ensure_ascii=False)

    def import_json(self):
        p, _ = QFileDialog.getOpenFileName(self, 'Import names', '', 'Names file (*.json)')
        if not p:
            return
        try:
            with open(p, encoding='utf-8') as f:
                o = json.load(f)
            lb = self.win.store.labels()
            for k in ('d', 'n'):
                lb[k].update({str(a): str(b) for a, b in (o.get(k) or {}).items()})
            self.win.store.save_labels()
            self.win.toast('Names imported')
        except (OSError, ValueError, AttributeError):
            self.win.toast('That file is not a names file')
        self.fill()

    def import_csv(self):
        p, _ = QFileDialog.getOpenFileName(self, 'Import names from a spreadsheet', '', 'CSV or text (*.csv *.txt *.tsv)')
        if not p:
            return
        try:
            with open(p, encoding='utf-8-sig', errors='replace') as f:
                t = f.read()
        except OSError:
            return
        n = 0
        lb = self.win.store.labels()
        for ln in t.splitlines():
            if not ln.strip():
                continue
            sep = '\t' if '\t' in ln else ';' if ';' in ln and ',' not in ln else ','
            c, cur, q = [], '', False
            for ch in ln:
                if ch == '"':
                    q = not q
                elif ch == sep and not q:
                    c.append(cur)
                    cur = ''
                else:
                    cur += ch
            c.append(cur)
            a = [x.strip() for x in c]
            if re.match(r'^(d|dev|device|n|net|network)$', a[0], re.I):
                k = 'n' if a[0][:1].lower() == 'n' else 'd'
                num, nm = (a[1] if len(a) > 1 else ''), ', '.join(a[2:])
            else:
                k, num, nm = 'd', a[0], ', '.join(a[1:])
            if not re.match(r'^\d+$', num or '') or not nm:
                continue
            lb[k][str(int(num))] = nm
            n += 1
        self.win.store.save_labels()
        self.win.toast(f'{n} names imported' if n else 'No usable rows found. Use columns: type (device/network), number, name')
        self.fill()


# ==================================================================== help --
HELP = {
    'start': ('Getting started', '<ul>'
              '<li><b>Open a capture</b> with File ▸ Open, or drag files onto the window. Each capture opens in its own tab.</li>'
              '<li><b>Packets</b> lists every message. Click one to see it decoded below, with a plain-English <i>Meaning</i> line. Right-click any cell to build a filter from it; double-click a cell to filter on its value.</li>'
              '<li><b>Findings</b> lists problems, why they matter, and numbered steps to fix them.</li>'
              '<li><b>Devices</b> shows which gateway leads to which network and which devices are on it. Double-click any entry to jump to its packets.</li>'
              '<li><b>Available IDs</b> lists unused device IDs for each network. <b>Available networks</b> lists unused network numbers.</li>'
              '<li><b>Bus speed</b> estimates the baud rate of an MS/TP trunk from frame timing and shows how busy each trunk is, plus throughput for each IP port. <b>Response times</b> shows how long each device takes to answer requests and which ones are slow or silent. <b>Compare</b> lines up two open captures (before and after a change).</li>'
              '<li><b>Names and notes:</b> right-click a device or network in Devices to give it a name. Right-click a packet to bookmark it or add a note (Edit ▸ Names &amp; labels manages all names). <b>File ▸ Export report</b> makes a plain-English report.</li>'
              '<li>Your open captures (and their filters) and the window size come back the next time you start the app.</li>'
              '<li><b>Live capture</b> records from your network adapter or an MS/TP serial adapter. Its controls appear on the Live capture tab.</li>'
              '<li><b>Save</b> and <b>Save As</b> save whichever view you are looking at.</li></ul>'),
    'filter': ('Display filter reference', '<p>Type in the filter box. A green dot means the filter is valid, red means it is not.</p>'
               '<table cellpadding="4"><tr><td><code>proto == "MS/TP"</code></td><td>exact match</td></tr>'
               '<tr><td><code>len &gt; 100</code></td><td>also &lt;, &gt;=, &lt;=, !=</td></tr>'
               '<tr><td><code>info contains "Read"</code></td><td>text search in a field</td></tr>'
               '<tr><td><code>a &amp;&amp; b</code>, <code>a || b</code>, <code>!a</code>, <code>(a || b) &amp;&amp; c</code></td><td>combine</td></tr>'
               '<tr><td><code>bad</code>, <code>iam</code>, <code>whois</code></td><td>true/false flags</td></tr></table>'
               '<p><b>Fields:</b> <code>no time src dst addr host from to proto len info device net dnet gateway bad iam whois nak router write command cov error bookmark note</code></p>'
               '<p><code>host</code> = sender <i>or</i> receiver; <code>from</code>/<code>to</code> = logical sender / receiver. Aliases: <code>ip.addr ip.src ip.dst bacnet.device bacnet.net frame.len mstp.bad</code>.</p>'
               '<p>Examples: <code>device == 1001</code> · <code>host == "10.0.0.5" &amp;&amp; !whois</code> · <code>net == 2000 &amp;&amp; gateway == "10.0.0.1:47808"</code></p>'),
    'bms': ('Everyday BMS tools', '<ul>'
            '<li><b>Discover</b>: lists every device from your capture and from discovery together. Press <b>Scan network</b> (or Ctrl+D) to find devices on the live network – it can also run by itself when a live capture starts, and discovered names become labels in your packets. Pick a device, then <b>Read points</b> reads the device and builds a tree – category (Analog Inputs, Binary Outputs…) then points – with values. <b>Write access</b> is off by default: switch it on (Discover or the Capture menu) for 5–60 minutes to send a value to a commandable point with a priority (or release it). A red bar shows while it is on, each write needs a second confirmation, is read back, and is logged. Only Write Property of present-value is possible – no restarts, no other settings.</li>'
            '<li><b>Changes</b>: every write, restart or communication on/off seen in the capture – who, which point, new value, priority and whether it was accepted.</li>'
            '<li><b>Traffic</b>: busiest senders, who polls whom and how often, and COV floods.</li>'
            '<li><b>MS/TP</b>: which MAC addresses are alive, token lap time, who holds the token longest and a Max Master suggestion.</li>'
            '<li><b>Online</b>: who is talking and who has gone quiet. In a live capture it raises alerts for new, silent or duplicate devices.</li>'
            '<li><b>Response times &amp; errors</b>: slow devices, plus every error, reject and abort grouped by device with a suggested fix.</li>'
            '<li><b>Map</b>: routers, networks and devices as a picture. Save it as PNG, SVG or a web page.</li>'
            '<li><b>Filters</b>: ready-made buttons (Writes, Commands, Errors, COV…). Type any filter and press <i>＋ Save current filter</i> to keep it as your own button.</li>'
            '<li><b>Names &amp; labels</b> (Edit menu) can import a spreadsheet saved as CSV: <code>device,1001,AHU-1</code> or just <code>1001,AHU-1</code>; use <code>network,5,Roof trunk</code> for networks.</li></ul>'),
    'keys': ('Keyboard shortcuts', '<table cellpadding="4">'
             '<tr><td>Ctrl+O</td><td>Open capture</td></tr><tr><td>Ctrl+S</td><td>Save (current view)</td></tr>'
             '<tr><td>Ctrl+Shift+S</td><td>Save As…</td></tr><tr><td>Ctrl+W</td><td>Close tab</td></tr>'
             '<tr><td>Ctrl+F</td><td>Search packets (ID, IP or network)</td></tr><tr><td>Ctrl+L</td><td>Go to the display filter box</td></tr>'
             '<tr><td>Ctrl+1 – 9</td><td>Packets / Findings / Devices / Online / Discover / Changes / Traffic / MS/TP / Map</td></tr>'
             '<tr><td>Ctrl+B</td><td>Bookmark the selected packet</td></tr><tr><td>Ctrl+D</td><td>Discover devices on the network</td></tr>'
             '<tr><td>↑ ↓ PgUp PgDn</td><td>Move through packets</td></tr><tr><td>Alt+←</td><td>Back to the previous view / device</td></tr>'
             '<tr><td>F1</td><td>Help</td></tr></table>'),
    'about': ('About BACnet Inspector', '<p><b>BACnet Inspector</b> {ver}<br>Reads BACnet/IP and BACnet MS/TP captures, explains what is on the '
              'network in plain English, and points out problems such as duplicate device IDs and duplicate network numbers.</p>'
              '<p>Everything stays on your computer.</p>')}


def make(k, win):
    cls = {'f': FindingsView, 'd': DevicesView, 'w': ChangesView, 't': TrafficView, 's': ResponseView, 'o': OnlineView,
           'g': MapView, 'a': AvailIdsView, 'n': AvailNetsView, 'm': MstpView, 'b': BusSpeedView, 'c': CompareView}[k]
    return cls(win)

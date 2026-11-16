"""
bi_sitewin.py - the windows of the site tools: the site health audit (and device clocks, with clock sync), the
site-wide override list, device commands (restart, communication control), Find point (Who-Has), BBMD tables, a trend
log's history, a schedule's week and a calendar (both editable), and the live point watch (polling or COV).
The network work is in bi_site.py and bi_explore.py. Anything that changes a device needs write access switched on,
asks first, and is recorded in the write log.
"""
from __future__ import annotations

import re
import threading
import time

from PySide6.QtCore import QDate, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDateEdit, QDialog, QDialogButtonBox, QFormLayout,
                               QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget)

import bi_explore as E
import bi_site
from bi_common import Table, colors, csv_text, doc, esc, html_table, label, summary_row
from bi_views import PointChart, hint

SEVC = {'SERIOUS': 'se', 'WARNING': 'wa', 'NOTE': 'no'}


def stamp(t):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))


def point_name(row):
    return row.get('name') or f"{E.sd_ty(row['ty'])} {row['inst']}"


def dev_title(dev):
    return dev.get('name') or f"Device {dev['id']}"


class TimeChart(PointChart):
    """The Point history graph with clock times on the axis, for values read from a device."""

    def __init__(self, win, empty=''):
        super().__init__(win)
        self.empty = empty or 'Nothing to show yet'

    def when(self, t):
        e = self.e
        ts = [s[0] for s in (e or {}).get('s') or []]
        span = (max(ts) - min(ts)) if ts else 0
        return time.strftime('%H:%M:%S' if span < 3 * 3600 else '%b %d %H:%M', time.localtime(t))


def _save(win, name, text):
    """Excel or spreadsheet, the user picks (the same Save as the rest of Discover)."""
    win.view('x').save_csv(name, text)


class _Worker:
    """Run fn on a thread and hand its result to done on the UI thread."""

    @staticmethod
    def start(win, fn, done):
        def run():
            try:
                r = fn()
            except Exception as e:                 # show, don't crash
                r = e
            win.on_ui(lambda: done(r))
        threading.Thread(target=run, daemon=True).start()


# =================================================================== audit --
def audit_devices(ex):
    ms = ex.mode == 'mstp'
    return sorted((d for d in ex.devs.values() if E.is_mstp(d) == ms and not d.get('old')), key=lambda d: d['id'])


def audit_dialog(win, clocks_only=False):
    ex = win.explorer
    if ex.busy:
        return win.toast('Wait for Discover to finish what it is doing, or press Stop there')
    devs = audit_devices(ex)
    if not devs:
        win.goto('x')
        return win.toast('Scan for devices in Discover first, then run the check')
    d = AuditDialog(win, devs, clocks_only)
    d.show()
    return d


class AuditDialog(QDialog):
    def __init__(self, win, devs, clocks_only):
        super().__init__(win)
        self.win, self.ex, self.devs, self.clocks_only = win, win.explorer, devs, clocks_only
        self.res = None
        self.setWindowTitle('Device clocks' if clocks_only else 'Site health audit')
        self.resize(1050, 640)
        v = QVBoxLayout(self)
        self.top = QHBoxLayout()
        v.addLayout(self.top)
        v.addWidget(hint('Device clocks are compared with this PC. A clock more than a minute out is listed.' if clocks_only else
                         'Reads every point of every device found in Discover and lists the ones out of service, in fault, '
                         'in alarm or overridden at priority 1–8, trend logs that are switched off, and wrong clocks. '
                         'It only reads. Double-click a row to open the point in Discover.'))
        row = QHBoxLayout()
        self.prog = label('', muted=True)
        row.addWidget(self.prog, 1)
        self.f = QComboBox()
        self.f.addItem('Every problem', '')
        for k, t in bi_site.KIND.items():
            self.f.addItem(t, k)
        self.f.currentIndexChanged.connect(self.fill)
        row.addWidget(self.f)
        self.stop_b = QPushButton('Stop')
        self.stop_b.clicked.connect(lambda: setattr(self.ex, 'stop', True))
        row.addWidget(self.stop_b)
        self.sync_b = QPushButton('Set wrong clocks…')
        self.sync_b.setToolTip('Set the clocks listed as wrong to this PC’s time (needs write access)')
        self.sync_b.clicked.connect(self.sync_clocks)
        self.sync_b.setEnabled(False)
        row.addWidget(self.sync_b)
        self.ovr_b = QPushButton('Review overrides…')
        self.ovr_b.setToolTip('List every active command on the site and release the ones you pick')
        self.ovr_b.clicked.connect(lambda: overrides_dialog(self.win))
        self.ovr_b.setVisible(not clocks_only)
        self.ovr_b.setEnabled(False)
        row.addWidget(self.ovr_b)
        self.exp_b = QPushButton('Export…')
        self.exp_b.clicked.connect(self.export)
        self.exp_b.setEnabled(False)
        row.addWidget(self.exp_b)
        v.addLayout(row)
        self.tabs = QTabWidget()
        self.tbl = Table(['', 'Device', 'Point', 'Problem', 'Detail'])
        self.tbl.rowActivated.connect(self.go)
        self.tabs.addTab(self.tbl, 'Problems')
        self.ck = Table(['Device', 'Device ID', 'Clock', 'Device time', 'Status', 'Points checked'])
        self.ck.rowActivated.connect(lambda k: k and self.go({'k': k}))
        self.tabs.addTab(self.ck, 'Devices and clocks')
        if clocks_only:
            self.tabs.setCurrentIndex(1)
        v.addWidget(self.tabs, 1)
        self.show_top()
        self.ex.busy = 'audit'
        self.ex.notify()
        _Worker.start(win, lambda: bi_site.audit(self.ex, devs, clocks_only, self.progress), self.got_result)

    def progress(self, i, n, name, j, m):
        txt = f'Checking {name} ({i + 1} of {n})' + (f' – {j} of {m} points' if m else '') + '…'
        self.win.on_ui(lambda: self.prog.setText(txt))

    def got_result(self, r):
        self.ex.busy = ''
        self.ex.notify()
        self.stop_b.setEnabled(False)
        if isinstance(r, Exception):
            self.prog.setText(f'The check stopped: {r}')
            return
        self.res = r
        self.ex.audit = r
        n = sum(d['n'] for d in r['devs'])
        self.prog.setText(('Stopped. ' if r['stopped'] else 'Done. ') + f"{len(r['devs'])} device(s)" +
                          (f', {n:,} points checked' if not self.clocks_only else '') + f" · {stamp(r['at'])}")
        self.exp_b.setEnabled(True)
        bad = self.bad_clocks()
        self.sync_b.setEnabled(bool(bad))
        self.sync_b.setText(f'Set {len(bad)} wrong clock{"" if len(bad) == 1 else "s"}…' if bad else 'Set wrong clocks…')
        self.ovr_b.setEnabled(any(x['kind'] == 'override' for x in r['items']))
        self.show_top()
        self.fill()

    def bad_clocks(self):
        keys = {d['key'] for d in (self.res or {}).get('devs', []) if (d['clock'] or {}).get('bad') and not d['err']}
        return [d for d in self.devs if d['key'] in keys]

    def sync_clocks(self):
        sync_clocks_dialog(self.win, self.bad_clocks())

    def show_top(self):
        while self.top.count():
            w = self.top.takeAt(0).widget()
            if w:
                w.setParent(None)
                w.deleteLater()
        title = 'Device clocks' if self.clocks_only else 'Site health audit'
        if not self.res:
            self.top.addWidget(summary_row(title, [(f'{len(self.devs)} device(s)', 'NOTE')]))
            return
        cn = bi_site.audit_counts(self.res)
        pills = [(f"{cn[k]} {bi_site.KIND[k].lower()}", bi_site.SEV[k]) for k in bi_site.KIND if cn.get(k)]
        self.top.addWidget(summary_row(title if self.res['items'] else title + ': no problems found', pills))

    def rows(self):
        k = self.f.currentData()
        return [x for x in (self.res or {}).get('items', []) if not k or x['kind'] == k]

    def fill(self):
        c = colors()
        R = self.rows()
        self.tbl.fill([[('●', {'fg': c[SEVC[x['sev']]]}), f"{x['dname']} ({x['id']})", x['name'] if x['o'] is not None else '',
                        bi_site.KIND[x['kind']], x['detail']] for x in R],
                      [{'k': x['key'], 'o': x['o']} for x in R])
        D = (self.res or {}).get('devs', [])
        rows = []
        for d in D:
            ck = d['clock'] or {}
            bad = ck.get('bad') or d['err']
            rows.append([d['name'], d['id'], (d['err'] or ck.get('text') or ck.get('err') or '', {'fg': c['se'] if bad else c['no']}),
                         stamp(ck['dev']) if ck.get('dev') else '', d['status'], d['n'] or ''])
        self.ck.fill(rows, [d['key'] for d in D])

    def go(self, node):
        if not node:
            return
        dv = self.win.view('x')
        self.win.goto('x')
        dv.go_node({k: v for k, v in node.items() if v is not None})

    def export(self):
        r = self.res
        if not r:
            return

        def csv():
            return csv_text('Severity,Device,Device ID,Point,Problem,Detail',
                            [[x['sev'].title(), x['dname'], x['id'], x['name'] if x['o'] is not None else '', bi_site.KIND[x['kind']],
                              x['detail']] for x in r['items']])

        def clocks():
            return csv_text('Device,Device ID,Clock,Device time,Status,Points checked',
                            [[d['name'], d['id'], d['err'] or (d['clock'] or {}).get('text', ''),
                              stamp(d['clock']['dev']) if (d['clock'] or {}).get('dev') else '', d['status'], d['n']] for d in r['devs']])
        fm = [('xlsx', 'Excel workbook – the problems (*.xlsx)', 'xlsx', lambda: __import__('bi_common').csv_to_xlsx(csv(), 'Audit')),
              ('csv', 'Spreadsheet – the problems (*.csv)', 'csv', lambda: '﻿' + csv()),
              ('clocks', 'Spreadsheet – the devices and their clocks (*.csv)', 'csv', lambda: '﻿' + clocks()),
              ('html', 'Web page – the audit (*.html)', 'html', lambda: doc('Site health audit', audit_html(r)))]
        self.win.save_as('audit', fm, self.win.store_sv, 'Save the site health audit')

    def closeEvent(self, ev):
        if self.ex.busy == 'audit':
            self.ex.stop = True
        super().closeEvent(ev)


def audit_html(r, h2='h3'):
    """The audit as HTML, for its own web page and for the site report."""
    cn = bi_site.audit_counts(r)
    head = ', '.join(f"{cn[k]} {bi_site.KIND[k].lower()}" for k in bi_site.KIND if cn.get(k)) or 'no problems found'
    b = (f"<{h2}>Site health audit</{h2}><p class=\"mu\">Read live from {len(r['devs'])} device(s) on {stamp(r['at'])}"
         + (' (stopped before the end)' if r['stopped'] else '') + f'. Found: {esc(head)}.</p>')
    if r['items']:
        b += html_table(['', 'Device', 'Point', 'Problem', 'Detail'],
                        [[x['sev'].title(), esc(f"{x['dname']} ({x['id']})"), esc(x['name'] if x['o'] is not None else ''),
                          esc(bi_site.KIND[x['kind']]), esc(x['detail'])] for x in r['items'][:500]])
    bad = [d for d in r['devs'] if (d['clock'] or {}).get('bad') or d['err']]
    if bad:
        b += '<p><b>Clocks to fix:</b> ' + esc('; '.join(f"{d['name']}: {d['err'] or d['clock']['text']}" for d in bad)) + '</p>'
    return b


def check_clock(win, dev):
    """One device's clock, from its Discover page."""
    _Worker.start(win, lambda: bi_site.clock(win.explorer, dev),
                  lambda r: win.toast(f"{dev_title(dev)} clock: " + (str(r) if isinstance(r, Exception) else r['err'] or r['text'])))


def _need_write(win):
    """Write access on, asking for it when it is off. True when it is on."""
    import bi_discover
    if win.explorer.armed():
        return True
    if not bi_discover.arm_dialog(win):
        return False
    win.wb_draw()
    return True


def _confirm(win, title, html_text, ok_text):
    import bi_discover
    return bi_discover.confirm(win, title, html_text, ok_text)


# ============================================================== clock sync --
def sync_clocks_dialog(win, devs):
    """Set the clocks of these devices to this PC's time, one at a time, and show each result."""
    if not devs:
        return win.toast('No devices to set')
    if not _need_write(win):
        return None
    d = SyncDialog(win, devs)
    d.show()
    return d


class SyncDialog(QDialog):
    def __init__(self, win, devs):
        super().__init__(win)
        self.win, self.ex, self.devs = win, win.explorer, devs
        self.setWindowTitle('Set device clocks')
        self.resize(820, 460)
        v = QVBoxLayout(self)
        v.addWidget(label(f"Set the clock of {len(devs)} device{'' if len(devs) == 1 else 's'} to this PC’s time "
                          f"({time.strftime('%Y-%m-%d %H:%M:%S')}). Check this PC’s clock and time zone first.", bold=True))
        v.addWidget(hint('Local time suits most controllers. Choose UTC only for devices that keep their own UTC offset and '
                         'daylight-saving setting (some newer controllers and supervisors). Each clock is read back afterwards.'))
        r = QHBoxLayout()
        r.addWidget(QLabel('Send'))
        self.kind = QComboBox()
        self.kind.addItem('Local time (Time Synchronization)', False)
        self.kind.addItem('UTC (UTC Time Synchronization)', True)
        r.addWidget(self.kind)
        r.addStretch(1)
        v.addLayout(r)
        self.tbl = Table(['Device', 'Device ID', 'Result', 'Clock now'])
        self.tbl.fill([[dev_title(x), x['id'], 'waiting', ''] for x in devs])
        v.addWidget(self.tbl, 1)
        bb = QDialogButtonBox()
        self.go = bb.addButton(f"Set {len(devs)} clock{'' if len(devs) == 1 else 's'}", QDialogButtonBox.ButtonRole.ActionRole)
        self.go.setStyleSheet('QPushButton{background:#c42b1c;color:white;padding:4px 14px}')
        self.close_b = bb.addButton(QDialogButtonBox.StandardButton.Close)
        self.close_b.clicked.connect(self.reject)
        self.go.clicked.connect(self.run)
        v.addWidget(bb)
        self.rows = [[dev_title(x), x['id'], 'waiting', ''] for x in devs]

    def run(self):
        if not self.ex.armed():
            return self.win.toast('Write access is switched off – switch it on again first')
        self.go.setEnabled(False)
        self.kind.setEnabled(False)
        utc = self.kind.currentData()
        c = colors()

        def work():
            for i, dev in enumerate(self.devs):
                if not self.ex.armed():
                    self.rows[i][2] = ('write access switched off', {'fg': c['se']})
                    continue
                self.rows[i][2] = 'setting…'
                self.win.on_ui(lambda: self.tbl.fill(self.rows))
                r = bi_site.sync_clock(self.ex, dev, utc)
                good = r.get('sent') and not r.get('err') and not r.get('bad')
                self.rows[i][2] = (('✓ set – ' + r['text']) if good else (r.get('err') or r.get('text') or 'failed'),
                                   {'fg': c['no'] if good else c['se']})
                self.rows[i][3] = stamp(r['dev']) if r.get('dev') else ''
                self.win.on_ui(lambda: self.tbl.fill(self.rows))
            return True
        _Worker.start(self.win, work, lambda _r: (self.tbl.fill(self.rows), self.close_b.setText('Done')))


# ========================================================= device commands --
def device_cmd_dialog(win, dev, kind):
    """Restart a device ('warm' / 'cold') or switch its communication off ('disable') or on ('enable')."""
    if not _need_write(win):
        return
    ex = win.explorer
    nm = dev_title(dev)
    d = QDialog(win)
    titles = {'warm': 'Restart (warm start)', 'cold': 'Restart (cold start)', 'disable': 'Disable communication',
              'enable': 'Enable communication'}
    d.setWindowTitle(f"{titles[kind]} – {nm}")
    v = QVBoxLayout(d)
    v.addWidget(label(f"{nm} · device {dev['id']} · {E.Explorer.addr(dev)}", muted=True))
    warn = {'warm': 'The controller restarts its program and keeps its settings. Outputs may drop out for a moment while it '
                    'starts up, and it will not answer for a little while.',
            'cold': 'The controller restarts from scratch: values that are not saved (for example ones written at a priority) '
                    'are lost and outputs may drop out while it starts up. Use a warm start unless the manufacturer says '
                    'otherwise.',
            'disable': 'The device stops answering and sending on the network (it keeps controlling its equipment). Supervisors '
                       'will show it offline. It answers only Enable communication and Restart until then, so set a time '
                       'limit unless you are sure.',
            'enable': 'The device starts answering and sending on the network again.'}[kind]
    v.addWidget(label(warn))
    f = QFormLayout()
    mode = mins = None
    if kind == 'disable':
        mode = QComboBox()
        mode.addItem('Disable – stop answering and sending', 1)
        mode.addItem('Disable initiation – keep answering, stop sending on its own', 2)
        f.addRow('What', mode)
        mins = QComboBox()
        for m, t in ((5, '5 minutes'), (15, '15 minutes'), (60, '1 hour'), (0, 'until enabled again')):
            mins.addItem(t, m)
        mins.setCurrentIndex(1)
        f.addRow('For', mins)
    pw = QLineEdit()
    pw.setPlaceholderText('leave empty if the device has none')
    pw.setMaxLength(20)
    f.addRow('Password', pw)
    v.addLayout(f)
    msg = QLabel()
    msg.setWordWrap(True)
    msg.setTextFormat(Qt.TextFormat.RichText)
    v.addWidget(msg)
    bb = QDialogButtonBox()
    go = bb.addButton(titles[kind] + '…', QDialogButtonBox.ButtonRole.ActionRole)
    go.setStyleSheet('QPushButton{background:#c42b1c;color:white;padding:4px 14px}')
    close = bb.addButton(QDialogButtonBox.StandardButton.Close)
    close.clicked.connect(d.reject)
    v.addWidget(bb)
    st = {'step': 0}
    c = colors()

    def click():
        if st['step'] == 0:
            st['step'] = 1
            what = titles[kind].lower()
            if kind == 'disable':
                what = f"{mode.currentText().split(' –')[0].lower()} {('for ' + mins.currentText()) if mins.currentData() else 'until enabled again'}"
            go.setText(f'Confirm: {titles[kind].lower()}')
            msg.setText(f'<b>Check before you confirm:</b> {esc(what)} on <b>{esc(nm)}</b> (device {dev["id"]}).')
            for w in (mode, mins, pw):
                if w is not None:
                    w.setEnabled(False)
            return
        go.setEnabled(False)
        go.setText('Sending…')
        if kind in ('warm', 'cold'):
            apdu = E.ex_reinit(1 if kind == 'warm' else 0, pw.text())
            shown = E.REINIT[1 if kind == 'warm' else 0]
        else:
            m = mode.currentData() if kind == 'disable' else 0
            n = mins.currentData() if kind == 'disable' else 0
            apdu = E.ex_dcc(m, n, pw.text())
            shown = E.DCC[m] + (f' for {n} min' if n else '')

        def work():
            return ex.device_command(dev, apdu, 'device · ' + titles[kind].lower(), shown)

        def done(r):
            ok, m_ = r if not isinstance(r, Exception) else (False, str(r))
            msg.setText(f'<span style="color:{c["no"] if ok else c["se"]}"><b>{esc(m_)}</b></span>'
                        + ('<br>Give the device a minute to start up before reading it again.' if ok and kind in ('warm', 'cold') else ''))
            go.hide()
            close.setText('Done')
            if 'x' in win.views:
                win.views['x'].refresh()
        _Worker.start(win, work, done)
    go.clicked.connect(click)
    d.resize(560, 320)
    d.exec()


# ============================================================== find point --
def who_has_dialog(win):
    d = WhoHasDialog(win)
    d.show()
    return d


class WhoHasDialog(QDialog):
    """Find which device has a point, by its name or by its object (Who-Has / I-Have)."""

    def __init__(self, win):
        super().__init__(win)
        self.win, self.ex = win, win.explorer
        self.res = []
        self.setWindowTitle('Find point (Who-Has)')
        self.resize(820, 480)
        v = QVBoxLayout(self)
        v.addWidget(hint('Asks every device on the network which one has this point. Type the exact object name '
                         '(for example AHU-1 SAT), or an object such as AI 3 or analog-value 12. Devices answer with I-Have. '
                         'It uses the same connection and BBMD as Scan network. Double-click a row to open it in Discover.'))
        r = QHBoxLayout()
        self.q = QLineEdit()
        self.q.setPlaceholderText('Object name, or AI 3')
        self.q.returnPressed.connect(self.go)
        r.addWidget(self.q, 1)
        r.addWidget(QLabel('Device IDs'))
        self.lo = QLineEdit()
        self.lo.setPlaceholderText('from')
        self.lo.setMaximumWidth(80)
        self.hi = QLineEdit()
        self.hi.setPlaceholderText('to')
        self.hi.setMaximumWidth(80)
        r.addWidget(self.lo)
        r.addWidget(self.hi)
        self.b = U_primary(QPushButton('Find'))
        self.b.clicked.connect(self.go)
        r.addWidget(self.b)
        v.addLayout(r)
        self.msg = label('', muted=True)
        v.addWidget(self.msg)
        self.tbl = Table(['Device ID', 'Device', 'Object', 'Name', 'Address'])
        self.tbl.rowActivated.connect(self.open)
        v.addWidget(self.tbl, 1)

    @staticmethod
    def parse_obj(text):
        """'AI 3', 'av12', 'analog-value 12' -> object id, or None when the text is a name."""
        import re
        m = re.match(r'^\s*([A-Za-z][A-Za-z\- ]*?)\s*[: ]?\s*(\d+)\s*$', text or '')
        if not m:
            return None
        t = m.group(1).strip().lower().replace(' ', '-')
        ab = {v.lower(): k for k, v in E.ABBR.items()}
        ty = ab.get(t)
        if ty is None:
            ty = next((k for k in range(0, 64) if C_tyname(k) == t), None)
        return None if ty is None else E.oid(ty, int(m.group(2)))

    def go(self):
        text = self.q.text().strip()
        if not text:
            return
        try:
            lo, hi = int(self.lo.text()), int(self.hi.text())
            if hi < lo:
                raise ValueError
        except ValueError:
            lo = hi = None
        o = self.parse_obj(text)
        self.b.setEnabled(False)
        self.msg.setText('Asking every device…')

        def work():
            return self.ex.who_has(None if o is not None else text, o, lo, hi)
        _Worker.start(self.win, work, self.got)

    def got(self, r):
        self.b.setEnabled(True)
        if isinstance(r, Exception):
            self.msg.setText(f'Could not ask: {r}')
            return
        self.res = r
        known = {d['id']: d for d in self.ex.devs.values()}
        self.msg.setText(f"{len(r)} answer{'' if len(r) == 1 else 's'}." if r else
                         'No device answered. Check the spelling (names must match exactly), or try the object instead.')
        self.tbl.fill([[x['id'], (known.get(x['id']) or {}).get('name') or '', f"{E.sd_ty(E.o_t(x['o']))} {E.o_i(x['o'])}",
                        x['name'], x['ip'] + (f" / network {x['sn']}" if x.get('sn') is not None else '')] for x in r],
                      [x for x in r])

    def open(self, x):
        if not x:
            return
        dev = next((d for d in self.ex.devs.values() if d['id'] == x['id']), None)
        if not dev:
            return self.win.toast(f"Device {x['id']} is not in Discover yet – scan the network first")
        dv = self.win.view('x')
        self.win.goto('x')
        node = {'k': dev['key']}
        if any(o['o'] == x['o'] for o in dev.get('objs') or []):
            node['o'] = x['o']
        dv.go_node(node)


def U_primary(b):
    import bi_ui
    return bi_ui.primary(b)


def C_tyname(t):
    import bi_core
    return bi_core.tyname(t)


# ============================================================ BBMD tables --
def bbmd_dialog(win):
    d = BbmdDialog(win)
    d.show()
    return d


class BbmdDialog(QDialog):
    """Read the broadcast distribution table (BDT) and foreign device table (FDT) of one or more BBMDs, and check
    that every BBMD lists every other one."""

    def __init__(self, win):
        super().__init__(win)
        self.win, self.ex = win, win.explorer
        self.setWindowTitle('BBMD tables')
        self.resize(900, 600)
        v = QVBoxLayout(self)
        v.addWidget(hint('Type the address of each BBMD (comma-separated) and press Read. The broadcast distribution table '
                         '(BDT) says which other BBMDs it forwards broadcasts to; every BBMD should list every other one, '
                         'with the same masks. The foreign device table (FDT) lists PCs and devices registered with it. '
                         'Reading these changes nothing.'))
        r = QHBoxLayout()
        self.q = QLineEdit(self.ex.opt.get('bbmd') or '')
        self.q.setPlaceholderText('10.0.1.5, 10.0.2.5, 10.0.3.5:47809')
        self.q.returnPressed.connect(self.go)
        r.addWidget(self.q, 1)
        self.b = U_primary(QPushButton('Read'))
        self.b.clicked.connect(self.go)
        r.addWidget(self.b)
        v.addLayout(r)
        self.msg = label('', muted=False)
        v.addWidget(self.msg)
        self.tabs = QTabWidget()
        self.bdt = Table(['BBMD', 'Lists', 'Port', 'Mask'])
        self.fdt = Table(['BBMD', 'Foreign device', 'Port', 'Registered for', 'Time left'])
        self.tabs.addTab(self.bdt, 'Broadcast distribution (BDT)')
        self.tabs.addTab(self.fdt, 'Foreign devices (FDT)')
        v.addWidget(self.tabs, 1)

    def go(self):
        addrs = [a.strip() for a in self.q.text().replace(';', ',').split(',') if a.strip()]
        if not addrs:
            return
        self.b.setEnabled(False)
        self.msg.setText('Reading…')

        def work():
            return [self.ex.read_bbmd(a) for a in addrs]
        _Worker.start(self.win, work, self.got)

    @staticmethod
    def check(res):
        """Problems between the BBMDs read: [text]."""
        out = []
        ok = [r for r in res if r['bdt'] is not None]
        ips = {r['ip'] for r in ok}
        for r in res:
            if r['err']:
                out.append(f"{r['ip']}: {r['err']}")
            elif r['bdt'] is None:
                out.append(f"{r['ip']} would not give its broadcast table" + (' (refused – it may not be a BBMD)' if r.get('bdt_nak') else '.'))
        for r in ok:
            listed = {e['ip'] for e in r['bdt']}
            if r['bdt'] and r['ip'] not in listed:
                out.append(f"{r['ip']} does not list itself in its own table (most BBMDs must).")
            for other in sorted(ips - {r['ip']} - listed):
                out.append(f"{r['ip']} does not list {other}: broadcasts from its subnet will not reach {other}’s subnet.")
            for e in r['bdt']:
                if e['mask'] not in ('255.255.255.255',):
                    out.append(f"{r['ip']} lists {e['ip']} with mask {e['mask']} (directed broadcast). That only works if the "
                               'routers between them pass directed broadcasts; 255.255.255.255 (two-hop) is safer.')
        masks = {}
        for r in ok:
            for e in r['bdt']:
                masks.setdefault(e['ip'], set()).add(e['mask'])
        for ip, m in masks.items():
            if len(m) > 1:
                out.append(f"The BBMDs disagree about the mask for {ip} ({', '.join(sorted(m))}). Use the same entry everywhere.")
        return out

    def got(self, res):
        self.b.setEnabled(True)
        if isinstance(res, Exception):
            self.msg.setText(f'Could not read: {res}')
            return
        c = colors()
        probs = self.check(res)
        good = not probs and all(r['bdt'] is not None for r in res)
        self.msg.setText(('✓ The tables agree: every BBMD lists every other one.' if len(res) > 1 else '✓ Read.') if good else
                         '\n'.join('• ' + p for p in probs))
        self.msg.setStyleSheet(f"color:{c['no'] if good else c['wa']}")
        self.bdt.fill([[r['ip'], e['ip'], e['port'], e['mask']] for r in res for e in (r['bdt'] or [])])
        self.fdt.fill([[r['ip'], e['ip'], e['port'], f"{e['ttl']} s", f"{e['left']} s"] for r in res for e in (r['fdt'] or [])])


# =============================================================== overrides --
def overrides_dialog(win):
    ex = win.explorer
    if ex.busy:
        return win.toast('Wait for Discover to finish what it is doing, or press Stop there')
    devs = audit_devices(ex)
    if not devs:
        win.goto('x')
        return win.toast('Scan for devices in Discover first, then look for overrides')
    d = OverridesDialog(win, devs)
    d.show()
    return d


class OverridesDialog(QDialog):
    """Every active command in every commandable point on the site, to review and release them in one go."""
    FILTERS = [('Priority 8 – manual operator', lambda x: x['pri'] == 8),
               ('Priorities 1–8 (manual and above)', lambda x: x['pri'] <= 8),
               ('Every active command (1–16)', lambda x: True),
               ('Only the command in control', lambda x: x['ctl'])]

    def __init__(self, win, devs):
        super().__init__(win)
        self.win, self.ex, self.devs, self.res = win, win.explorer, devs, None
        self.setWindowTitle('Overrides')
        self.resize(1050, 640)
        v = QVBoxLayout(self)
        v.addWidget(hint('Reads the priority array of every output and value in every device found in Discover and lists each '
                         'active command. Pick rows (Ctrl or Shift for several, Ctrl+A for all) and press Release to remove '
                         'those commands, for example the manual overrides left behind at priority 8 before handover. '
                         'Releasing needs write access and asks first. Double-click a row to open the point.'))
        r = QHBoxLayout()
        self.prog = label('', muted=True)
        r.addWidget(self.prog, 1)
        self.f = QComboBox()
        for t, _ in self.FILTERS:
            self.f.addItem(t)
        self.f.currentIndexChanged.connect(self.fill)
        r.addWidget(self.f)
        self.stop_b = QPushButton('Stop')
        self.stop_b.clicked.connect(lambda: setattr(self.ex, 'stop', True))
        r.addWidget(self.stop_b)
        self.again = QPushButton('Read again')
        self.again.clicked.connect(self.read)
        r.addWidget(self.again)
        self.rel = QPushButton('Release selected…')
        self.rel.setStyleSheet('QPushButton{background:#c42b1c;color:white;padding:4px 14px}'
                               'QPushButton:disabled{background:#d9a9a4}')
        self.rel.clicked.connect(self.release)
        r.addWidget(self.rel)
        self.exp = QPushButton('Export…')
        self.exp.clicked.connect(self.export)
        r.addWidget(self.exp)
        v.addLayout(r)
        self.tbl = Table(['Device', 'Point', 'Priority', 'Value', 'In control', 'Result'])
        self.tbl.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tbl.rowActivated.connect(self.go)
        self.tbl.itemSelectionChanged.connect(self.sel_changed)
        v.addWidget(self.tbl, 1)
        self.done_res = {}                       # (object key, priority) -> result text
        self.read()

    def read(self):
        self.rel.setEnabled(False)
        self.again.setEnabled(False)
        self.stop_b.setEnabled(True)
        self.ex.busy = 'audit'
        self.ex.notify()
        _Worker.start(self.win, lambda: bi_site.overrides(self.ex, self.devs, self.progress), self.got)

    def progress(self, i, n, name, j, m):
        txt = f'Reading {name} ({i + 1} of {n})' + (f' – {j} of {m} points' if m else '') + '…'
        self.win.on_ui(lambda: self.prog.setText(txt))

    def got(self, r):
        self.ex.busy = ''
        self.ex.notify()
        self.stop_b.setEnabled(False)
        self.again.setEnabled(True)
        if isinstance(r, Exception):
            self.prog.setText(f'Stopped: {r}')
            return
        self.res = r
        self.done_res = {}
        p8 = sum(1 for x in r['items'] if x['pri'] == 8)
        self.prog.setText(('Stopped. ' if r['stopped'] else '') + f"{len(r['items'])} active command(s) in {r['n']:,} points"
                          + (f', {p8} at priority 8' if p8 else '') + f" · {stamp(r['at'])}"
                          + (f" · {len(r['errs'])} device(s) could not be read" if r['errs'] else ''))
        self.fill()

    def rows(self):
        fn = self.FILTERS[self.f.currentIndex()][1]
        return [x for x in (self.res or {}).get('items', []) if fn(x)]

    def fill(self):
        c = colors()
        R = self.rows()

        def shown(x):
            u = E.unit_of(x['row']) if x['ty'] not in E.MS_T and x['ty'] not in (3, 4, 5) else ''
            return f"{E.temp_text(x['val'], x['row'].get('uc'))} {u}".strip()
        self.tbl.fill([[f"{x['dname']} ({x['id']})", x['name'], (str(x['pri']) + (' – manual operator' if x['pri'] == 8 else ''),
                        {'bold': x['pri'] == 8}), shown(x), 'yes' if x['ctl'] else '',
                        (self.done_res.get((x['key'], x['o'], x['pri']), ''),
                         {'fg': c['no'] if self.done_res.get((x['key'], x['o'], x['pri']), '').startswith('✓') else c['se']})]
                       for x in R], R)
        self.sel_changed()

    def selected(self):
        R = self.rows()
        idx = sorted({i.row() for i in self.tbl.selectionModel().selectedRows()})
        return [R[i] for i in idx if i < len(R) and not self.done_res.get((R[i]['key'], R[i]['o'], R[i]['pri']), '').startswith('✓')]

    def sel_changed(self):
        n = len(self.selected())
        self.rel.setEnabled(bool(n) and not self.ex.busy)
        self.rel.setText(f'Release {n} selected…' if n else 'Release selected…')

    def release(self):
        S = self.selected()
        if not S or not _need_write(self.win):
            return
        devs = len({x['key'] for x in S})
        lst = ''.join(f"<li>{esc(x['name'])} in {esc(x['dname'])}: priority {x['pri']} = {esc(x['val'])}</li>" for x in S[:12])
        if not _confirm(self.win, 'Release commands',
                        f"Release <b>{len(S)}</b> command{'' if len(S) == 1 else 's'} in <b>{devs}</b> device"
                        f"{'' if devs == 1 else 's'}?<ul>{lst}</ul>{'…and ' + str(len(S) - 12) + ' more.' if len(S) > 12 else ''}"
                        'Each point then follows its next active priority, or its relinquish default.',
                        f"Release {len(S)}"):
            return
        self.rel.setEnabled(False)

        def work():
            for x in S:
                if not self.ex.armed():
                    self.done_res[(x['key'], x['o'], x['pri'])] = 'write access switched off'
                    continue
                _e, msg, ok = self.ex.write(x['dev'], x['row'], [0], x['pri'], True, f"RELEASE (null) at {x['pri']}")
                self.done_res[(x['key'], x['o'], x['pri'])] = ('✓ released' if ok else msg.split('. ')[0])
                self.win.on_ui(self.fill)
            return True
        _Worker.start(self.win, work, lambda _r: (self.fill(), self.win.toast(
            f"Released {sum(1 for v in self.done_res.values() if v.startswith('✓'))} of {len(S)}")))

    def go(self, x):
        if not x:
            return
        dv = self.win.view('x')
        self.win.goto('x')
        dv.go_node({'k': x['key'], 'o': x['o']})

    def export(self):
        r = self.res
        if not r:
            return
        _save(self.win, 'overrides.csv', csv_text('Device,Device ID,Point,Priority,Value,In control,Result',
                                                   [[x['dname'], x['id'], x['name'], x['pri'], x['val'], 'yes' if x['ctl'] else '',
                                                     self.done_res.get((x['key'], x['o'], x['pri']), '')] for x in r['items']]))

    def closeEvent(self, ev):
        if self.ex.busy == 'audit':
            self.ex.stop = True
        super().closeEvent(ev)


# =================================================================== trend --
def trend_dialog(win, dev, row):
    d = TrendDialog(win, dev, row)
    d.show()
    return d


class TrendDialog(QDialog):
    LIMIT = 2000

    def __init__(self, win, dev, row):
        super().__init__(win)
        self.win, self.dev, self.row, self.res = win, dev, row, None
        self.setWindowTitle(f'Trend log – {point_name(row)}')
        self.resize(980, 640)
        v = QVBoxLayout(self)
        self.head = label(f'{point_name(row)} · {dev_title(dev)}', bold=True, size=15)
        v.addWidget(self.head)
        self.sub = label('Reading the history from the device…', muted=True)
        v.addWidget(self.sub)
        self.chart = TimeChart(win, 'Reading…')
        v.addWidget(self.chart, 3)
        self.tbl = Table(['Time', 'Value', 'Note'])
        v.addWidget(self.tbl, 2)
        r = QHBoxLayout()
        self.more = QPushButton('Read all')
        self.more.hide()
        self.more.clicked.connect(lambda: self.read(10 ** 6))
        r.addWidget(self.more)
        self.again = QPushButton('Read again')
        self.again.clicked.connect(lambda: self.read(self.LIMIT))
        r.addWidget(self.again)
        r.addStretch(1)
        self.exp = QPushButton('Export…')
        self.exp.clicked.connect(self.export)
        r.addWidget(self.exp)
        v.addLayout(r)
        self.read(self.LIMIT)

    def read(self, limit):
        self.again.setEnabled(False)
        self.more.setEnabled(False)
        self.exp.setEnabled(False)
        self.sub.setText('Reading the history from the device…')

        def prog(n, m):
            self.win.on_ui(lambda: self.sub.setText(f'Reading the history from the device… {n:,} of {m:,} records'))
        _Worker.start(self.win, lambda: bi_site.trend(self.win.explorer, self.dev, self.row['o'], limit, prog), self.got_result)

    def got_result(self, r):
        self.again.setEnabled(True)
        if isinstance(r, Exception):
            self.sub.setText(f'Could not read the trend log: {r}')
            return
        self.res = r
        recs = r['recs']
        if r['name']:
            self.head.setText(f"{r['name']} · {dev_title(self.dev)}")
        bits = []
        if r['what']:
            bits.append('records ' + r['what'])
        if r['interval']:
            s = r['interval'] / 100
            bits.append('every ' + (f'{s / 60:g} minutes' if s >= 60 else f'{s:g} seconds'))
        if r['enabled'] is False:
            bits.append('switched OFF: it is not recording')
        if recs:
            bits.append(f"{len(recs):,} records from {stamp(recs[0][0])} to {stamp(recs[-1][0])}"
                        + (f" (the newest of {r['total']:,})" if r['total'] > len(recs) else ''))
        elif not r['err']:
            bits.append('the log is empty')
        if r['err']:
            bits.append(r['err'])
        self.sub.setText(' · '.join(bits))
        self.more.setVisible(r['total'] > len(recs) and not r['err'])
        self.more.setText(f"Read all {r['total']:,}")
        self.more.setEnabled(True)
        self.exp.setEnabled(bool(recs))
        self.chart.empty = 'No values in this trend log'
        self.recs = recs = self.shown(r)
        if any(st == 'daylight saving' for _t, _x, _n, st in recs):
            self.sub.setText(self.sub.text() + ' · the clocks changed for daylight saving during this log (marked in the list)')
        self.chart.show_point({'s': [(t, x, n, None) for t, x, n, st in recs if not st or st == 'daylight saving'], 'w': []})
        rows = [[stamp(t), x if st in ('', 'daylight saving') else '', st] for t, x, n, st in reversed(recs[-3000:])]
        self.tbl.fill(rows)

    @staticmethod
    def shown(r):
        """The records in the temperature unit chosen in View (with the unit), a daylight saving change marked."""
        uc = r.get('uc')
        u = E.unit_of({'uc': uc, 'u': E.EXU.get(uc, '') if uc is not None else ''})
        out, dst = [], None
        for t, x, n, st in r['recs']:
            if not st:
                x, n = (E.temp_text(x, uc) + (f' {u}' if u else '')), E.conv(n, uc)
            d = time.localtime(t).tm_isdst
            if dst is not None and d != dst and not st:
                st = 'daylight saving'
            dst = d
            out.append((t, x, n, st))
        return out

    def export(self):
        r = self.res
        if r and r['recs']:
            _save(self.win, f"trend-{self.dev['id']}-{self.row['inst']}.csv",
                  csv_text('Time,Value,Note', [[stamp(t), x if st in ('', 'daylight saving') else '', st]
                                               for t, x, n, st in self.shown(r)]))


# ================================================================ schedule --
class WeekView(QWidget):
    """Seven rows, midnight to midnight: when the schedule is on (or which value it sets)."""
    LW, TH = 96, 22

    def __init__(self):
        super().__init__()
        self.week, self.default = [], ''
        self.setMinimumHeight(7 * 30 + self.TH + 8)

    def set(self, week, default):
        self.week, self.default = week, default
        self.update()

    @staticmethod
    def mins(hm):
        try:
            h, m = hm.split(':')
            return int(h) * 60 + (int(m) if m.isdigit() else 0)
        except ValueError:
            return 0

    def paintEvent(self, _ev):
        c = colors()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W = self.width() - self.LW - 12
        rh = (self.height() - self.TH - 8) / 7
        grid = QColor(c['mu'])
        grid.setAlpha(60)
        for h in range(0, 25, 3):
            x = self.LW + W * h / 24
            p.setPen(QPen(grid, 1))
            p.drawLine(int(x), self.TH, int(x), int(self.TH + 7 * rh))
            p.setPen(QColor(c['mu']))
            r = QRectF(x - 60, 0, 60, self.TH - 4) if h == 24 else QRectF(x - 30, 0, 60, self.TH - 4)
            p.drawText(r, Qt.AlignmentFlag.AlignRight if h == 24 else Qt.AlignmentFlag.AlignCenter, f'{h:02d}:00')
        on = QColor(c['ac'])
        other = QColor(c['ac'])
        other.setAlpha(110)
        for i, name in enumerate(bi_site.DAYS):
            y = self.TH + i * rh
            p.setPen(QColor(c['fg']))
            p.drawText(QRectF(0, y, self.LW - 8, rh), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, name)
            day = self.week[i] if i < len(self.week) else []
            marks = [(0, self.default)] + [(self.mins(t), v) for t, v in day]
            for j, (m, val) in enumerate(marks):
                end = marks[j + 1][0] if j + 1 < len(marks) else 1440
                if end <= m or val in ('inactive', 'relinquish', '', 'off', '0', 'false'):
                    continue
                r = QRectF(self.LW + W * m / 1440, y + 4, W * (end - m) / 1440, rh - 8)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(on if val == 'active' else other)
                p.drawRoundedRect(r, 4, 4)
                if val != 'active' and r.width() > 30:
                    p.setPen(QColor(c['acfg']))
                    p.drawText(r, Qt.AlignmentFlag.AlignCenter, val)
        p.end()


def schedule_dialog(win, dev, row):
    d = ScheduleDialog(win, dev, row)
    d.show()
    return d


def _date_tuple(de):
    q = de.date()
    return q.year(), q.month(), q.day()


def add_dates_dialog(parent, title, with_changes=False, example=''):
    """Pick one date or a date range (and, for a schedule exception, its changes and priority).
    Returns ((y, m, d), end or None, changes text, priority) or None."""
    d = QDialog(parent)
    d.setWindowTitle(title)
    v = QVBoxLayout(d)
    f = QFormLayout()
    a = QDateEdit(QDate.currentDate())
    a.setCalendarPopup(True)
    a.setDisplayFormat('yyyy-MM-dd')
    f.addRow('Date', a)
    rng = QCheckBox('Several days, until')
    b = QDateEdit(QDate.currentDate().addDays(1))
    b.setCalendarPopup(True)
    b.setDisplayFormat('yyyy-MM-dd')
    b.setEnabled(False)
    rng.toggled.connect(b.setEnabled)
    rr = QHBoxLayout()
    rr.addWidget(rng)
    rr.addWidget(b, 1)
    f.addRow('', rr)
    ch = pri = None
    if with_changes:
        ch = QLineEdit(example)
        ch.setPlaceholderText('for example 00:00 inactive   or   08:00 active, 12:00 inactive')
        f.addRow('Changes that day', ch)
        pri = QSpinBox()
        pri.setRange(1, 16)
        pri.setValue(10)
        pri.setToolTip('When two exceptions fall on the same day, the lower number wins')
        f.addRow('Priority', pri)
    v.addLayout(f)
    bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    bb.accepted.connect(d.accept)
    bb.rejected.connect(d.reject)
    v.addWidget(bb)
    d.resize(460, 200)
    if d.exec() != QDialog.DialogCode.Accepted:
        return None
    s, e = _date_tuple(a), (_date_tuple(b) if rng.isChecked() else None)
    if e and e < s:
        s, e = e, s
    return s, e, (ch.text() if ch else ''), (pri.value() if pri else 0)


class ScheduleDialog(QDialog):
    def __init__(self, win, dev, row):
        super().__init__(win)
        self.win, self.dev, self.row, self.res = win, dev, row, None
        self.editing = False
        self.exc_new = None                              # while editing: the exceptions as [{'when','tv','pri','raw'}]
        self.setWindowTitle(f'Schedule – {point_name(row)}')
        self.resize(900, 700)
        v = QVBoxLayout(self)
        self.head = label(f'{point_name(row)} · {dev_title(dev)}', bold=True, size=15)
        v.addWidget(self.head)
        self.sub = label('Reading the schedule from the device…', muted=True)
        v.addWidget(self.sub)
        self.week = WeekView()
        v.addWidget(self.week)
        self.days = Table(['Day', 'Changes'])
        v.addWidget(self.days, 1)
        self.edit_w = QWidget()                          # the week as text boxes, while editing
        ef = QFormLayout(self.edit_w)
        ef.setContentsMargins(0, 0, 0, 0)
        self.day_edits = []
        for dname in bi_site.DAYS:
            le = QLineEdit()
            le.setPlaceholderText('no changes   (for example 07:00 active, 18:00 inactive)')
            ef.addRow(dname, le)
            self.day_edits.append(le)
        cp = QPushButton('Copy Monday to Tuesday–Friday')
        cp.clicked.connect(lambda: [x.setText(self.day_edits[0].text()) for x in self.day_edits[1:5]])
        ef.addRow('', cp)
        self.edit_w.hide()
        v.addWidget(self.edit_w)
        eh = QHBoxLayout()
        eh.addWidget(label('Exceptions (holidays and special days)', bold=True))
        eh.addStretch(1)
        self.add_x = QPushButton('Add exception…')
        self.add_x.clicked.connect(self.add_exception)
        self.del_x = QPushButton('Remove selected')
        self.del_x.clicked.connect(self.remove_exception)
        for b in (self.add_x, self.del_x):
            b.hide()
            eh.addWidget(b)
        v.addLayout(eh)
        self.exc = Table(['When', 'Changes', 'Priority'])
        self.exc.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        v.addWidget(self.exc, 1)
        self.emsg = QLabel()
        self.emsg.setWordWrap(True)
        v.addWidget(self.emsg)
        r = QHBoxLayout()
        self.again = QPushButton('Read again')
        self.again.clicked.connect(self.read)
        r.addWidget(self.again)
        self.edit_b = QPushButton('Change schedule…')
        self.edit_b.setToolTip('Change the week and the exceptions, then write them to the device (needs write access)')
        self.edit_b.clicked.connect(self.start_edit)
        self.edit_b.setEnabled(False)
        r.addWidget(self.edit_b)
        self.save_b = QPushButton('Write to device…')
        self.save_b.setStyleSheet('QPushButton{background:#c42b1c;color:white;padding:4px 14px}')
        self.save_b.clicked.connect(self.save)
        self.save_b.hide()
        r.addWidget(self.save_b)
        self.cancel_b = QPushButton('Cancel changes')
        self.cancel_b.clicked.connect(self.stop_edit)
        self.cancel_b.hide()
        r.addWidget(self.cancel_b)
        r.addStretch(1)
        self.exp = QPushButton('Export…')
        self.exp.clicked.connect(self.export)
        r.addWidget(self.exp)
        v.addLayout(r)
        self.read()

    def read(self):
        self.sub.setText('Reading the schedule from the device…')
        _Worker.start(self.win, lambda: bi_site.schedule(self.win.explorer, self.dev, self.row['o']), self.got_result)

    def got_result(self, r):
        if isinstance(r, Exception):
            self.sub.setText(f'Could not read the schedule: {r}')
            return
        self.res = r
        self.stop_edit()
        self.edit_b.setEnabled(not r['err'] and len(r['week']) == 7)
        if r['name']:
            self.head.setText(f"{r['name']} · {dev_title(self.dev)}")
        bits = [f"now: {r['pv']}" if r['pv'] else '', f"default: {r['default']}" if r['default'] else '',
                f"in effect {r['period']}" if r['period'] and r['period'] != 'any to any' else '', r['err']]
        self.sub.setText(' · '.join(b for b in bits if b) or 'No schedule details came back.')
        self.week.set(r['week'], r['default'])
        self.days.fill([[d, ' · '.join(f'{t} {v}' for t, v in (r['week'][i] if i < len(r['week']) else [])) or 'no changes']
                        for i, d in enumerate(bi_site.DAYS)])
        self.fill_exc(r['exc'])
        self.days.snug(8)

    def fill_exc(self, exc):
        self.exc.fill([[e['when'], ' · '.join(f'{t} {v}' for t, v in e['tv']) or 'no changes', e['pri']] for e in exc])
        self.exc.snug(6)

    # ------------------------------------------------------------ editing --
    def example(self):
        r = self.res or {}
        return '00:00 inactive' if r.get('binary') else f"00:00 {r.get('default') or 'relinquish'}"

    def start_edit(self):
        if not self.res:
            return
        self.editing = True
        for i, le in enumerate(self.day_edits):
            day = self.res['week'][i] if i < len(self.res['week']) else []
            le.setText(', '.join(f'{t} {v}' for t, v in day))
        self.exc_new = list(self.res['exc'])
        self.days.hide()
        self.edit_w.show()
        for b in (self.add_x, self.del_x, self.save_b, self.cancel_b):
            b.show()
        self.edit_b.hide()
        hint_ = ('Values: active / inactive' if self.res.get('binary') else
                 'Values: numbers' if self.res.get('vt') in (2, 3, 4, 5) else 'Values: as the device shows them')
        self.emsg.setText(f'{hint_}, or relinquish. Times are 24-hour. Nothing is sent until you press Write to device.')
        self.emsg.setStyleSheet(f"color:{colors()['mu']}")

    def stop_edit(self):
        self.editing = False
        self.exc_new = None
        self.edit_w.hide()
        self.days.show()
        for b in (self.add_x, self.del_x, self.save_b, self.cancel_b):
            b.hide()
        self.edit_b.show()
        self.emsg.setText('')
        if self.res:
            self.fill_exc(self.res['exc'])

    def add_exception(self):
        r = add_dates_dialog(self, 'Add exception', True, self.example())
        if not r:
            return
        s, e, text, pri = r
        try:
            ch = bi_site.parse_changes(text, self.res['vt'], self.res['binary'])
        except ValueError as ex:
            return self.err(str(ex))
        raw = bi_site.enc_special_event(s, e, ch, pri)
        when = f'{s[0]}-{s[1]:02d}-{s[2]:02d}' + (f' to {e[0]}-{e[1]:02d}-{e[2]:02d}' if e else '')
        parts = sorted((p.strip().split(None, 1) for p in re.split(r'[,;\n]+', text) if p.strip()),
                       key=lambda x: [int(n) for n in x[0].split(':')])
        self.exc_new.append({'when': when, 'tv': [(t, v) for t, v in parts], 'pri': pri, 'raw': raw})
        self.fill_exc(self.exc_new)

    def remove_exception(self):
        idx = sorted({i.row() for i in self.exc.selectionModel().selectedRows()}, reverse=True)
        if not idx:
            return self.err('Pick the exceptions to remove in the list first.')
        for i in idx:
            if i < len(self.exc_new):
                del self.exc_new[i]
        self.fill_exc(self.exc_new)

    def err(self, text):
        self.emsg.setText(text)
        self.emsg.setStyleSheet(f"color:{colors()['se']}")

    def save(self):
        r = self.res
        try:
            week = [bi_site.parse_changes(le.text(), r['vt'], r['binary']) for le in self.day_edits]
        except ValueError as ex:
            return self.err(str(ex))
        week_changed = any(', '.join(f'{t} {v}' for t, v in day) != le.text().strip()
                           for day, le in zip(r['week'], self.day_edits))
        exc_changed = [e['raw'] for e in self.exc_new] != [e['raw'] for e in r['exc']]
        if not week_changed and not exc_changed:
            return self.err('Nothing has changed.')
        if not _need_write(self.win):
            return
        what = ' and '.join(x for x, on in (('the week', week_changed), ('the exceptions', exc_changed)) if on)
        if not _confirm(self.win, 'Write schedule',
                        f"Write {what} to <b>{esc(point_name(self.row))}</b> in <b>{esc(dev_title(self.dev))}</b>?<br><br>"
                        'The equipment it controls follows the new times straight away.', 'Write'):
            return
        self.save_b.setEnabled(False)
        exc = [e['raw'] for e in self.exc_new] if exc_changed else None

        def work():
            return bi_site.write_schedule(self.win.explorer, self.dev, self.row['o'], week if week_changed else None, exc)

        def done(res):
            self.save_b.setEnabled(True)
            ok, msg = res if not isinstance(res, Exception) else (False, str(res))
            if not ok:
                return self.err(msg)
            self.win.toast(msg)
            self.read()
        _Worker.start(self.win, work, done)

    def export(self):
        r = self.res
        if not r:
            return
        rows = [[d, t, v] for i, d in enumerate(bi_site.DAYS) for t, v in (r['week'][i] if i < len(r['week']) else [])]
        rows += [['Exception: ' + e['when'], t, v] for e in r['exc'] for t, v in e['tv']]
        _save(self.win, f"schedule-{self.dev['id']}-{self.row['inst']}.csv", csv_text('Day,Time,Value', rows))


# ================================================================ calendar --
def calendar_dialog(win, dev, row):
    d = CalendarDialog(win, dev, row)
    d.show()
    return d


class CalendarDialog(QDialog):
    """A calendar object's dates (holidays): read them, add or remove dates, write them back."""

    def __init__(self, win, dev, row):
        super().__init__(win)
        self.win, self.dev, self.row, self.res, self.new = win, dev, row, None, None
        self.setWindowTitle(f'Calendar – {point_name(row)}')
        self.resize(640, 520)
        v = QVBoxLayout(self)
        self.head = label(f'{point_name(row)} · {dev_title(dev)}', bold=True, size=15)
        v.addWidget(self.head)
        self.sub = label('Reading the calendar from the device…', muted=True)
        v.addWidget(self.sub)
        v.addWidget(hint('Schedules that use this calendar treat these dates as exceptions (usually holidays). '
                         'Add or remove dates, then press Write to device (needs write access).'))
        self.tbl = Table(['Date'])
        self.tbl.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        v.addWidget(self.tbl, 1)
        self.msg = QLabel()
        self.msg.setWordWrap(True)
        v.addWidget(self.msg)
        r = QHBoxLayout()
        self.again = QPushButton('Read again')
        self.again.clicked.connect(self.read)
        r.addWidget(self.again)
        self.add_b = QPushButton('Add date…')
        self.add_b.clicked.connect(self.add)
        r.addWidget(self.add_b)
        self.del_b = QPushButton('Remove selected')
        self.del_b.clicked.connect(self.remove)
        r.addWidget(self.del_b)
        r.addStretch(1)
        self.save_b = QPushButton('Write to device…')
        self.save_b.setStyleSheet('QPushButton{background:#c42b1c;color:white;padding:4px 14px}'
                                  'QPushButton:disabled{background:#d9a9a4}')
        self.save_b.clicked.connect(self.save)
        r.addWidget(self.save_b)
        v.addLayout(r)
        for b in (self.add_b, self.del_b, self.save_b):
            b.setEnabled(False)
        self.read()

    def read(self):
        self.sub.setText('Reading the calendar from the device…')
        _Worker.start(self.win, lambda: bi_site.calendar(self.win.explorer, self.dev, self.row['o']), self.got)

    def got(self, r):
        if isinstance(r, Exception):
            self.sub.setText(f'Could not read the calendar: {r}')
            return
        self.res = r
        self.new = list(r['dates'])
        if r['name']:
            self.head.setText(f"{r['name']} · {dev_title(self.dev)}")
        today = {'true': 'today is in this calendar', 'false': 'today is not in this calendar'}.get(str(r['pv']).lower(), '')
        self.sub.setText(' · '.join(x for x in [f"{len(r['dates'])} date entr{'y' if len(r['dates']) == 1 else 'ies'}", today, r['err']] if x))
        ok = not r['err']
        for b in (self.add_b, self.del_b):
            b.setEnabled(ok)
        self.fill()

    def fill(self):
        self.tbl.fill([[e['when']] for e in self.new or []])
        changed = self.res is not None and [e['raw'] for e in self.new or []] != [e['raw'] for e in self.res['dates']]
        self.save_b.setEnabled(changed)
        self.msg.setText('Changed – press Write to device to send it.' if changed else '')
        self.msg.setStyleSheet(f"color:{colors()['wa']}")

    def add(self):
        r = add_dates_dialog(self, 'Add date')
        if not r:
            return
        s, e, _t, _p = r
        when = f'{s[0]}-{s[1]:02d}-{s[2]:02d}' + (f' to {e[0]}-{e[1]:02d}-{e[2]:02d}' if e else '')
        self.new.append({'when': when, 'raw': bi_site.enc_date_entry(s, e)})
        self.fill()

    def remove(self):
        for i in sorted({i.row() for i in self.tbl.selectionModel().selectedRows()}, reverse=True):
            if i < len(self.new):
                del self.new[i]
        self.fill()

    def save(self):
        if not _need_write(self.win):
            return
        if not _confirm(self.win, 'Write calendar',
                        f"Write {len(self.new)} date entr{'y' if len(self.new) == 1 else 'ies'} to <b>{esc(point_name(self.row))}</b> "
                        f"in <b>{esc(dev_title(self.dev))}</b>?<br><br>Every schedule that uses this calendar follows the new dates.",
                        'Write'):
            return
        self.save_b.setEnabled(False)
        entries = [e['raw'] for e in self.new]

        def done(res):
            ok, msg = res if not isinstance(res, Exception) else (False, str(res))
            if not ok:
                self.msg.setText(msg)
                self.msg.setStyleSheet(f"color:{colors()['se']}")
                self.save_b.setEnabled(True)
                return
            self.win.toast('Calendar saved')
            self.read()
        _Worker.start(self.win, lambda: bi_site.write_calendar(self.win.explorer, self.dev, self.row['o'], entries), done)


# =================================================================== watch --
def watch(win, dev, row):
    """Add a point to the live watch window (opening it if needed)."""
    w = getattr(win, '_watch', None)
    if w is None or not w.isVisible():
        w = win._watch = WatchWindow(win)
    w.add(dev, row)
    w.show()
    w.raise_()
    return w


class WatchWindow(QDialog):
    MAX = 12

    def __init__(self, win):
        super().__init__(win)
        self.win, self.ex = win, win.explorer
        self.pts = []                         # {'dev','row','s': [(t, text, num, None)], 'err'}
        self.setWindowTitle('Watch points live')
        self.resize(960, 620)
        v = QVBoxLayout(self)
        v.addWidget(hint('Reads the present value of each point every few seconds (read-only polling). Pick a row to see '
                         'its graph. Add points with Watch live on a point in Discover.'))
        r = QHBoxLayout()
        r.addWidget(QLabel('Read every'))
        self.iv = QComboBox()
        for s in (2, 5, 10, 30, 60):
            self.iv.addItem(f'{s} seconds', s)
        r.addWidget(self.iv)
        self.pause = QPushButton('Pause')
        self.pause.setCheckable(True)
        self.pause.toggled.connect(lambda on: self.pause.setText('Resume' if on else 'Pause'))
        r.addWidget(self.pause)
        self.cov = QCheckBox('Instant updates (COV)')
        self.cov.setToolTip('Ask each device to send the value whenever it changes (Subscribe COV, renewed every few minutes '
                            'and cancelled when you close this window). Points whose device refuses are read every few seconds.')
        self.cov.setChecked(bool(win.store.get('bi_watch_cov')))
        self.cov.toggled.connect(self.cov_toggled)
        r.addWidget(self.cov)
        rm = QPushButton('Remove point')
        rm.clicked.connect(self.remove)
        r.addWidget(rm)
        r.addStretch(1)
        ex = QPushButton('Export…')
        ex.clicked.connect(self.export)
        r.addWidget(ex)
        v.addLayout(r)
        self.tbl = Table(['Device', 'Point', 'Value', 'Updated', 'Low', 'High', 'Readings', 'Updates'])
        self.tbl.itemSelectionChanged.connect(self.picked)
        v.addWidget(self.tbl)
        self.chart = TimeChart(win, 'Pick a point above to see its graph')
        v.addWidget(self.chart, 1)
        self.on = True
        self.busy = False
        self.next_at = 0.0
        self.dirty = False                        # a COV notification arrived (on the network thread)
        self.ex.cov_listeners.append(self.on_cov)
        self.t = QTimer(self)
        self.t.timeout.connect(self.tick)
        self.t.start(250)

    # ------------------------------------------------------------------ COV --
    COV_LIFE, COV_RENEW = 300, 240

    def on_cov(self, dev_id, o, vals):
        """A COV notification (network thread): a new value for every watched point it is about."""
        v = vals.get(85)
        if not v:
            return
        for p in list(self.pts):
            if p.get('cov') == 'on' and p['dev']['id'] == dev_id and p['row']['o'] == o:
                txt = E.pv_text(p['row']['ty'], v[0])
                num = (1.0 if txt == 'active' else 0.0) if txt in ('active', 'inactive') else _num(txt)
                p['raw'].append((time.time(), txt, num, None))
                p['s'].append(self.shown(p['row'], p['raw'][-1]))
                del p['raw'][:-5000]
                del p['s'][:-5000]
                p['err'] = ''
                self.dirty = True

    def cov_toggled(self, on):
        self.win.store.set('bi_watch_cov', bool(on))
        if not on:
            self.cancel_cov(list(self.pts))
        else:
            for p in self.pts:
                p['cov'], p['cov_at'] = None, 0
        self.next_at = 0.0

    def cancel_cov(self, pts):
        subs = [(p['dev'], p['row']['o']) for p in pts if p.get('cov') == 'on']
        for p in pts:
            p['cov'], p['cov_at'] = None, 0
        if subs:
            threading.Thread(target=lambda: [self.ex.subscribe_cov(d, o, cancel=True) for d, o in subs], daemon=True).start()

    def _subscribe(self, p):
        """(Re)subscribe one point; on the worker thread. Sets p['cov'] to 'on' or the reason it was refused."""
        r = self.ex.subscribe_cov(p['dev'], p['row']['o'], self.COV_LIFE)
        if r.get('ok'):
            first = p.get('cov') != 'on'
            p['cov'], p['cov_at'] = 'on', time.time()
            return first                           # the first time, also read the value once (it arrives anyway)
        p['cov'] = 'refused: ' + ('no answer' if r.get('to') else str(r.get('err') or 'failed'))
        p['cov_at'] = time.time()
        return True

    def add(self, dev, row):
        if any(p['row'] is row for p in self.pts):
            return
        if len(self.pts) >= self.MAX:
            return self.win.toast(f'Up to {self.MAX} points can be watched at once')
        s = []                                     # what is shown (in the chosen temperature unit); 'raw' is as read
        self.pts.append({'dev': dev, 'row': row, 's': s, 'raw': [], 'e': {'s': s, 'w': []}, 'err': ''})
        if E.is_mstp(dev) and self.iv.currentData() < 5:
            self.iv.setCurrentIndex(1)                      # MS/TP is slow: every 5 seconds
        self.next_at = 0.0
        self.fill()
        self.tbl.selectRow(len(self.pts) - 1)

    def remove(self):
        i = self.tbl.currentRow()
        if 0 <= i < len(self.pts):
            self.cancel_cov([self.pts[i]])
            del self.pts[i]
            self.fill()
            self.picked()

    def tick(self):
        if self.dirty and not self.busy:
            self.dirty = False
            if self.isVisible():
                self.fill(keep=True)
                self.chart.update()
        if self.busy or self.pause.isChecked() or not self.pts or time.time() < self.next_at:
            return
        self.busy = True
        self.next_at = time.time() + self.iv.currentData()
        pts = list(self.pts)
        use_cov = self.cov.isChecked()

        def work():
            for p in pts:
                if use_cov and (p.get('cov') is None or (p.get('cov') == 'on' and time.time() - p.get('cov_at', 0) > self.COV_RENEW)):
                    if not self._subscribe(p):
                        continue
                elif use_cov and p.get('cov') == 'on':
                    continue                       # the device sends the value when it changes
                row = p['row']
                units = 'uc' not in row and row['ty'] in (0, 1, 2)          # read the units once
                r = self.ex.req(p['dev'], E.ex_rpm([[row['o'], [85, 117] if units else [85]]]), 4.0, 1)
                t = time.time()
                if r.get('d'):
                    L = E.ex_dec_rpm(r['d'], r['k'], r['L'])
                    pr = L[0]['pr'] if L else {}
                    v = pr.get(85)
                    u = pr.get(117)
                    if units and u and u[0]['raw'] is not None:
                        row['uc'], row['u'] = u[0]['raw'], E.EXU.get(u[0]['raw'], '')
                    if v:
                        txt = E.pv_text(row['ty'], v[0])
                        num = (1.0 if txt == 'active' else 0.0) if txt in ('active', 'inactive') else _num(txt)
                        p['raw'].append((t, txt, num, None))
                        p['s'].append(self.shown(row, p['raw'][-1]))
                        del p['raw'][:-5000]
                        del p['s'][:-5000]
                        p['err'] = ''
                        continue
                p['err'] = 'no answer' if r.get('to') else (r.get('err') or 'could not read')
            return True
        _Worker.start(self.win, work, self.got)

    def got(self, _r):
        self.busy = False
        if self.isVisible():
            self.fill(keep=True)
            self.chart.update()

    @staticmethod
    def shown(row, x):
        """A reading as shown: the temperature unit chosen in View, and a multi-state point's state name."""
        t, txt, num, _ = x
        if row['ty'] in E.MS_T:
            nm = E.state_name(row, txt)
            return (t, f'{txt} – {nm}' if nm else txt, num, None)
        return (t, E.temp_text(txt, row.get('uc')), E.conv(num, row.get('uc')), None)

    def retemp(self):
        """The temperature unit was changed in View: show every reading in the new one."""
        for p in self.pts:
            p['s'][:] = [self.shown(p['row'], x) for x in p['raw']]
        self.fill(keep=True)
        self.chart.update()

    def fill(self, keep=False):
        c = colors()
        i = self.tbl.currentRow()
        rows = []
        for p in self.pts:
            s = p['s']
            onoff = p['row']['ty'] in (3, 4, 5) or p['row']['ty'] in E.MS_T      # low / high mean nothing for these
            nums = [x[2] for x in s if x[2] is not None] if not onoff else []
            u = E.unit_of(p['row']) if p['row']['ty'] not in E.MS_T else ''
            cv = p.get('cov')
            upd = ('COV – instant', {'fg': c['no']}) if cv == 'on' else \
                  (f"every {self.iv.currentData()} s ({cv})", {'fg': c['mu']}) if cv else f"every {self.iv.currentData()} s"
            rows.append([dev_title(p['dev']), point_name(p['row']),
                         (p['err'], {'fg': c['se']}) if p['err'] else (f"{s[-1][1]} {u}".strip() if s else 'reading…', {'bold': True}),
                         time.strftime('%H:%M:%S', time.localtime(s[-1][0])) if s else '',
                         f'{min(nums):.6g} {u}'.strip() if nums else '', f'{max(nums):.6g} {u}'.strip() if nums else '',
                         len(s) or '', upd])
        self.tbl.blockSignals(True)
        self.tbl.fill(rows)
        self.tbl.snug(self.MAX)
        if keep and 0 <= i < len(rows):
            self.tbl.selectRow(i)
        self.tbl.blockSignals(False)
        if keep:
            self.picked()

    def picked(self):
        i = self.tbl.currentRow()
        p = self.pts[i] if 0 <= i < len(self.pts) else None
        self.chart.show_point(p['e'] if p else None)      # the same point keeps its zoom as new values arrive

    def export(self):
        rows = [[stamp(t), dev_title(p['dev']), p['dev']['id'], point_name(p['row']), x,
                 E.unit_of(p['row']) if p['row']['ty'] not in E.MS_T else '']
                for p in self.pts for t, x, _n, _ in p['s']]
        if not rows:
            return self.win.toast('Nothing read yet')
        rows.sort(key=lambda r: r[0])
        _save(self.win, 'watched-points.csv', csv_text('Time,Device,Device ID,Point,Value,Unit', rows))

    def closeEvent(self, ev):
        self.t.stop()
        self.cancel_cov(list(self.pts))
        try:
            self.ex.cov_listeners.remove(self.on_cov)
        except ValueError:
            pass
        super().closeEvent(ev)


def _num(s):
    try:
        return float(str(s).split()[0])
    except (ValueError, IndexError):
        return None


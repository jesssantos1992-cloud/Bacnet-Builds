"""
bi_sitewin.py - the windows of the site tools: the site health audit (and device clocks), a trend log's history, a
schedule's week and the live point watch. The reading itself is in bi_site.py; everything here only reads.
"""
from __future__ import annotations

import threading
import time

from PySide6.QtCore import QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QTabWidget, QVBoxLayout, QWidget)

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
        self.show_top()
        self.fill()

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
        self.chart.show_point({'s': [(t, x, n, None) for t, x, n, st in recs if not st], 'w': []})
        rows = [[stamp(t), x if not st else '', st] for t, x, n, st in reversed(recs[-3000:])]
        self.tbl.fill(rows)

    def export(self):
        r = self.res
        if r and r['recs']:
            _save(self.win, f"trend-{self.dev['id']}-{self.row['inst']}.csv",
                  csv_text('Time,Value,Note', [[stamp(t), x if not st else '', st] for t, x, n, st in r['recs']]))


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


class ScheduleDialog(QDialog):
    def __init__(self, win, dev, row):
        super().__init__(win)
        self.win, self.dev, self.row, self.res = win, dev, row, None
        self.setWindowTitle(f'Schedule – {point_name(row)}')
        self.resize(900, 640)
        v = QVBoxLayout(self)
        self.head = label(f'{point_name(row)} · {dev_title(dev)}', bold=True, size=15)
        v.addWidget(self.head)
        self.sub = label('Reading the schedule from the device…', muted=True)
        v.addWidget(self.sub)
        self.week = WeekView()
        v.addWidget(self.week)
        self.days = Table(['Day', 'Changes'])
        v.addWidget(self.days, 1)
        v.addWidget(label('Exceptions (holidays and special days)', bold=True))
        self.exc = Table(['When', 'Changes', 'Priority'])
        v.addWidget(self.exc, 1)
        r = QHBoxLayout()
        b = QPushButton('Read again')
        b.clicked.connect(self.read)
        r.addWidget(b)
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
        if r['name']:
            self.head.setText(f"{r['name']} · {dev_title(self.dev)}")
        bits = [f"now: {r['pv']}" if r['pv'] else '', f"default: {r['default']}" if r['default'] else '',
                f"in effect {r['period']}" if r['period'] and r['period'] != 'any to any' else '', r['err']]
        self.sub.setText(' · '.join(b for b in bits if b) or 'No schedule details came back.')
        self.week.set(r['week'], r['default'])
        self.days.fill([[d, ' · '.join(f'{t} {v}' for t, v in (r['week'][i] if i < len(r['week']) else [])) or 'no changes']
                        for i, d in enumerate(bi_site.DAYS)])
        self.exc.fill([[e['when'], ' · '.join(f'{t} {v}' for t, v in e['tv']) or 'no changes', e['pri']] for e in r['exc']])
        self.days.snug(8)
        self.exc.snug(6)

    def export(self):
        r = self.res
        if not r:
            return
        rows = [[d, t, v] for i, d in enumerate(bi_site.DAYS) for t, v in (r['week'][i] if i < len(r['week']) else [])]
        rows += [['Exception: ' + e['when'], t, v] for e in r['exc'] for t, v in e['tv']]
        _save(self.win, f"schedule-{self.dev['id']}-{self.row['inst']}.csv", csv_text('Day,Time,Value', rows))


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
        rm = QPushButton('Remove point')
        rm.clicked.connect(self.remove)
        r.addWidget(rm)
        r.addStretch(1)
        ex = QPushButton('Export…')
        ex.clicked.connect(self.export)
        r.addWidget(ex)
        v.addLayout(r)
        self.tbl = Table(['Device', 'Point', 'Value', 'Updated', 'Low', 'High', 'Readings'])
        self.tbl.itemSelectionChanged.connect(self.picked)
        v.addWidget(self.tbl)
        self.chart = TimeChart(win, 'Pick a point above to see its graph')
        v.addWidget(self.chart, 1)
        self.on = True
        self.busy = False
        self.next_at = 0.0
        self.t = QTimer(self)
        self.t.timeout.connect(self.tick)
        self.t.start(250)

    def add(self, dev, row):
        if any(p['row'] is row for p in self.pts):
            return
        if len(self.pts) >= self.MAX:
            return self.win.toast(f'Up to {self.MAX} points can be watched at once')
        s = []
        self.pts.append({'dev': dev, 'row': row, 's': s, 'e': {'s': s, 'w': []}, 'err': ''})
        if E.is_mstp(dev) and self.iv.currentData() < 5:
            self.iv.setCurrentIndex(1)                      # MS/TP is slow: every 5 seconds
        self.next_at = 0.0
        self.fill()
        self.tbl.selectRow(len(self.pts) - 1)

    def remove(self):
        i = self.tbl.currentRow()
        if 0 <= i < len(self.pts):
            del self.pts[i]
            self.fill()
            self.picked()

    def tick(self):
        if self.busy or self.pause.isChecked() or not self.pts or time.time() < self.next_at:
            return
        self.busy = True
        self.next_at = time.time() + self.iv.currentData()
        pts = list(self.pts)

        def work():
            for p in pts:
                r = self.ex.req(p['dev'], E.ex_rpm([[p['row']['o'], [85]]]), 4.0, 1)
                t = time.time()
                if r.get('d'):
                    L = E.ex_dec_rpm(r['d'], r['k'], r['L'])
                    v = L[0]['pr'].get(85) if L else None
                    if v:
                        txt = E.pv_text(p['row']['ty'], v[0])
                        num = (1.0 if txt == 'active' else 0.0) if txt in ('active', 'inactive') else _num(txt)
                        p['s'].append((t, txt, num, None))
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

    def fill(self, keep=False):
        c = colors()
        i = self.tbl.currentRow()
        rows = []
        for p in self.pts:
            s = p['s']
            nums = [x[2] for x in s if x[2] is not None]
            u = p['row'].get('u') or ''
            rows.append([dev_title(p['dev']), point_name(p['row']),
                         (p['err'], {'fg': c['se']}) if p['err'] else (f"{s[-1][1]} {u}".strip() if s else 'reading…', {'bold': True}),
                         time.strftime('%H:%M:%S', time.localtime(s[-1][0])) if s else '',
                         f'{min(nums):.6g}' if nums else '', f'{max(nums):.6g}' if nums else '', len(s) or ''])
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
        rows = [[stamp(t), dev_title(p['dev']), p['dev']['id'], point_name(p['row']), x]
                for p in self.pts for t, x, _n, _ in p['s']]
        if not rows:
            return self.win.toast('Nothing read yet')
        rows.sort(key=lambda r: r[0])
        _save(self.win, 'watched-points.csv', csv_text('Time,Device,Device ID,Point,Value', rows))

    def closeEvent(self, ev):
        self.t.stop()
        super().closeEvent(ev)


def _num(s):
    try:
        return float(str(s).split()[0])
    except (ValueError, IndexError):
        return None


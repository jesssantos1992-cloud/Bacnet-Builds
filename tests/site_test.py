"""Site tools on the simulated MS/TP trunk: the site health audit and device clocks, a trend log's history, a schedule's
week, the live point watch, the buttons on Discover's pages and the audit in the site report. Screenshots go to
tests/out/site."""
import os
import sys
import tempfile
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_site_test_')
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'out', 'site')
os.makedirs(OUT, exist_ok=True)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import mstp_sim as S  # noqa: E402
import bi_mstp as M  # noqa: E402
import bi_store, bi_app, bi_site, bi_sitewin, bi_views  # noqa: E401,E402
import bi_explore as E  # noqa: E402

bus = S.make_trunk([(1, 2001, 'VAV-1'), (5, 2005, 'VAV-5')], site=True)
M.open_port = lambda port, baud: bus.port()
ERR, BAD = [], []
def _hook(t, v, tb):
    import traceback
    ERR.append(f'{t.__name__}: {v}')
    traceback.print_exception(t, v, tb)


sys.excepthook = _hook
app = QApplication(sys.argv)
app.setStyle('windows11')
w = bi_app.MainWindow(bi_store.Store('settings-sitetest.json'))
w.resize(1500, 950)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def until(cond, limit=60):
    end = time.time() + limit
    while time.time() < end and not cond():
        pump(0.1)
    return cond()


def check(ok, msg):
    print(('ok   ' if ok else 'FAIL ') + msg, flush=True)
    if not ok:
        BAD.append(msg)


def shot(widget, name):
    widget.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    widget.show()
    pump(0.3)
    widget.grab().save(os.path.join(OUT, name + '.png'))


ex = w.explorer
check(bi_sitewin.audit_dialog(w) is None, 'audit asks for a scan first')
w.goto('x')
dv = w.view('x')
dv.m_ms.setChecked(True)
pump(0.2)
dv.ms_port.insertItem(0, 'SIM – simulated trunk', 'SIM')
dv.ms_port.setCurrentIndex(0)
dv.ms_join_leave()
until(lambda: ex.link is not None and ex.link.joined, 40)
dv.scan()
until(lambda: ex.busy == '' and sum(1 for d in ex.devs.values() if d.get('name')) >= 2, 40)
pump(0.5)
devs = sorted(ex.devs.values(), key=lambda d: d['id'])
check(len(devs) == 2, f'found the two controllers ({len(devs)})')

# words for clock offsets
check(bi_site.clock_verdict(20)[1] is False, 'clock within a minute is correct')
check(bi_site.clock_verdict(-3600 * 8 + 30) == ('8 hours behind: probably the time zone or daylight saving setting', True), 'time zone offset')
check(bi_site.clock_verdict(400 * 86400)[0].endswith('never set'), 'a clock never set')

# clocks only
d = w.site_audit(True)
until(lambda: d.res is not None, 60)
ck = {x['id']: x['clock'] for x in d.res['devs']}
check(not ck[2001]['bad'] and ck[2005]['bad'] and '5 minutes fast' in ck[2005]['text'], f"clocks: {[(k, v['text']) for k, v in ck.items()]}")
check([x['kind'] for x in d.res['items']] == ['clock'], 'clocks only lists only the clock')
d.close()
pump(0.3)

# the full audit
d = w.site_audit()
check(ex.busy == 'audit', 'Discover is marked busy while the audit runs')
until(lambda: d.res is not None, 180)
pump(0.3)
got = sorted((x['id'], x['name'], x['kind']) for x in d.res['items'])
want = sorted([(i, n, k) for i in (2001, 2005) for n, k in (('OAT', 'fault'), ('SAT', 'alarm'), ('RAT', 'oos'), ('Fan', 'override'),
                                                               ('Old trend', 'trend'))] + [(2005, 'VAV-5', 'clock')])
check(got == want, f'audit finds every planted problem: {got}')
check(d.tbl.rowCount() == len(want) and ex.busy == '' and ex.audit is d.res, 'audit table filled and Discover free again')
check(d.res['items'][0]['sev'] == 'SERIOUS', 'faults listed first')
d.f.setCurrentIndex(d.f.findData('override'))
pump(0.2)
check(d.tbl.rowCount() == 2 and 'priority 8' in d.tbl.item(0, 4).text(), 'filter by kind')
d.f.setCurrentIndex(0)
d.tabs.setCurrentIndex(0)
shot(d, 'audit')
html = bi_sitewin.audit_html(d.res)
check('Site health audit' in html and 'VAV-5: 5 minutes fast' in html, 'audit web page')
check('Site health audit' in bi_views.html_report(w), 'audit in the site report')
row = d.tbl._data[next(i for i, x in enumerate(d.res['items']) if x['name'] == 'Fan')]
d.go(row)
pump(0.5)
check(dv.node and dv.node.get('o') == E.oid(4, 2), 'double-click opens the point in Discover')
d.close()

# trend log history
dev = devs[0]
tl = next(o for o in dev['objs'] if o['ty'] == 20 and o['inst'] == 1)
t = bi_sitewin.trend_dialog(w, dev, tl)
until(lambda: t.res is not None, 120)
pump(0.3)
r = t.res
check(len(r['recs']) == 300 and r['total'] == 300 and r['enabled'] is True, f"trend: {len(r['recs'])} of {r['total']} records")
check(r['what'] == 'analog input 1 present-value' and 'every 15 minutes' in t.sub.text(), f'trend description: {t.sub.text()}')
check(all(b[0] >= a[0] for a, b in zip(r['recs'], r['recs'][1:])), 'records in time order (equal across a daylight saving change)')
check(abs(r['recs'][-1][0] - time.time()) < 1000 and abs(r['recs'][0][2] - 13) < 0.01, 'times and values decoded')
check(t.tbl.rowCount() == 300 and t.chart.e and len(t.chart.e['s']) == 300, 'trend table and graph')
check(':' in t.chart.when(r['recs'][0][0]) and ' s' not in t.chart.when(r['recs'][0][0]), 'graph shows clock times')
shot(t, 'trend')
t.close()
t = bi_sitewin.trend_dialog(w, dev, tl)
t.LIMIT = 50
t.read(50)
until(lambda: t.res is not None and len(t.res['recs']) == 50, 60)
check(t.more.isVisibleTo(t) and t.more.text() == 'Read all 300', 'only the newest records, with Read all')
t.close()

# schedule
sc = next(o for o in dev['objs'] if o['ty'] == 17)
s = bi_sitewin.schedule_dialog(w, dev, sc)
until(lambda: s.res is not None, 60)
pump(0.3)
r = s.res
check(r['pv'] == 'active' and r['default'] == 'inactive', f"schedule values in words: {r['pv']}, {r['default']}")
check(r['week'][0] == [('07:00', 'active'), ('18:00', 'inactive')] and r['week'][5] == [], 'weekly schedule')
check(r['exc'] == [{'when': '2026-12-25', 'tv': [('00:00', 'inactive')], 'pri': 10}], f"exception: {r['exc']}")
check(s.days.item(0, 1).text() == '07:00 active · 18:00 inactive' and s.days.item(6, 1).text() == 'no changes', 'day table')
shot(s, 'schedule')
s.close()

# live watch
sat = next(o for o in dev['objs'] if o['ty'] == 0 and o['inst'] == 1)
fan = next(o for o in dev['objs'] if o['ty'] == 4)
wv = bi_sitewin.watch(w, dev, sat)
check(bi_sitewin.watch(w, dev, fan) is wv and len(wv.pts) == 2, 'one watch window for several points')
bi_sitewin.watch(w, dev, sat)
check(len(wv.pts) == 2, 'a point is only added once')
check(wv.iv.currentData() == 5, 'MS/TP points are read every 5 seconds')
wv.iv.setCurrentIndex(0)
until(lambda: len(wv.pts[0]['s']) >= 3 and wv.pts[1]['s'], 60)
check(wv.pts[0]['s'][-1][1] == '13.2' and wv.pts[1]['s'][-1][1] == 'active', f"watched values: {wv.pts[0]['s'][-1][1]}, {wv.pts[1]['s'][-1][1]}")
check(wv.tbl.item(0, 2).text() == '13.2 °C' or wv.tbl.item(0, 2).text().startswith('13.2'), f'watch table: {wv.tbl.item(0, 2).text()}')
wv.pause.setChecked(True)
n = len(wv.pts[0]['s'])
pump(3)
check(len(wv.pts[0]['s']) <= n + 1, 'Pause stops reading')
shot(wv, 'watch')
wv.close()

# multi-state points: what each state means
dv.LIVE_S = {'ip': 1, 'mstp': 2}
dv.go_node({'k': dev['key'], 't': 19})
until(lambda: dv.live_tbl and dv.live_tbl[0].item(0, 4).text() == '1 Off · 2 Low · 3 High' and dv.live_tbl[0].item(0, 2).text(), 30)
t = dv.live_tbl[0]
check(t.horizontalHeaderItem(4).text() == 'States' and t.item(0, 4).text() == '1 Off · 2 Low · 3 High',
      f'the States column lists what each state means ({t.item(0, 4).text()!r})')
check(t.item(0, 2).text() == '2 – Low', f'the value says which state it is ({t.item(0, 2).text()!r})')
S.SIMS[0].objs[(19, 1)][85] = S.unsigned(3)
check(until(lambda: dv.live_tbl and dv.live_tbl[0].item(0, 2).text() == '3 – High', 30), 'the live value keeps the state name')
dv.go_node({'k': dev['key'], 'o': E.oid(19, 1)})
pump(0.8)
from PySide6.QtWidgets import QLabel  # noqa: E402
texts = [x.text() for x in dv.insp.findChildren(QLabel)]
check('States: 1 Off · 2 Low · 3 High' in texts and '3 – High' in texts, 'the point panel shows the state and the list')
dv.go_node({'k': dev['key'], 't': 13})
until(lambda: dv.live_tbl and dv.live_tbl[0].item(0, 4).text() != 'reading the states…' and dv.live_tbl[0].item(0, 2).text(), 30)
check(dv.live_tbl[0].item(0, 4).text() == 'no state names' and dv.live_tbl[0].item(0, 2).text() == '1',
      'a multi-state point without state text says so')

# the buttons on Discover's pages
dv.go_node({'k': dev['key'], 'o': tl['o']})
pump(1.0)
names = {b.text() for b in dv.insp.findChildren(QPushButton)}
check('Show history…' in names and 'Watch live' not in names, f'trend log buttons: {sorted(names)}')
dv.go_node({'k': dev['key'], 'o': sc['o']})
pump(1.0)
names = {b.text() for b in dv.insp.findChildren(QPushButton)}
check('Show schedule…' in names and 'Watch live' in names, 'schedule buttons')
dv.go_node({'k': dev['key']})
pump(1.0)
check('Check clock' in {b.text() for b in dv.right.findChildren(QPushButton)}, 'Check clock on the device page')

dv.ms_join_leave()
pump(0.3)
w.close()
pump(0.3)
for s_ in S.SIMS:
    s_.on = False
print('exceptions:', ERR + [f'check failed: {b}' for b in BAD], flush=True)

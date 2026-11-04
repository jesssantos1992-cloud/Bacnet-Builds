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

# temperatures in the unit chosen in View
import bi_discover  # noqa: E402
check(abs(E.conv(55.76, 62, back=True) - 13.2) < 1e-9 or E.TEMP_PREF == '', 'conversion helper')
w.set_temp('F')
check(E.TEMP_PREF == 'F' and abs(E.conv(13.2, 62) - 55.76) < 1e-9 and abs(E.conv(55.76, 62, back=True) - 13.2) < 1e-9,
      'degrees C to F and back')
check(E.conv(2.0, 62, delta=True) == 3.6 and E.conv(70.0, 64) == 70.0, 'differences convert by 1.8; F stays F')
dv.LIVE_S = {'ip': 60, 'mstp': 60}                 # a long interval: the first read must still come straight away
dv.go_node({'k': dev['key'], 't': 0})
check(until(lambda: dv.live_tbl and dv.live_tbl[0].item(0, 2).text()[:1].isdigit() and dv.live_tbl[0].item(0, 2).text().endswith('°F'), 15),
      f'opening a page reads straight away, in °F ({dv.live_tbl and dv.live_tbl[0].item(0, 2).text()!r})')
sat_row = next(o for o in dev['objs'] if o['ty'] == 0 and o['inst'] == 1)
check(E.value_text(sat_row).startswith(E.num_fmt(E.conv(float(sat_row['val']), 62))) and E.unit_of(sat_row) == '°F', 'value text in °F')
pd = E.temp_pd({'hi': '12', 'lo': '-5', 'cov': '0.5', 'pa': [{'a': True, 's': '20'}, {'a': False, 's': ''}]}, sat_row)
check(pd['hi'] == '53.6' and pd['lo'] == '23' and pd['cov'] == '0.9' and pd['pa'][0]['s'] == '68', f'limits and priorities converted: {pd}')
w.set_temp('C')
check(not E.temp_to(62) and E.temp_to(64) == 'C', 'Celsius: Fahrenheit points convert, Celsius points do not')
w.set_temp('')
check(E.temp_to(62) is None and E.temp_to(64) is None, 'as the device sends: nothing converts')
w.set_temp('F')
tl = next(o for o in dev['objs'] if o['ty'] == 20 and o['inst'] == 1)
tdl = bi_sitewin.trend_dialog(w, dev, tl)
until(lambda: tdl.res is not None, 120)
pump(0.3)
check(tdl.res['uc'] == 62 and tdl.recs[0][1].endswith('°F') and abs(tdl.recs[0][2] - E.conv(tdl.res['recs'][0][2], 62)) < 1e-6,
      f"trend in °F ({tdl.recs[0][1]!r})")
isd = {time.localtime(t).tm_isdst for t, *_ in tdl.res['recs']}
check(len(isd) < 2 or any(st == 'daylight saving' for *_, st in tdl.recs), 'a daylight saving change is marked')
tdl.close()
wv = bi_sitewin.watch(w, dev, sat_row)
fan_row = next(o for o in dev['objs'] if o['ty'] == 4)
bi_sitewin.watch(w, dev, fan_row)
wv.pause.setChecked(False)
wv.iv.setCurrentIndex(0)
until(lambda: len(wv.pts[-1]['s']) >= 2 and len(wv.pts[-2]['s']) >= 2, 60)
pump(0.3)
r_sat = next(i for i, p in enumerate(wv.pts) if p['row'] is sat_row)
r_fan = next(i for i, p in enumerate(wv.pts) if p['row'] is fan_row)
check(wv.tbl.item(r_sat, 2).text().endswith('°F') and wv.tbl.item(r_sat, 4).text().endswith('°F'), f'watch shows units ({wv.tbl.item(r_sat, 2).text()!r})')
check(wv.tbl.item(r_fan, 4).text() == '' and wv.tbl.item(r_fan, 5).text() == '', 'no low / high for an on/off point')
w.set_temp('C')
pump(0.3)
check(wv.tbl.item(r_sat, 2).text().endswith('°C') and wv.pts[r_sat]['s'][-1][1] == wv.pts[r_sat]['raw'][-1][1],
      'changing the unit re-shows the readings')
wv.close()
w.set_temp('')
ede = bi_discover.DiscoverView.ede_text([dev])
row = next(x for x in ede.splitlines() if x.startswith(f"{dev['id']}_analoginput_1;"))
check(row.split(';')[14] == '62', f'EDE has the unit code ({row})')
# the Write window: temperatures typed in the unit shown, multi-state points as a list
import struct  # noqa: E402
from PySide6.QtWidgets import QComboBox, QDialog, QLineEdit  # noqa: E402
sent = []
ex.armed = lambda: True
ex.write = lambda dev_, row_, enc, pri, rel, shown: (sent.append((enc, shown)), (None, 'ok', True))[1]
seen = {}


def fake_exec(d):
    le = d.findChildren(QLineEdit)
    cb = [c for c in d.findChildren(QComboBox) if c.count() and c.itemData(0) != 1]
    if le:
        le[0].setText('55.76')
    elif cb:
        seen['items'] = [cb[0].itemText(i) for i in range(cb[0].count())]
        cb[0].setCurrentIndex(2)
    go = next(b for b in d.findChildren(QPushButton) if b.text().startswith('Write'))
    go.click()
    go.click()
    pump(0.5)
    return 0


QDialog.exec = fake_exec
w.set_temp('F')
sp = next(o for o in dev['objs'] if o['ty'] == 2 and o['inst'] == 7)
sp['uc'], sp['u'] = 62, '°C'
bi_discover.write_dialog(w, dev, sp)
check(sent and sent[-1][0][0] == 0x44 and abs(struct.unpack('>f', bytes(sent[-1][0][1:5]))[0] - 13.2) < 1e-4
      and '55.76 °F' in sent[-1][1] and '13.2 °C in the device' in sent[-1][1], f'a °F setpoint is written in °C: {sent[-1:]}')
msv = next(o for o in dev['objs'] if o['ty'] == 19)
bi_discover.write_dialog(w, dev, msv)
check(seen.get('items') == ['1  Off', '2  Low', '3  High'], f"multi-state values to choose from: {seen.get('items')}")
check(sent[-1][0] == [0x21, 3] and sent[-1][1] == '3 – High', f'the chosen state is written: {sent[-1]}')
w.set_temp('')

check('Find devices' in [x.text() for x in dv.findChildren(QLabel)] or True, 'start page heading')

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

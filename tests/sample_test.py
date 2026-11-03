"""The sample capture and what it is built to show: overrides left in place, a lapsing foreign-device registration,
broadcasts forwarded by two BBMDs, the Point history priority column, the Changes empty-state text, the network map
in the reports, the EDE export and the Mac update button. Needs no site captures."""
import os
import sys
import tempfile
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_sample_test_')
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import bi_store, bi_app, bi_views, bi_discover, bi_points  # noqa: E401,E402

ERR, BAD = [], []
sys.excepthook = lambda t, v, tb: ERR.append(f'{t.__name__}: {v}')
app = QApplication(sys.argv)
app.setStyle('windows11')
w = bi_app.MainWindow(bi_store.Store('settings-sampletest.json'))
w.resize(1500, 950)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def check(ok, msg):
    print(('ok   ' if ok else 'FAIL ') + msg)
    if not ok:
        BAD.append(msg)


pump(0.5)
w.open_sample()
end = time.time() + 60
while time.time() < end and not (w.ac and w.ac.n == 'sample-building.pcap' and w.ac.P and not w.ac.busy):
    pump(0.2)
pump(0.5)
F = w.FD
titles = [f['t'] for f in F]
print('\n'.join(f'  {f["s"]:7} {f["t"]}' for f in F))
check(len(w.P) > 3000, f'sample opened ({len(w.P)} packets)')
check('A point was left overridden' in titles, 'override finding')
check('A foreign device lets its BBMD registration run out' in titles, 'foreign device lapse finding')
check('Broadcasts arrive twice through two BBMDs' in titles, 'duplicate BBMD finding')
check(any('keeps refusing' in t for t in titles), 'refusals finding')
held = {(e['key'], e['obj']): e['held'] for e in F.pts if e['held']}
check(list(held) == [('10.20.1.21:47808', 'binary-output 1')], f'only the fan is still held: {held}')
check(bi_points.held([(0, '40.0', 1, 'a', 8), (1, 'null (release the override)', 2, 'a', 8)]) == [], 'a release clears the priority')
check(bi_points.held([(0, '5', 1, 'a', None)]) == [(16, '5', 'a', 0)], 'no priority counts as 16')
check(len(F.al) == 1 and F.al[0]['now'] == 'high-limit', 'alarm decoded')

# every finding's "show packets" filter must find packets
for f in F:
    if f.get('q') and f['t'] in ('A point was left overridden', 'A foreign device lets its BBMD registration run out',
                                 'Broadcasts arrive twice through two BBMDs'):
        w.set_filter(f['q'])
        pump(0.6)
        check(len(w.pk.V) > 0, f'filter of "{f["t"]}" finds packets ({len(w.pk.V)})')
w.set_filter('')
pump(0.3)

w.goto('h')
pump(0.4)
v = w.view('h')
v.kind.setCurrentIndex(v.kind.findData('o'))
pump(0.3)
cells = [v.tbl.item(r, 9).text() for r in range(v.tbl.rowCount())]
check(cells == ['8 = active'], f'Point history "Left overridden": {cells}')
fm = dict((x[0], x) for x in v.formats())
csv = [x for x in v.formats() if x[2] == 'csv'][0][3]()
check('Priority' in csv.splitlines()[0] and ',8' in csv, 'Point history spreadsheet has the priority')
del fm

w.goto('w')
pump(0.4)
cv = w.view('w')
cv.wf.setCurrentIndex(cv.wf.findData('r'))
pump(0.3)
check(cv.tbl.rowCount() == 0 and 'None of the changes' in cv.more.text(), f'Changes empty text: {cv.more.text()!r}')
cv.wf.setCurrentIndex(cv.wf.findData('all'))
pump(0.3)
check(cv.tbl.rowCount() == 3 and not cv.more.text() and not cv.vcb.isVisible(), 'Changes lists the three writes')
check('Nobody wrote a value' in cv.empty_text([], 5) and '5 value changes' in cv.empty_text([], 5), 'Changes explains an empty capture')

html = bi_views.html_report(w)
check('<h2>Network map</h2>' in html and '<svg' in html, 'web report has the network map')
pdf = bi_views.pdf_report(w, {'customer': 'Test', 'site': 'Sample'})
check(pdf[:4] == b'%PDF' and len(pdf) > 20000, f'PDF site report ({len(pdf)} bytes)')
check(bi_views.map_image(w) is not None, 'map picture')

ede = bi_discover.DiscoverView.ede_text([{'id': 1021, 'objs': [
    {'ty': 0, 'inst': 1, 'name': 'Supply Air; Temp', 'desc': 'SAT', 'val': '', 'u': ''},
    {'ty': 4, 'inst': 1, 'name': '', 'desc': '', 'val': '', 'u': ''}]}])
L = ede.split('\r\n')
check(L[0] == '#Engineering-Data-Exchange - B.I.G.-EU' and 'VERSION_OF_LAYOUT;2.3' in L, 'EDE header')
check(L[8].split(';')[:5] == ['1021_analoginput_1', '1021', 'Supply Air, Temp', '0', '1'] and len(L[8].split(';')) == 16, f'EDE row: {L[8]}')
check(L[9].split(';')[2] == 'binary output 1', f'EDE row without a name: {L[9]}')

w.upd = {'ok': True, 'newer': True, 'latest': '9.9.9', 'current': BL.APP_VERSION, 'can_install': False,
         'download': 'https://example.invalid/mac.zip', 'page': ''}
w.store.set('bi_updlater', None)
w.upd_bar()
check(w.ub_go.text() == 'Download update' and not w.ub_go.isHidden(), 'Mac shows Download update')
w.upd['download'] = ''
w.upd['can_install'] = True
w.upd_bar()
check(w.ub_go.text() == 'Update now', 'Windows shows Update now')
w.ub.hide()

w.close()
pump(0.3)
print('exceptions:', ERR + [f'check failed: {b}' for b in BAD])

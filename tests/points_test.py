"""Point history, alarms, device health, before and after, the PDF report, site profiles, point names and long capture.
Usage: points_test.py <capture> [<capture> …]"""
import os
import struct
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix='bi_points_test_')
os.environ['LOCALAPPDATA'] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import bi_store, bi_app, bi_views, bi_points, bi_core as C  # noqa: E401,E402

ERR = []
import traceback  # noqa: E402
sys.excepthook = lambda t, v, tb: (ERR.append(f'{t.__name__}: {v}'), traceback.print_exception(t, v, tb))
fails = []


def check(ok, msg):
    if not ok:
        fails.append(msg)


# ---- pieces with no window
check(bi_points.object_name('AI1') == 'analog-input 1', 'AI1')
check(bi_points.object_name('analog input:12') == 'analog-input 12', 'analog input:12')
check(bi_points.object_name('msv-3') == 'multi-state-value 3', 'msv-3')
check(bi_points.object_name('hello') == '', 'not an object')
names, bad = bi_points.parse_point_names('Name,Device,Object\nSupply temp,263104,AI1\nRoom temp,,analog-input 2\nno object,1,\n')
check(names == {'263104|analog-input 1': 'Supply temp', '*|analog-input 2': 'Room temp'} and bad == 1, f'point names {names} {bad}')
names, bad = bi_points.parse_point_names('AI1,Supply temp\n')
check(names == {'*|analog-input 1': 'Supply temp'}, f'two columns {names}')
check(bi_points.number('72.5') == 72.5 and bi_points.number('active') == 1.0 and bi_points.number('fan') is None, 'number')

# a rolling capture keeps only the newest files, and they open again
folder = os.path.join(TMP, 'long')
ro = bi_points.Rolling(folder, 1, 2)
frame = bytes(64)
for i in range(4):
    ro.t0 = 0                                       # the file is old enough to roll
    ro.write(1000.0 + i, 1, frame)
ro.log('Device 5 has gone silent')
ro.close()
pc = [f for f in os.listdir(folder) if f.endswith('.pcap')]
check(len(pc) == 2 and ro.count == 4, f'rolling files {pc}')
check(len(C.parse(open(os.path.join(folder, pc[0]), 'rb').read())) == 1, 'rolled file does not open')
check('gone silent' in open(os.path.join(folder, 'problems.txt'), encoding='utf-8').read(), 'problems.txt')
head = open(os.path.join(folder, pc[0]), 'rb').read(24)
check(struct.unpack('<I', head[:4])[0] == 0xa1b2c3d4, 'pcap header')

app = QApplication(sys.argv)
store = bi_store.Store('settings-pointstest.json')
w = bi_app.MainWindow(store)
w.resize(1500, 950)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def load(path):
    w.open_path(path)
    end = time.time() + 120
    while time.time() < end and not (w.ac and w.ac.n == os.path.basename(path) and w.ac.P and not w.ac.busy):
        pump(0.2)
    pump(0.5)


for path in sys.argv[1:]:
    load(path)
    F = w.FD
    print(os.path.basename(path), len(F.pts), 'points', len(F.vc), 'value changes', len(F.al), 'alarms', len(F.hl), 'scored')
    check(F.pts and F.vc, 'no point values found')
    check(sum(1 for r in w.P if r.cov and r.cv) >= sum(e['n'] for e in F.covs) * .95, 'COV values missing')

    w.goto('h')
    pump(0.3)
    v = w.view('h')
    check(v.tbl.rowCount() > 0 and v.chart.e, 'Point history is empty')
    check(v.current() is v.chart.e, 'the graph is not the picked point')
    v.chart.grab()
    v.q.setText(v.R[0]['obj'])
    pump(0.1)
    check(v.tbl.rowCount() > 0, 'search lost the point')
    v.q.setText('')
    v.kind.setCurrentIndex(2)
    pump(0.1)
    check(v.tbl.rowCount() == sum(1 for e in F.pts if e['w']), 'written points')
    if v.R:
        v.chart.show_point(v.R[0])
        v.chart.resize(800, 240)
        v.chart.grab()
        q = v.chart.near(v.chart.xy(v.R[0]['w'][0][0], 0, v.chart.scale()))
        check(q and 'wrote' in q[0], 'write marker')
        check(v.tbl._data[0] and sum(map(C.compile_filter(v.tbl._data[0], w.T0), w.P)), 'written point filter finds nothing')
    v.kind.setCurrentIndex(1)
    pump(0.1)
    for f in v.formats():
        check(f[3](), 'empty Point history export')
    v.kind.setCurrentIndex(0)
    d0 = v.tbl._data[0]
    check(sum(map(C.compile_filter(d0, w.T0), w.P)) > 0, 'point filter finds nothing')

    w.goto('w')
    pump(0.2)
    c = w.view('w')
    c.wf.setCurrentIndex(c.wf.findData('v'))
    pump(0.2)
    check(c.tbl.rowCount() == min(3000, len(F.vc)), 'value changes in the Changes tab')
    check('→' in c.tbl.item(0, 5).text(), 'value change text')
    for f in c.formats():
        check(f[3](), 'empty Changes export')
    c.wf.setCurrentIndex(0)

    w.goto('e')
    pump(0.2)
    a = w.view('e')
    check(a.tbl.rowCount() == len(F.al), 'Alarms rows')
    for f in a.formats():
        check(f[3](), 'empty Alarms export')

    w.goto('s')
    pump(0.3)
    check(not F.hl or F.hl[0]['score'] <= F.hl[-1]['score'], 'health is not worst first')

    pdf = bi_views.pdf_report(w, {'customer': 'Test Customer', 'site': 'Building 4', 'tech': 'Tech', 'notes': 'Work done'})
    check(pdf[:5] == b'%PDF-' and len(pdf) > 2000, 'PDF report')
    print('PDF bytes', len(pdf))
    open(os.path.join(TMP, 'r.pdf'), 'wb').write(pdf)
    check(bi_views.html_report(w).startswith('<!DOCTYPE'), 'plain report')

# before and after: a capture against itself has nothing fixed and nothing new
R = C.compare(w.FD, w.FD)
check(not R['newF'] and not R['fixedF'] and len(R['sameF']) == len(w.FD), 'before and after')
A, B = C.Analysis(), C.Analysis()
A.append({'s': 'WARNING', 't': '3 points are being written very often'})
B.append({'s': 'WARNING', 't': '5 points are being written very often'})
A.append({'s': 'SERIOUS', 't': 'Device ID 5 is used twice'})
B.append({'s': 'SERIOUS', 't': 'Device ID 6 is used twice'})
R = C.compare(A, B)
check(len(R['sameF']) == 1 and len(R['newF']) == 1 and len(R['fixedF']) == 1, f'counts in titles {R}')

# site profile: remove a device from the saved site, change another
p = bi_points.profile(w.FD, 'Building 4')
check(p['devs'], 'empty profile')
R = bi_points.profile_diff(p, w.FD)
check(not (R['new'] or R['gone'] or R['moved'] or R['fw']), f'site differs from itself {R}')
p2 = dict(p, devs=[dict(d) for d in p['devs'][1:]])
p2['devs'][0]['key'] = '1.2.3.4:47808'
R = bi_points.profile_diff(p2, w.FD)
check(len(R['new']) == 1 and len(R['moved']) >= 1, f'site changes {R}')
dlg = bi_views.SitesDialog(w)
dlg.name.setText('Building 4')
dlg.save()
check(dlg.site.count() == 1, 'site not saved')
dlg.compare()
check('unchanged' in dlg.out.toPlainText(), 'site compare')
dlg.delete()
check(dlg.site.count() == 0, 'site not deleted')

# point names show up
e = w.FD.pts[0]
csvf = os.path.join(TMP, 'points.csv')
open(csvf, 'w', encoding='utf-8').write(f'Device,Object,Name\n{e["dev"] or ""},{e["obj"]},Supply air temp\n')
w.load_points(csvf)
pump(0.2)
check('Supply air temp' in bi_views.point_label(w, e), 'imported name not shown')
w.clear_points()
check('Supply air temp' not in bi_views.point_label(w, e), 'name not cleared')

# long capture settings
w.store.set('bi_long', {'on': True, 'dir': os.path.join(TMP, 'live'), 'min': 5, 'keep': 3})
w.roll_start()
check(w.roll is not None, 'long capture did not start')
w.roll.write(1000.0, 1, frame)
w.alert('Test alert')
w.roll_stop()
check(os.path.exists(os.path.join(TMP, 'live', 'problems.txt')), 'alert not logged')

w.close()
pump(0.2)
print('exceptions:', ERR + fails)

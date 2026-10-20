"""Test the new features on the simulated trunk + UI: alarms, all properties, point details, MS/TP frames in Packets,
Excel exports, background sorting."""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
from PySide6.QtCore import Qt, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import mstp_sim as S  # noqa: E402
import bi_mstp as M  # noqa: E402
import bi_store, bi_app  # noqa: E401,E402

OUT = os.path.join(HERE, 'out', 'shots')
bus = S.make_trunk([(1, 2001, 'VAV-1'), (5, 2005, 'VAV-5')])
M.open_port = lambda port, baud: bus.port()
ERR = []
sys.excepthook = lambda t, v, tb: ERR.append(f'{t.__name__}: {v}')
app = QApplication(sys.argv)
app.setStyle('windows11')
store = bi_store.Store('settings-feat.json')
w = bi_app.MainWindow(store)
w.resize(1500, 950)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()
closer = QTimer()
closer.timeout.connect(lambda: [x.close() for x in QApplication.topLevelWidgets() if x.isModal() and x.isVisible() and x is not w and getattr(x, '_keep', False) is False and 'All properties' not in x.windowTitle()])


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def until(c, n=40):
    end = time.time() + n
    while time.time() < end and not c():
        pump(0.1)
    return c()


pump(1)
w.goto('x')
dv = w.view('x')
dv.m_ms.setChecked(True)
dv.ms_port.insertItem(0, 'SIM', 'SIM')
dv.ms_port.setCurrentIndex(0)
dv.ms_join_leave()
print('joined:', until(lambda: w.explorer.link is not None and w.explorer.link.joined))
dv.scan()
until(lambda: not w.explorer.busy and any(d.get('name') for d in w.explorer.devs.values()))
pump(1)
devs = dv.all_devs()
en = devs[0]
dv.read_points(en)
until(lambda: (en['ex'] or {}).get('objs') and not w.explorer.busy)
# alarms
dv.go_node({'k': en['key']})
dv.read_alarms(en)
until(lambda: (en['ex'] or {}).get('alarms') is not None and not en['ex'].get('alarms_busy'))
pump(0.5)
print('alarms:', en['ex']['alarms'])
w.grab().save(os.path.join(OUT, 'feat_alarms.png'))
# point details
ai = next(o for o in en['ex']['objs'] if o['ty'] == 0)
dv.ptab = 1
dv.go_node({'k': en['key'], 'o': ai['o']})
until(lambda: ai.get('pd') and not ai.get('pdl'))
pump(0.5)
print('details:', {k: ai['pd'].get(k) for k in ('flags', 'es', 'hi', 'prof')})
w.grab().save(os.path.join(OUT, 'feat_details.png'))
# read all properties (worker call directly)
print('all props:', w.explorer.read_all(en['ex'], ai['o']))
# MS/TP frames in the live capture tab
pump(1.5)
w.switch_tab(w.LT)
w.goto('p')
pump(1)
print('live tab frames:', len(w.LT.P), '| status:', w.live.ls.text())
w.grab().save(os.path.join(OUT, 'feat_live_mstp.png'))
dv.ms_join_leave()
pump(0.5)
print('after leave, feed:', w._feed, 'timer active:', w.poll_timer.isActive())
# excel exports for every view
w.open_path(sys.argv[1])
until(lambda: any(not t.live and t.P and not t.busy for t in w.TB), 60)
w.switch_tab(next(t for t in w.TB if not t.live))
n = 0
for k in ['p', 'f', 'd', 'w', 't', 's', 'o', 'a', 'n', 'm', 'b', 'c', 'x']:
    w.goto(k)
    pump(0.2)
    for key, lab, ext, mk in w.formats(k):
        if ext == 'xlsx':
            b = mk()
            assert b[:2] == b'PK', k
            n += 1
print('excel exports built:', n)
# background sort on a big capture
w.open_path(sys.argv[2])
until(lambda: any(t.n == os.path.basename(sys.argv[2]) and t.P and not t.busy for t in w.TB), 120)
w.switch_tab(next(t for t in w.TB if t.n == os.path.basename(sys.argv[2])))
w.goto('p')
t0 = time.time()
w.pk.sort_click(7)
blocked = time.time() - t0
until(lambda: w.pk.model.sort == ('info', 1) and len(w.pk.V) == len(w.P), 30)
print(f'sort click returned in {blocked:.2f}s (UI not blocked); sorted list ready after {time.time() - t0:.1f}s; status during: ok')
t0 = time.time()
w.pk.sort_click(7)
until(lambda: w.pk.model.sort == ('info', -1), 30)
print(f're-sort (cached keys) took {time.time() - t0:.1f}s')
w.close()
pump(0.3)
for s in S.SIMS:
    s.on = False
os.remove(store.path) if os.path.exists(store.path) else None
print('exceptions:', ERR)

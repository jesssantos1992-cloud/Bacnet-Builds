"""The Discover screen driving a simulated MS/TP trunk: choose MS/TP, find a MAC, join, scan, read points."""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import mstp_sim as S  # noqa: E402
import bi_mstp as M  # noqa: E402
import bi_store  # noqa: E402
import bi_app  # noqa: E402

OUT = os.path.join(HERE, 'out', 'shots')
bus = S.make_trunk([(1, 2001, 'VAV-1'), (5, 2005, 'VAV-5')])
M.open_port = lambda port, baud: bus.port()          # the "COM port" is the simulated trunk

app = QApplication(sys.argv)
app.setStyle('windows11')
store = bi_store.Store('settings-mstptest.json')
w = bi_app.MainWindow(store)
w.resize(1500, 950)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def until(cond, limit=30):
    end = time.time() + limit
    while time.time() < end and not cond():
        pump(0.1)
    return cond()


pump(1)
w.goto('x')
dv = w.view('x')
dv.m_ms.setChecked(True)
pump(0.2)
dv.ms_port.insertItem(0, 'SIM \u2013 simulated trunk', 'SIM')
dv.ms_port.setCurrentIndex(0)
dv.ms_join_leave()                       # listens first, then joins
ok = until(lambda: w.explorer.link is not None and w.explorer.link.joined, 40)
print('joined:', ok, '|', dv.ms_status.text())
dv.scan()
until(lambda: w.explorer.busy == '' and any(d.get('name') for d in w.explorer.devs.values()), 40)
pump(1)
print('tree groups:', [dv.tree.topLevelItem(i).text(0) for i in range(dv.tree.topLevelItemCount())])
devs = dv.all_devs()
print('devices:', [(d['id'], d['name'], d['ip']) for d in devs])
dv.read_points(devs[0])
until(lambda: (devs[0]['ex'] or {}).get('objs') and not w.explorer.busy, 40)
pump(1)
dv.go_node({'k': devs[0]['key'], 't': 0})
pump(0.5)
w.grab().save(os.path.join(OUT, 'mstp_discover.png'))
print('points:', [(o['name'], o['val'], o['u']) for o in devs[0]['ex']['objs']])
dv.set_mode('ip')
pump(0.3)
print('IP mode shows', len(dv.all_devs()), 'devices (MS/TP ones hidden)')
dv.m_ms.setChecked(True)
pump(0.2)
dv.ms_join_leave()                       # leave
pump(0.3)
print('after leave:', dv.ms_status.text(), '| link:', w.explorer.link)
w.close()
pump(0.3)
for s in S.SIMS:
    s.on = False
os.remove(store.path) if os.path.exists(store.path) else None
print('OK')

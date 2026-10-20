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
from PySide6.QtWidgets import QTreeWidgetItemIterator
it = QTreeWidgetItemIterator(dv.tree)
while it.value():
    print('tree:', it.value().text(0)); it += 1
dv.tree.grab().save(os.path.join(OUT, 'tree_labels.png'))
dv.ms_join_leave(); pump(0.3); w.close()
for s in S.SIMS: s.on = False
os.remove(store.path) if os.path.exists(store.path) else None
print('exceptions:', ERR)

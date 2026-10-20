"""Site inventory on the simulated MS/TP trunk: scan, build the inventory (object lists of every device), check the
spreadsheet and the Excel workbook, and that the Save dialog is offered."""
import os
import sys
import tempfile
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_inv_test_')
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))  # the app's folder
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import mstp_sim as S  # noqa: E402
import bi_mstp as M  # noqa: E402
import bi_store, bi_app  # noqa: E401,E402

bus = S.make_trunk([(1, 2001, 'VAV-1'), (5, 2005, 'VAV-5')])
M.open_port = lambda port, baud: bus.port()
ERR = []
sys.excepthook = lambda t, v, tb: ERR.append(f'{t.__name__}: {v}')
app = QApplication(sys.argv)
app.setStyle('windows11')
store = bi_store.Store('settings-invtest.json')
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
dv.inventory()
pump(0.2)
print('before a scan:', w.toaster.lab.text())
dv.m_ms.setChecked(True)
pump(0.2)
dv.ms_port.insertItem(0, 'SIM – simulated trunk', 'SIM')
dv.ms_port.setCurrentIndex(0)
dv.ms_join_leave()
until(lambda: w.explorer.link is not None and w.explorer.link.joined, 40)
dv.scan()
until(lambda: w.explorer.busy == '' and sum(1 for d in w.explorer.devs.values() if d.get('name')) >= 2, 40)
pump(0.5)
saves = []
w.save_as = lambda v, fm, holder, title=None: saves.append((v, [f[0] for f in fm], title))
dv.inventory()
seen_progress = until(lambda: 'Building the site inventory' in dv.status.text(), 10)
until(lambda: w.explorer.busy == '' and saves, 60)
pump(0.3)
print('progress shown:', seen_progress, '| status:', w.explorer.msg)
print('save offered:', saves)
csv = dv.csv_inventory()
lines = csv.strip().splitlines()
print(lines[0])
for line in lines[1:]:
    print(line)
fm = dict((f[0], f) for f in w.formats('x'))
xl = fm['inventory.xlsx'][3]()
head = lines[0].split(',')
rows = [r.split(',') for r in lines[1:]]
objs = [int(r[head.index('Objects')]) for r in rows]
ok = (len(rows) == 2 and all(n > 0 for n in objs) and xl[:2] == b'PK' and saves and saves[0][1][0] == 'inventory.xlsx'
      and 'MAC 1' in csv and 'MAC 5' in csv and 'VAV-1' in csv and seen_progress)
print('objects per device:', objs, '| xlsx bytes:', len(xl))
dv.ms_join_leave()
pump(0.3)
w.close()
pump(0.3)
for s in S.SIMS:
    s.on = False
print('exceptions:', ERR if ok else ERR + ['inventory check failed'])

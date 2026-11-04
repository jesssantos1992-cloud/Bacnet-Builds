"""Discover: picking a network opens its page, Discover this network finds and reads its devices, and the values on a
category page and in the point panel update by themselves (no Read now / Refresh values). Also checks the Who-Is sent
to a network behind a router."""
import os
import sys
import tempfile
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_netpage_test_')
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import mstp_sim as S  # noqa: E402
import bi_mstp as M  # noqa: E402
import bi_store, bi_app  # noqa: E401,E402
import bi_explore as E  # noqa: E402

ERR, BAD = [], []


def _hook(t, v, tb):
    import traceback
    ERR.append(f'{t.__name__}: {v}')
    traceback.print_exception(t, v, tb)


sys.excepthook = _hook


def check(ok, msg):
    print(('ok   ' if ok else 'FAIL ') + msg, flush=True)
    if not ok:
        BAD.append(msg)


# the Who-Is for network 2401 behind a router: broadcast on this subnet with DNET 2401 and an empty DADR
pkt = E.ex_wrap({'dnet': 2401, 'dadr': []}, [0x10, 8], 0, False, 0x0B)
check(pkt == bytes([0x81, 0x0B, 0, 12, 1, 0x20, 0x09, 0x61, 0, 255, 0x10, 8]), f'routed Who-Is: {pkt.hex()}')
check(BL._read_only_ok(pkt) == '', 'the routed Who-Is is allowed by the read-only rules')

bus = S.make_trunk([(1, 2001, 'VAV-1'), (5, 2005, 'VAV-5')])
M.open_port = lambda port, baud: bus.port()
app = QApplication(sys.argv)
app.setStyle('windows11')
w = bi_app.MainWindow(bi_store.Store('settings-netpage.json'))
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


w.goto('x')
dv = w.view('x')
check(not hasattr(dv, 'b_new') and 'New discover' not in {b.text() for b in dv.findChildren(QPushButton)},
      'no New discover button at the top')
dv.m_ms.setChecked(True)
pump(0.2)
dv.ms_port.insertItem(0, 'SIM – simulated trunk', 'SIM')
dv.ms_port.setCurrentIndex(0)
dv.ms_join_leave()
until(lambda: w.explorer.link is not None and w.explorer.link.joined, 40)
dv.scan()
until(lambda: w.explorer.busy == '' and sum(1 for d in w.explorer.devs.values() if d.get('name')) >= 2, 40)
pump(0.5)

# pick the network in the tree
g = dv.tree.topLevelItem(0)
dv.tree.setCurrentItem(g)
pump(0.5)
check(dv.node == {'g': 'mstp'}, f'picking the network opens its page ({dv.node})')
btns = {b.text(): b for b in dv.right.findChildren(QPushButton)}
check('Discover this network' in btns, f'the network page has Discover this network ({sorted(btns)})')

for d in w.explorer.devs.values():
    d['objs'] = None
btns['Discover this network'].click()
pump(0.3)
check(dv.nrun is not None and 'Stop' in {b.text() for b in dv.right.findChildren(QPushButton)}, 'Stop while it runs')
until(lambda: dv.nrun is None, 120)
pump(0.5)
devs = sorted(w.explorer.devs.values(), key=lambda d: d['id'])
check(all(d.get('objs') and all(o.get('ok') for o in d['objs'] if o['ty'] != 8) for d in devs),
      'every device on the network was read, points and values')
check(dv.nres and dv.nres[0] == 'mstp' and dv.nres[1].startswith('Done. 2 answered, 2 read'), f'result: {dv.nres}')
check(any(lab.text().startswith('Done. 2 answered') for lab in dv.right.findChildren(type(dv.status))), 'result shown on the page')

os.makedirs(os.path.join(HERE, 'out', 'shots'), exist_ok=True)
w.grab().save(os.path.join(HERE, 'out', 'shots', 'discover-network.png'))

# a category page: values update by themselves
dev = devs[0]
dv.LIVE_S = {'ip': 1, 'mstp': 2}
dv.go_node({'k': dev['key'], 't': 0})
pump(0.5)
names = {b.text() for b in dv.right.findChildren(QPushButton)}
check('Refresh values' not in names, 'no Refresh values button')
t = dv.live_tbl[0]
check(t.item(0, 2).text().startswith('13.2'), f'value shown: {t.item(0, 2).text()}')
S.SIMS[0].objs[(0, 1)][85] = S.real(17.5)
check(until(lambda: dv.live_tbl and dv.live_tbl[0].item(0, 2).text().startswith('17.5'), 30), 'the category value updated by itself')
check(dv.live_lab.text().startswith('● Live: values update every 2 seconds · read'), f'live note: {dv.live_lab.text()}')

# the point panel
dv.go_node({'k': dev['key'], 'o': E.oid(0, 1)})
pump(0.8)
names = {b.text() for b in dv.insp.findChildren(QPushButton)}
check('Read now' not in names, f'no Read now in the point panel ({sorted(names)})')
S.SIMS[0].objs[(0, 1)][85] = S.real(19.25)
check(until(lambda: dv.live_big and dv.live_big[0].text().startswith('19.25'), 30), 'the point value updated by itself')

# breadcrumbs: the network is clickable from a device
dv.go_node({'k': dev['key']})
pump(0.5)
from PySide6.QtWidgets import QToolButton  # noqa: E402
crumb = [b for b in dv.findChildren(QToolButton) if b.isVisibleTo(dv) and b.text().startswith('MS/TP trunk')]
check(bool(crumb), 'the network in the path is clickable')
if crumb:
    crumb[0].click()
    pump(0.4)
    check(dv.node == {'g': 'mstp'}, 'clicking it opens the network page')

dv.go_node({'k': dev['key'], 't': 0})
pump(0.5)
cb = [b for b in dv.findChildren(QToolButton) if b.isVisibleTo(dv) and b.text().startswith('Device 2001')]
if cb:
    cb[0].click()
    pump(0.4)
check(bool(cb) and dv.node == {'k': dev['key']}, f'the device in the path opens the device ({dv.node})')

dv.ms_join_leave()
pump(0.3)
w.close()
pump(0.3)
for s_ in S.SIMS:
    s_.on = False
print('exceptions:', ERR + [f'check failed: {b}' for b in BAD], flush=True)

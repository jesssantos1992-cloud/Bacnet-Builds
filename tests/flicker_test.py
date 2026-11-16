"""Discover joined to an MS/TP trunk: the token traffic that streams into the Live capture tab must not make Discover
rebuild (flicker) or lose its scroll position; real changes (a new name, a theme switch) still redraw."""
import os
import sys
import tempfile
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_flicker_test_')
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import mstp_sim as S  # noqa: E402
import bi_mstp as M  # noqa: E402
import bi_store, bi_app  # noqa: E401,E402

BAD, ERR = [], []
sys.excepthook = lambda t, v, tb: ERR.append(f'{t.__name__}: {v}')


def check(ok, msg):
    print(('ok   ' if ok else 'FAIL ') + msg, flush=True)
    if not ok:
        BAD.append(msg)


bus = S.make_trunk([(i, 2000 + i, f'VAV-{i}') for i in range(1, 13)], site=True)
M.open_port = lambda port, baud: bus.port()
app = QApplication(sys.argv)
w = bi_app.MainWindow(bi_store.Store('settings-flicker.json'))
w.resize(1500, 900)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.01)


def until(c, n=60):
    end = time.time() + n
    while time.time() < end and not c():
        pump(0.1)
    return c()


w.goto('x')
dv = w.view('x')
dv.m_ms.setChecked(True)
pump(0.2)
dv.ms_port.insertItem(0, 'SIM – simulated trunk', 'SIM')
dv.ms_port.setCurrentIndex(0)
dv.ms_join_leave()
until(lambda: w.explorer.link is not None and w.explorer.link.joined)
dv.scan()
until(lambda: w.explorer.busy == '' and sum(1 for d in w.explorer.devs.values() if d.get('name')) >= 12, 90)
pump(1)
for d in w.explorer.devs.values():                      # give every device its points, so the tree is long enough to scroll
    d['objs'] = [{'o': o, 'ty': o >> 22, 'inst': o & 0x3FFFFF, 'name': f'P{o & 0xFF}', 'val': '', 'u': '', 'desc': '', 'ok': 1}
                 for o in [(t << 22) | i for t in (0, 1, 2, 3, 4, 5) for i in range(1, 6)]]
    dv.open.add(d['key'])
dv.gopen.update({'nmstp', 'nlocal'})
dv.refresh()
pump(0.8)
n = {'tree': 0, 'right': 0}
bt, br = dv.build_tree, dv.build_right
dv.build_tree = lambda *a: (n.__setitem__('tree', n['tree'] + 1), bt(*a))[1]
dv.build_right = lambda *a: (n.__setitem__('right', n['right'] + 1), br(*a))[1]
sb = dv.tree.verticalScrollBar()
check(sb.maximum() > 0, f'the tree is long enough to scroll (max {sb.maximum()})')
sb.setValue(sb.maximum() // 2)
y0 = sb.value()
p0 = len(w.LT.P)
pump(10)
print(f"10 s joined and idle: {len(w.LT.P) - p0} frames arrived; tree rebuilt {n['tree']}x, page {n['right']}x", flush=True)
check(len(w.LT.P) - p0 > 500, 'token traffic is flowing into the Live capture tab')
check(n['tree'] == 0 and n['right'] == 0, 'Discover does not rebuild while nothing in it changes')
check(sb.value() == y0, f'the tree keeps its scroll position ({y0} -> {sb.value()})')

# a real change redraws, and two rebuilds in a row keep the position
d0 = sorted(w.explorer.devs.values(), key=lambda d: d['id'])[0]
d0['name'] = 'AHU renamed'
dv.refresh()
dv.refresh(force=True)
pump(0.5)
check(n['tree'] >= 1, 'a renamed device redraws')
check(sb.value() == y0, f'two rebuilds in a row keep the scroll position ({y0} -> {sb.value()})')
k = n['tree']
w.set_theme('light')
pump(0.8)
check(n['tree'] > k, 'switching theme redraws')
w.set_theme('')
pump(0.5)

# the page on the right keeps its scroll position too
dv.go_node({'k': d0['key']})
pump(0.6)
rs = dv.right.scroll.verticalScrollBar()
if rs.maximum() > 0:
    rs.setValue(rs.maximum())
    ry = rs.value()
    d0['name'] = 'AHU renamed again'
    dv.refresh()
    dv.refresh(force=True)
    pump(0.5)
    check(rs.value() == ry, f'the page keeps its scroll position ({ry} -> {rs.value()})')
dv.ms_join_leave()
pump(0.3)
w.close()
for s_ in S.SIMS:
    s_.on = False
print('exceptions:', ERR + [f'check failed: {b}' for b in BAD], flush=True)

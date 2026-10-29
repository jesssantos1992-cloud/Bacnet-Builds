"""Packet details decode the full service (like Wireshark) and highlighted addresses open their packets.
Usage: find_test.py <capture> [<capture> …]"""
import os
import sys
import tempfile
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_find_test_')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
from PySide6.QtCore import QEvent, QPointF, Qt  # noqa: E402
from PySide6.QtGui import QMouseEvent  # noqa: E402
from PySide6.QtWidgets import QApplication, QStyleOptionViewItem  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import bi_store, bi_app, bi_core as C, bi_common  # noqa: E401,E402

ERR = []
sys.excepthook = lambda t, v, tb: ERR.append(f'{t.__name__}: {v}')
fails = []

# ---- 1. every packet decodes, and COV notifications show their values
for path in sys.argv[1:]:
    raw = C.parse(open(path, 'rb').read())
    cov = bad = 0
    for n, (ts, lt, d, ifc) in enumerate(raw[:20000]):
        r = C.dis(ts, lt, d, n + 1, ifc, True)
        rows = r.tree or []
        if any('could not be decoded' in s for _, s in rows):
            bad += 1
        if 'COV Notification' in r.info and 'present-value =' in r.info:
            cov += 1
            if cov == 1:
                lv = [lvl for lvl, s in rows if s.startswith('Value: ')]
                if not any(s.startswith('Monitored object: ') for _, s in rows) or not lv or max(lv) < 2:
                    fails.append('COV notification is not decoded in full')
    print(f'{os.path.basename(path)}: {min(len(raw), 20000)} packets, {cov} COV with values, {bad} not decodable')
    if bad:
        fails.append(f'{bad} packets could not be decoded in {os.path.basename(path)}')

# ---- 2. click-to-find
app = QApplication(sys.argv)
app.setStyle('windows11')
store = bi_store.Store('settings-findtest.json')
w = bi_app.MainWindow(store)
w.resize(1500, 950)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


w.find_link(bi_common.find_href('ip', '10.0.0.1'))
pump(0.2)
print('no capture open:', w.toaster.lab.text())
w.open_path(sys.argv[1])
end = time.time() + 120
while time.time() < end and not (w.ac and w.ac.P and not w.ac.busy):
    pump(0.2)
pump(0.5)
html = bi_app.bi_views.findings_html(w, w.FD) if hasattr(bi_app, 'bi_views') else __import__('bi_views').findings_html(w, w.FD)
links = html.count('href="bi:')
print('links in Findings:', links)
if not links:
    fails.append('no clickable addresses in Findings')
dv = [d for d in (w.FD.dv or []) if d.get('key')]
tests = []
ips = sorted({k.split(', ')[-1] for k in (d['key'] for d in dv) if k[0].isdigit()})
if ips:
    tests.append(('ip', ips[0]))
macs = sorted({d['sa'] for d in dv if d.get('sa', '') and str(d['sa']).startswith('MAC')})
if macs:
    tests.append(('mac', 'MAC ' + macs[0].split()[-1]))
nets = sorted({d['sn'] for d in dv if d.get('sn') is not None})
if nets:
    tests.append(('net', f'network {nets[0]}'))
if dv:
    tests.append(('id', f"device {dv[0]['id']}"))
for kind, val in tests:
    w.goto('f')
    w.find_link(bi_common.find_href(kind, val))
    pump(0.3)
    n = len(w.pk.V)
    print(f'{kind:4} {val:28} -> view {w.cur_view}, filter {w.qbox.text()!r}, {n} packets | {w.toaster.lab.text()}')
    if w.cur_view != 'p' or not n:
        fails.append(f'finding {val} showed no packets')
# a click on a highlighted cell in the Devices tree
w.set_filter('')
w.goto('d')
pump(0.5)
tree = w.view('d').tree
hd = tree.itemDelegate()
found = None
it = tree.topLevelItem(0)
stack = [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]
while stack and not found:
    it = stack.pop(0)
    stack += [it.child(i) for i in range(it.childCount())]
    for col in range(tree.columnCount()):
        if bi_common.Labels.HRE.search(it.text(col) or ''):
            found = (it, col)
            break
if found:
    it, col = found
    tree.scrollToItem(it)
    pump(0.2)
    ix = tree.indexFromItem(it, col)
    rect = tree.visualRect(ix)
    opt = QStyleOptionViewItem()
    opt.initFrom(tree.viewport())
    opt.rect = rect
    opt.widget = tree
    href = ''
    for x in range(rect.left() + 2, rect.right(), 3):
        href = hd.href_at(opt, ix, QPointF(x, rect.center().y()))
        if href:
            break
    if href:
        ev = QMouseEvent(QEvent.Type.MouseButtonRelease, QPointF(x, rect.center().y()), QPointF(x, rect.center().y()),
                         Qt.MouseButton.LeftButton, Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier)
        hd.editorEvent(ev, tree.model(), opt, ix)
        pump(0.4)
    print(f'Devices tree cell {it.text(col)!r}: link {href!r} -> view {w.cur_view}, {len(w.pk.V)} packets')
    if not href or w.cur_view != 'p':
        fails.append('clicking an address in the Devices tree did not open its packets')
w.close()
pump(0.2)
print('exceptions:', ERR + fails)

"""Every start is fresh: Discover does not bring back last time's devices and last time's capture tabs do not reopen.
Discover's Clear list empties the list (discovered devices and the capture's devices), and Undo puts them back."""
import os
import sys
import tempfile
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_fresh_test_')
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
import bacnet_live as BL  # noqa: E402
import bi_sample  # noqa: E402

old_cap = bi_sample.write_sample(os.path.join(tempfile.mkdtemp(), 'last-time.pcap'))
BL.load_session = lambda: {'tabs': [{'path': old_cap, 'q': ''}], 'active': old_cap}   # what the last run left open
BL.save_session = lambda u: None
import bi_store, bi_app  # noqa: E401,E402

ERR, BAD = [], []
sys.excepthook = lambda t, v, tb: ERR.append(f'{t.__name__}: {v}')
store = bi_store.Store('settings-fresh.json')
store.set('bi_disc', {'at': time.time(), 'd': [{'key': '1001@10.0.0.5', 'id': 1001, 'ip': '10.0.0.5', 'port': 47808}]})
app = QApplication(sys.argv)
app.setStyle('windows11')
w = bi_app.MainWindow(store)
w.resize(1500, 950)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def check(ok, msg):
    print(('ok   ' if ok else 'FAIL ') + msg, flush=True)
    if not ok:
        BAD.append(msg)


pump(1.5)
check(not w.explorer.devs and store.get('bi_disc') is None, 'last time’s discovered devices are gone')
check([t.n for t in w.TB if not t.live] == [], f'last time’s capture tabs did not reopen: {[t.n for t in w.TB]}')
w.goto('x')
dv = w.view('x')
pump(0.3)
check(dv.all_devs() == [] and dv.status.text() == 'No devices discovered yet.', f'Discover starts empty: {dv.status.text()!r}')
dv.clear_list()
pump(0.2)
check('already empty' in w.toaster.lab.text(), 'Clear list on an empty list says so')

w.open_sample()
end = time.time() + 60
while time.time() < end and not (w.ac and w.ac.P and not w.ac.busy):
    pump(0.2)
w.goto('x')
pump(0.5)
w.explorer.devs['2001@10.9.9.9'] = {'key': '2001@10.9.9.9', 'id': 2001, 'ip': '10.9.9.9', 'port': 47808, 'st': 'ok',
                                    'name': 'Scanned', 'objs': None}
dv.refresh()
pump(0.3)
n = len(dv.all_devs())
check(n == 5, f'the capture’s 4 devices and 1 scanned device are listed ({n})')
dv.clear_list()
pump(0.3)
check(dv.all_devs() == [] and not w.explorer.devs and dv.tree.topLevelItemCount() == 0, 'Clear list empties the list and the tree')
check(w.toaster.lab.text() == 'Device list cleared', f'toast: {w.toaster.lab.text()!r}')
check(len(w.P) > 3000, 'the capture itself stays open')
w.toaster.btn.click()
pump(0.3)
check(len(dv.all_devs()) == 5, f'Undo puts them back ({len(dv.all_devs())})')
dv.clear_list()
pump(0.3)
w.goto('f')
w.goto('x')
pump(0.3)
check(dv.all_devs() == [], 'stays clear when coming back to Discover')
w.close()
pump(0.3)
print('exceptions:', ERR + [f'check failed: {b}' for b in BAD], flush=True)

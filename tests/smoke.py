"""Smoke test for the native app: open captures, visit every view, build every export, take screenshots."""
import os
import sys
import time
import traceback

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out', 'shots')
os.makedirs(OUT, exist_ok=True)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QStyleFactory  # noqa: E402

import bacnet_live as BL  # noqa: E402

BL.load_session = lambda: {}          # never touch the real session file
BL.save_session = lambda u: None
import bi_store  # noqa: E402
import bi_app  # noqa: E402

app = QApplication(sys.argv)
if 'windows11' in [k.lower() for k in QStyleFactory.keys()]:
    app.setStyle('windows11')
print('style:', app.style().name())
store = bi_store.Store('settings-smoketest.json')
w = bi_app.MainWindow(store)
w.resize(1500, 950)
if '--show' not in sys.argv:
    w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)   # real Windows rendering, but never on screen
w.show()
files = [a for a in sys.argv[1:] if not a.startswith('--')]
errors = []


def pump(sec):
    end = time.time() + sec
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def wait_loaded(t, limit=120):
    end = time.time() + limit
    while time.time() < end and (t.busy or not t.P):
        pump(0.1)


try:
    pump(1.0)
    for f in files:
        w.open_path(f)
    pump(0.5)
    for t in list(w.TB):
        if not t.live:
            wait_loaded(t)
            print(f'loaded {t.n}: {len(t.P)} packets, {len(t.FD)} findings, {len(t.FD.dv or [])} devices')
    tab = next(t for t in w.TB if not t.live)
    w.switch_tab(tab)
    pump(0.3)
    w.pk.tv.selectRow(5)
    pump(0.2)
    w.grab().save(os.path.join(OUT, '00_packets.png'))
    for f in ['iam', 'device == 1001 && proto == "MS/TP"', 'host == "MS/TP MAC 5" || bad', '(', 'write']:
        w.set_filter(f)
        pump(0.1)
        print(f'filter {f!r}: {len(w.pk.V)} rows')
    w.set_filter('')
    w.pk.sq.setText('2630')
    pump(0.5)
    print('search hits:', len(w.pk.HI))
    w.grab().save(os.path.join(OUT, '01_search.png'))
    w.pk.sq.setText('')
    for k in ['f', 'd', 'w', 't', 's', 'o', 'g', 'a', 'n', 'm', 'b', 'c', 'x']:
        try:
            w.goto(k)
            pump(0.4)
            w.grab().save(os.path.join(OUT, f'view_{k}.png'))
            for key, lab, ext, mk in w.formats(k):
                data = mk()
                assert data, f'{k}/{key} produced nothing'
                print(f'  export {k}/{key}: {len(data)} bytes')
        except Exception:
            errors.append(k)
            traceback.print_exc()
    w.goto('p')
    for key, lab, ext, mk in w.formats('p'):
        print(f'  export p/{key}: {len(mk())} bytes')
    import bi_views
    print('report html', len(bi_views.html_report(w)), 'txt', len(bi_views.txt_report(w)))
    # ---- UI interactions that use signal arguments
    w.goto('w')
    cv = w.view('w')
    for i in range(cv.wf.count()):
        cv.wf.setCurrentIndex(i)
        pump(0.1)
        print('changes filter', cv.wf.currentData(), cv.tbl.rowCount())
    cv.wq.setText('present')
    pump(0.1)
    cv.wq.setText('')
    w.goto('b')
    bv = w.view('b')
    w.store.set('bi_baud', 38400)
    bv.refresh()
    w.store.set('bi_baud', 0)
    w.goto('c')
    w.view('c').swap()
    pump(0.2)
    w.goto('x')
    dv = w.view('x')
    dv.pick_capture()
    pump(0.3)
    print('picker groups:', dv.tree.topLevelItemCount())
    g = dv.tree.topLevelItem(0)
    if g and g.childCount():
        g.setExpanded(True)
        g.child(0).setCheckState(0, Qt.CheckState.Checked)
        pump(0.3)
        print('picked:', len(dv.pk['sel']))
    w.grab().save(os.path.join(OUT, 'view_x_pick.png'))
    dv.new_discover()
    # ---- back navigation
    w.goto('f'); pump(0.1); w.goto('d'); pump(0.1)
    w.nav_back(); pump(0.1)
    print('after back:', w.cur_view)
    # ---- simulated live capture: feed real packets through the live path
    import bi_core as C
    k = C.parse(open(files[-1], 'rb').read())
    w.switch_tab(w.LT)
    w.goto('o')
    w.LT.ts = time.time() - 60
    w.run = True
    w.cap.running = True
    for i in range(0, min(len(k), 120000), 20000):
        for ts, lt, d, _ in k[i:i + 20000]:
            w.cap.add(ts, lt, d)
        w.poll()
        pump(0.3)
    end = time.time() + 30
    while w.analysing and time.time() < end:
        pump(0.1)
    w.poll()
    pump(1)
    while w.analysing and time.time() < end:
        pump(0.1)
    nos = [r.no for r in w.LT.P]
    print(f'live: {len(w.LT.P)} kept, numbers {nos[0]}..{nos[-1]} unique={len(set(nos)) == len(nos)}, '
          f'findings {len(w.LT.FD)}, devices {len(w.LT.FD.dv or [])}, alerts {len(w.ALR)}')
    w.grab().save(os.path.join(OUT, 'live_online.png'))
    w.cap.running = False
    w.poll()
except Exception:
    traceback.print_exc()
    errors.append('main')
print('ERRORS:', errors)
w.close()
pump(0.3)
try:
    os.remove(store.path)
except OSError:
    pass
app.quit()
print('closed normally')
sys.exit(1 if errors else 0)

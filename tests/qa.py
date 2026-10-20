"""QA pass: drive every view and control in both themes and two window sizes; record every exception."""
import os
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'out', 'qa')
os.makedirs(OUT, exist_ok=True)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
from PySide6.QtCore import QPoint, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import bi_store, bi_app  # noqa: E401,E402

ERR = []


def hook(t, v, tb):
    ERR.append(''.join(traceback.format_exception(t, v, tb)))
    sys.__excepthook__(t, v, tb)


sys.excepthook = hook
app = QApplication(sys.argv)
app.setStyle('windows11')
store = bi_store.Store('settings-qa.json')
w = bi_app.MainWindow(store)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.resize(1500, 950)
w.show()
from PySide6.QtCore import QTimer  # noqa: E402


def close_popups():
    p = QApplication.activePopupWidget()
    if p:
        p.close()


_close = QTimer()
_close.timeout.connect(close_popups)               # a real context menu would wait for a click: close it
_close.start(150)


def pump(s=0.2):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.01)


def step(name, fn):
    try:
        fn()
        pump(0.15)
    except Exception:
        ERR.append(f'[{name}]\n' + traceback.format_exc())


pump(1)
caps = sys.argv[1:]
for f in caps:
    w.open_path(f)
end = time.time() + 90
while time.time() < end and any(t.busy or (not t.live and not t.P) for t in w.TB):
    pump(0.2)
tabs = [t for t in w.TB if not t.live]
print('loaded', [(t.n, len(t.P)) for t in tabs])
V = ['p', 'f', 'd', 'w', 't', 's', 'o', 'g', 'a', 'n', 'm', 'b', 'c', 'x']
for theme in ('dark', 'light'):
    w.set_theme(theme)
    for size in ((1500, 950), (1100, 680)):
        w.resize(*size)
        for t in tabs:
            w.switch_tab(t)
            pump(0.3)
            for k in V:
                step(f'view {k}', lambda k=k: w.goto(k))
                w.grab().save(os.path.join(OUT, f'{theme}_{size[0]}_{t.n[:8]}_{k}.png'))
# ---- packet list interactions
w.set_theme('')
w.resize(1500, 950)
w.switch_tab(tabs[0])
w.goto('p')
pk = w.pk
for col in range(8):
    for _ in range(3):
        step(f'sort {col}', lambda col=col: pk.sort_click(col))
for f in ['iam', 'bad', '(((', 'device == 2001', 'info contains "Read"', 'time > 5 && len < 80', 'note', 'bookmark', '']:
    step(f'filter {f}', lambda f=f: w.set_filter(f))
for m in (pk.mode_f, pk.mode_hl):
    m.setChecked(True)
    for s in ('2630', '192.168', 'device 2', 'zzz', ''):
        step(f'search {s}', lambda s=s: (pk.sq.setText(s), pump(0.4), pk.sq_go(1), pk.sq_go(-1)))
step('select rows', lambda: [pk.tv.selectRow(i) for i in (0, 5, 50)])
r = pk.V[3]
step('bookmark', lambda: w.toggle_bm(r))
step('context menu', lambda: pk.menu(pk.tv.visualRect(pk.model.index(3, 2)).center()))
step('double-click cell', lambda: pk.dbl(pk.model.index(3, 7)))
step('copy packet', w.copy_packet)
step('label device', lambda: (store.set_label('d', tabs[0].FD.dv[0]['id'], 'QA Device'), w.labels_changed()))
step('label network', lambda: (store.set_label('n', 2631, 'QA Net'), w.labels_changed()))
# ---- exports of every view, written to disk
tmp = tempfile.mkdtemp()
for k in V:
    try:
        w.goto(k)
        pump(0.2)
        for key, lab, ext, mk in w.formats(k):
            data = mk()
            with open(os.path.join(tmp, f'{k}.{ext}'), 'wb') as fh:
                fh.write(data if isinstance(data, bytes) else data.encode('utf-8'))
    except Exception:
        ERR.append(f'[export {k}]\n' + traceback.format_exc())
step('report html', lambda: __import__('bi_views').html_report(w))
step('report txt', lambda: __import__('bi_views').txt_report(w))
# ---- view controls
step('devices expand', lambda: (w.goto('d'), w.view('d').expand(True), w.view('d').expand(False)))
step('devices menu', lambda: w.view('d').menu(QPoint(30, 30)))
cv = w.view('w')
step('changes filters', lambda: [(w.goto('w'), cv.wf.setCurrentIndex(i), pump(0.1)) for i in range(4)])
step('changes search', lambda: (cv.wq.setText('present'), pump(0.1), cv.wq.setText('')))
step('online toggles', lambda: (w.goto('o'), w.view('o').set_cfg('snd', True), w.view('o').set_cfg('snd', False)))
step('map click', lambda: (w.goto('g'), w.view('g').canvas.regs and w.view('g').go(w.view('g').canvas.regs[0][1])))
step('avail ids settings', lambda: (w.goto('a'), store.set('bi_av2', {'ds': 3, 'ea': True, 'lo': '1000', 'hi': '5000000', 'ln': '1', 'rs': '1-50'}), w.view('a').refresh()))
step('avail nets settings', lambda: (w.goto('n'), store.set('bi_nv', {'lo': '1', 'hi': '65534', 'rn': '100-200', 'ea': True}), w.view('n').refresh()))
step('bus speed baud', lambda: (w.goto('b'), store.set('bi_baud', 76800), w.view('b').refresh(), store.set('bi_baud', 0)))
step('compare swap', lambda: (w.goto('c'), w.view('c').swap(), w.view('c').swap()))
dv = w.view('x')
step('discover pick', lambda: (w.goto('x'), dv.pick_capture(), dv.back(), dv.home()))
step('discover mstp mode', lambda: (dv.m_ms.setChecked(True), pump(0.2), dv.scan(), dv.m_ip.setChecked(True)))
step('nav back', lambda: [w.nav_back() for _ in range(6)])
step('help pages', lambda: [__import__('bi_views').HELP[k] for k in ('start', 'filter', 'bms', 'keys', 'about')])
# ---- tabs
step('switch tabs fast', lambda: [w.switch_tab(t) for t in w.TB * 3])
step('close + reopen', lambda: (w.close_tab(tabs[-1]), w.open_path(caps[-1])))
pump(3)
step('live tab', lambda: (w.switch_tab(w.LT), w.goto('p'), w.goto('f'), w.goto('x'), w.goto('o')))
w.grab().save(os.path.join(OUT, 'final_live.png'))
w.close()
pump(0.5)
os.remove(store.path) if os.path.exists(store.path) else None
print(f'\n{len(ERR)} exception(s)')
for e in ERR:
    print('-' * 70)
    print(e[-2500:])

import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
import bacnet_live as BL
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import bi_store, bi_app  # noqa: E401

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out', 'shots')
app = QApplication(sys.argv)
app.setStyle('windows11')
store = bi_store.Store('settings-navtest.json')
w = bi_app.MainWindow(store)
w.resize(1500, 950)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()


def pump(s=0.3):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


pump(1)
ex = w.explorer
k = '4001@203.0.113.5'          # documentation address: the relay refuses to send there
ex.devs[k] = {'key': k, 'id': 4001, 'ip': '203.0.113.5', 'port': 47808, 'route': None, 'sn': None, 'sa': '', 'mx': 480,
              'sg': 3, 'vn': 8, 'name': 'AHU-1', 'vendor': 'Delta Controls', 'st': 'ok', 'old': 0,
              'objs': [{'o': 0 * 4194304 + 1, 'ty': 0, 'inst': 1, 'name': 'Supply Air Temp', 'val': '13.2', 'u': '°C', 'desc': 'SAT'},
                       {'o': 2 * 4194304 + 7, 'ty': 2, 'inst': 7, 'name': 'SAT Setpoint', 'val': '13', 'u': '°C', 'desc': ''}]}
w.goto('x')
dv = w.view('x')
dv.live = True
dv.refresh()
pump()


def where():
    n = dv.node
    crumbs = [dv.crumbs.itemAt(i).widget().text() for i in range(dv.crumbs.count()) if dv.crumbs.itemAt(i).widget()]
    return f"node={n}  back={dv.b_back.isEnabled()} home={dv.b_home.isEnabled()} winBack={w.back.isEnabled()}  path={' '.join(crumbs)}"


print('start   ', where())
dv.go_node({'k': k}); pump()
print('device  ', where())
dv.go_node({'k': k, 't': 0}); pump()
print('category', where())
dv.go_node({'k': k, 'o': 1}); pump(1)
print('point   ', where())
w.grab().save(os.path.join(OUT, 'nav_point.png'))
dv.back(); pump(); print('back 1  ', where())
dv.back(); pump(); print('back 2  ', where())
dv.back(); pump(); print('back 3  ', where())
dv.go_node({'k': k, 'o': 2 * 4194304 + 7}); pump(1)
dv.home(); pump(); print('home    ', where())
w.nav_back(); pump(); print('win back', where())
dv.pick_capture(); pump(); print('picker  ', where())
w.nav_back(); pump(); print('win back', where(), 'pk=', dv.pk)
w.goto('f'); pump(); w.goto('x'); pump()
w.nav_back(); pump(); print('view back from discover start ->', w.cur_view)
w.close()
pump()
os.remove(store.path) if os.path.exists(store.path) else None
print('OK')

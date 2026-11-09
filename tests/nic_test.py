"""Discover's network adapter: Ethernet is preferred over Wi-Fi and virtual adapters, broadcasts go to the adapter's
real subnet, the relay is bound to the chosen adapter (and still receives unicast and broadcast answers on it), and
the drop-down in Discover lists the adapters with Automatic first."""
import os
import socket
import sys
import tempfile
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_nic_test_')
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import bacnet_live as BL  # noqa: E402

BAD = []


def check(ok, msg):
    print(('ok   ' if ok else 'FAIL ') + msg, flush=True)
    if not ok:
        BAD.append(msg)


# ---- ranking, with a made-up PC that has everything plugged in
FAKE = [
    {'id': 'w', 'name': 'Wi-Fi', 'desc': 'Intel Wi-Fi 6', 'iftype': 71, 'up': True, 'ip': '10.0.0.12', 'prefix': 24, 'gw': '10.0.0.1', 'metric': 25},
    {'id': 'h', 'name': 'vEthernet (WSL)', 'desc': 'Hyper-V Virtual Ethernet Adapter', 'iftype': 6, 'up': True, 'ip': '172.20.0.1', 'prefix': 20, 'gw': '', 'metric': 5},
    {'id': 'e', 'name': 'Ethernet 2', 'desc': 'Realtek USB GbE Family Controller', 'iftype': 6, 'up': True, 'ip': '192.168.40.50', 'prefix': 16, 'gw': '', 'metric': 25},
    {'id': 'a', 'name': 'Ethernet', 'desc': 'Intel Ethernet Connection', 'iftype': 6, 'up': True, 'ip': '169.254.10.9', 'prefix': 16, 'gw': '', 'metric': 25},
    {'id': 'v', 'name': 'Office VPN', 'desc': 'Fortinet SSL VPN Virtual Ethernet Adapter', 'iftype': 6, 'up': True, 'ip': '10.212.134.2', 'prefix': 32, 'gw': '', 'metric': 1},
    {'id': 'd', 'name': 'Ethernet 3', 'desc': 'Unplugged', 'iftype': 6, 'up': False, 'ip': '192.168.99.5', 'prefix': 24, 'gw': '', 'metric': 25},
]
real = BL._win_adapters
BL._win_adapters = lambda: [dict(a) for a in FAKE]
ads = BL.adapters()
ids = [a['id'] for a in ads]
check(ids[:3] == ['e', 'a', 'w'] and set(ids[3:]) == {'h', 'v'}, f"order: Ethernet, Ethernet with no address, Wi-Fi, then virtual ({ids})")
check([a['kind'] for a in ads] == ['Ethernet', 'Ethernet', 'Wi-Fi', 'Virtual', 'Virtual'], 'kinds')
check(ads[0]['bcast'] == '192.168.255.255' and ads[0]['subnet'] == '192.168.0.0/16', f"a /16 broadcasts to its real subnet ({ads[0]['bcast']})")
check(BL.pick_adapter('', ads)['id'] == 'e', 'Automatic picks the connected Ethernet')
check(BL.pick_adapter('w', ads)['id'] == 'w', 'a chosen adapter is used')
check(BL.pick_adapter('d', ads)['id'] == 'e', 'a chosen adapter that is unplugged falls back to the best')
r = BL.Relay()
r.iface = ads[0]
check(r.broadcasts() == ['255.255.255.255', '192.168.255.255'], f'broadcasts on the chosen adapter only ({r.broadcasts()})')
BL._win_adapters = real

# ---- the real adapters of this PC, and a relay bound to the best one
ads = BL.adapters()
print('this PC:', [(a['kind'], a['name'], a['subnet']) for a in ads])
check(all(not a['ip'].startswith('127.') for a in ads), 'no loopback')
if ads:
    ad = ads[0]
    r = BL.Relay()
    r.set_iface(ad)
    r.open()
    check(r.sock.getsockname()[0] == ad['ip'], f"the relay is bound to {ad['name']} ({r.sock.getsockname()})")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((ad['ip'], 0))
    s.sendto(b'\x81\x0a\x00\x06\x01\x00', (ad['ip'], r.port))                 # a unicast answer
    got = r.recv(0, 3)['items']
    check(any(x['hex'] == '810a00060100' for x in got), 'a unicast answer arrives on the bound adapter')
    s.sendto(b'\x81\x0b\x00\x06\x01\x00', (ad['bcast'], r.port))              # a broadcast (an I-Am is often one)
    end = time.time() + 3
    seen = False
    while time.time() < end and not seen:
        seen = any(x['hex'] == '810b00060100' for x in r.recv(0, 0.5)['items'])
    check(seen, f"a broadcast to {ad['bcast']} arrives too")
    s.close()
    r.set_iface(None)
    check(r.sock is None, 'changing the adapter closes the socket (it opens again on the next send)')
    r.open()
    check(r.sock.getsockname()[0] == '0.0.0.0', 'no adapter: listens on all of them, as before')
    r.sock.close()

# ---- the drop-down in Discover
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
BL._win_adapters = lambda: [dict(a) for a in FAKE]
import bi_store, bi_app  # noqa: E401,E402
app = QApplication(sys.argv)
w = bi_app.MainWindow(bi_store.Store('settings-nic.json'))
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()
w.goto('x')
dv = w.view('x')
dv.m_ip.setChecked(True)
app.processEvents()
items = [dv.ip_nic.itemText(i) for i in range(dv.ip_nic.count())]
check(items[0].startswith('Automatic – Ethernet – Ethernet 2 – 192.168.40.50') and len(items) == 6, f'drop-down: {items[:3]}')
check(dv.ipw.isVisibleTo(dv) and 'Discover uses Ethernet “Ethernet 2”' in dv.ip_status.text()
      and 'Wi-Fi “Wi-Fi”' in dv.ip_status.text(), f'status: {dv.ip_status.text()}')
check(w.explorer.relay.iface['id'] == 'e', 'Discover is bound to the Ethernet')
os.makedirs(os.path.join(HERE, 'out', 'shots'), exist_ok=True)
w.resize(1500, 900)
end_ = time.time() + 1.5
while time.time() < end_:
    app.processEvents()
    time.sleep(0.02)
w.grab().save(os.path.join(HERE, 'out', 'shots', 'discover-adapter.png'))
dv.ip_nic.setCurrentIndex(dv.ip_nic.findData('w'))
app.processEvents()
check(w.store.get('bi_nic') == 'w' and w.explorer.relay.iface['id'] == 'w', 'picking Wi-Fi uses Wi-Fi and is remembered')
dv.ip_nic.setCurrentIndex(dv.ip_nic.findData('a'))
check('169.254' in dv.ip_status.text() and 'static IP' in dv.ip_status.text(), 'an adapter with no address is explained')
FAKE[2]['up'] = False                                                          # the cable comes out
dv.ip_nic.setCurrentIndex(0)
dv.fill_nics()
check(w.explorer.relay.iface['id'] == 'a', 'Automatic follows the cables that are connected now')
dv.m_ms.setChecked(True)
app.processEvents()
check(not dv.ipw.isVisibleTo(dv), 'the adapter row is hidden for MS/TP')
w.explorer.relay.set_iface(None)
w.close()
print('exceptions:', [f'check failed: {b}' for b in BAD], flush=True)

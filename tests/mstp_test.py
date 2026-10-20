"""End-to-end: Discover over MS/TP on a simulated trunk (listen, join, Who-Is, read names, points, values)."""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
import mstp_sim as S  # noqa: E402
import bi_mstp as M  # noqa: E402
import bi_explore as E  # noqa: E402
import bacnet_live as BL  # noqa: E402


class MemStore:
    def __init__(self):
        self.d = {}
        self.lb = {'d': {}, 'n': {}}

    def get(self, k, default=None):
        return self.d.get(k, default)

    def set(self, k, v):
        self.d[k] = v

    def labels(self):
        return self.lb

    def save_labels(self):
        pass


def run(controllers, kill_after=None):
    bus = S.make_trunk(controllers)
    ports = iter([bus.port() for _ in range(3)])
    opener = lambda port, baud: next(ports)  # noqa: E731
    time.sleep(0.5)
    info = M.listen('SIM', 38400, 3.0, opener)
    mac, why = M.suggest_mac(info)
    print(f"  listen: {info['frames']} frames, masters {info['masters']}, free polled {info['free_polled'][:6]}... -> MAC {mac} ({why})")
    ex = E.Explorer(BL.RELAY, MemStore(), notify=lambda: None)
    link = M.MstpLink('SIM', 38400, mac, on_npdu=ex.rx_mstp, opener=opener, allow_create=not info['frames'])
    link.start()
    ex.link = link
    ex.mode = 'mstp'
    t0 = time.time()
    while not link.joined and time.time() - t0 < 20:
        time.sleep(0.05)
    print(f'  joined: {link.joined} after {time.time() - t0:.1f}s  NS={link.ns}  masters={sorted(link.masters)}')
    time.sleep(1)
    print('  status:', link.status_text())
    t0 = time.time()
    ex.scan()
    devs = [d for d in ex.devs.values() if E.is_mstp(d) and not d.get('old')]
    print(f'  scan: {len(devs)} devices in {time.time() - t0:.1f}s ->', sorted((d['id'], d['ip'], d.get('name')) for d in devs))
    if kill_after is not None:
        S.SIMS[kill_after].on = False
        S.SIMS[kill_after].p.close()
        print(f'  -- controller MAC {S.SIMS[kill_after].mac} switched off --')
    for d in sorted(devs, key=lambda d: d['id']):
        if kill_after is not None and d['mac'] == S.SIMS[kill_after].mac:
            r = ex.rpc(d, E.oid(8, d['id']), 77)
            print(f"  read from the switched-off device -> {'no answer (correct)' if r.get('to') else r}")
            continue
        t0 = time.time()
        ex.browse(d)
        print(f"  device {d['id']}: {len(d.get('objs') or [])} objects read in {time.time() - t0:.1f}s:",
              [(o['name'], o['val'], o['u']) for o in d.get('objs') or []])
    # the token must still be going round
    n0 = link.token_count
    time.sleep(1.5)
    print(f'  token kept circulating: {link.token_count - n0} tokens in 1.5 s, NS={link.ns}, error={link.error!r}')
    # guarded write: refused while write access is off
    d = devs[0]
    try:
        ex.send_mstp(d['mac'], E.ex_npdu(None, E.ex_wp(E.oid(2, 7), [0x44, 0x41, 0x60, 0, 0], 8), 1), True)
        print('  write while disarmed: SENT (WRONG)')
    except RuntimeError as e:
        print('  write while disarmed: refused ->', e)
    link.stop()
    for s in S.SIMS:
        s.on = False
    time.sleep(0.2)
    return link


print('== one controller on the trunk (MAC 3)')
run([(3, 3001, 'AHU-1')])
print('\n== three controllers (MAC 1, 5, 9); MAC 9 dies after the scan')
run([(1, 2001, 'VAV-1'), (5, 2005, 'VAV-5'), (9, 2009, 'VAV-9')], kill_after=2)

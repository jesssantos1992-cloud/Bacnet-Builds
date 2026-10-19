"""
bi_explore.py - the Discover client: scan for devices (Who-Is), read their names and points,
and (only while write access is switched on) write present-value of one point.

Every packet goes through bacnet_live.RELAY, which refuses anything except Who-Is, reads and
that one guarded write - this module cannot change a device in any other way.
"""
from __future__ import annotations

import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import bi_core as C

EXU = {0: 'm²', 1: 'ft²', 2: 'mA', 3: 'A', 4: 'Ω', 5: 'V', 6: 'kV', 8: 'VA', 9: 'kVA', 12: 'kVAR', 16: 'J',
       18: 'Wh', 19: 'kWh', 20: 'BTU', 21: 'therms', 22: 'ton-h', 25: 'cycles/h', 27: 'Hz', 29: '%RH', 30: 'mm', 31: 'm',
       32: 'in', 33: 'ft', 34: 'W/ft²', 36: 'lm', 37: 'lx', 38: 'fc', 39: 'kg', 40: 'lb', 42: 'kg/s', 47: 'W', 48: 'kW',
       49: 'MW', 50: 'BTU/h', 51: 'hp', 52: 'tons', 53: 'Pa', 54: 'kPa', 55: 'bar', 56: 'psi', 57: 'cmH₂O',
       58: 'inH₂O', 59: 'mmHg', 61: 'inHg', 62: '°C', 63: 'K', 64: '°F', 65: '°C-days', 66: '°F-days',
       67: 'years', 68: 'months', 69: 'weeks', 70: 'days', 71: 'h', 72: 'min', 73: 's', 74: 'm/s', 75: 'km/h', 76: 'ft/s',
       77: 'ft/min', 78: 'mph', 79: 'ft³', 80: 'm³', 82: 'L', 83: 'gal', 84: 'cfm', 85: 'm³/s', 87: 'L/s',
       88: 'L/min', 89: 'gpm', 90: '°', 96: 'ppm', 97: 'ppb', 98: '%', 104: 'rpm'}
CATS = [(0, 'Analog Inputs'), (1, 'Analog Outputs'), (2, 'Analog Values'), (3, 'Binary Inputs'), (4, 'Binary Outputs'),
        (5, 'Binary Values'), (13, 'Multi-state Inputs'), (14, 'Multi-state Outputs'), (19, 'Multi-state Values'),
        (17, 'Schedules'), (6, 'Calendars'), (20, 'Trend Logs'), (12, 'Loops'), (15, 'Notification Classes'),
        (16, 'Programs'), (10, 'Files'), (7, 'Commands'), (9, 'Event Enrollments'), (11, 'Groups'), (18, 'Averaging')]
ABBR = {0: 'AI', 1: 'AO', 2: 'AV', 3: 'BI', 4: 'BO', 5: 'BV', 8: 'DEV', 13: 'MSI', 14: 'MSO', 19: 'MSV', 17: 'SCH',
        20: 'TL', 10: 'FILE', 15: 'NC', 12: 'LOOP', 6: 'CAL', 7: 'CMD', 9: 'EE'}
CMD_T = (1, 2, 4, 5, 14, 19)          # commandable object types (outputs and values)
WHINT = [('write access denied', 'The point is read-only, or not commandable, or needs a password / higher permission.'),
         ('value out of range', 'The value is outside the limits set in the device (min / max).'),
         ('unknown object', 'That object does not exist any more in the device.'),
         ('not supported', 'The device does not support writing this property.'),
         ('optional functionality', 'The device does not support writing this property.'),
         ('invalid data type', 'The device expected a different kind of value (for example a whole number instead of a decimal).')]


def sd_ty(t):
    return C.tyname(t).replace('-', ' ')


def cat_name(t):
    for k, n in CATS:
        if k == t:
            return n
    s = sd_ty(t)
    return s[:1].upper() + s[1:] + 's'


def cat_ord(t):
    for i, (k, _) in enumerate(CATS):
        if k == t:
            return i
    return 99 + t


def oid(t, i):
    return t * 4194304 + i


def o_t(o):
    return o // 4194304


def o_i(o):
    return o % 4194304


def be4(n):
    return [n >> 24 & 255, n >> 16 & 255, n >> 8 & 255, n & 255]


def unq(s):
    s = str(s)
    if s.startswith('"'):
        s = s[1:]
    if s.endswith('"'):
        s = s[:-1]
    return s


def ex_wrap(route, apdu, exp, bc=False, fn=None):
    n = [1, 0]
    if bc:
        n[1] = 0x20
        n += [255, 255, 0, 255]
    elif route:
        n[1] = 0x20 | (4 if exp else 0)
        n += [route['dnet'] >> 8, route['dnet'] & 255, len(route['dadr']), *route['dadr'], 255]
    else:
        n[1] = 4 if exp else 0
    d = n + list(apdu)
    L = len(d) + 4
    return bytes([0x81, fn or (0x0B if bc else 0x0A), L >> 8, L & 255, *d])


def ex_rp(o, p, idx=None):
    a = [0, 5, 0, 12, 12, *be4(o)]
    a += [0x19, p] if p < 256 else [0x1A, p >> 8, p & 255]
    if idx is not None:
        a += [0x29, idx] if idx < 256 else [0x2A, idx >> 8, idx & 255]
    return a


def ex_rpm(lst):
    a = [0, 5, 0, 14]
    for o, ps in lst:
        a += [12, *be4(o), 0x1E]
        for p in ps:
            a += [0x09, p] if p < 256 else [0x0A, p >> 8, p & 255]
        a.append(0x1F)
    return a


def ex_wp(o, val, pri):
    return [0, 5, 0, 15, 12, *be4(o), 0x19, 85, 0x3E, *val, 0x3F] + ([0x49, pri] if pri else [])


def ex_enc(ty, txt):
    """Encode a typed value for present-value; None if it is not valid for that object type."""
    txt = str(txt).strip().lower()
    if ty in (1, 2):
        try:
            f = float(txt)
        except ValueError:
            return None
        if txt == '' or f != f or f in (float('inf'), float('-inf')):
            return None
        return [0x44, *struct.pack('>f', f)]
    if ty in (4, 5):
        v = 1 if txt in ('active', 'on', '1') else 0 if txt in ('inactive', 'off', '0') else None
        return None if v is None else [0x91, v]
    try:
        n = int(txt)
    except ValueError:
        return None
    if not (n >= 1) or n > 65535 or str(n) != txt:
        return None
    return [0x21, n] if n < 256 else [0x22, n >> 8, n & 255]


def ex_vals(d, k, L):
    it = []
    while k < L:
        t = d[k]
        a = C.tg(d, k)
        if a.cx and a.o == 2:
            return it, a.v
        if a.cx and a.o == 1:
            e = C.skip(d, k + 1, L)
            it.append({'n': -1, 's': '(structure)', 'raw': None})
            k = e
            continue
        if a.cx:
            k = a.v + a.len
            continue
        it.append({'n': a.n, 's': C.pv(d, a, t),
                   'raw': C.num(d[a.v:a.v + a.len]) if a.n in (12, 9, 2) else None})
        k = a.v + a.len
    return it, k


def ex_dec_rp(d, k, L):
    if d[k] != 0x0C:
        return None
    o = C.num(d[k + 1:k + 5])
    k += 5
    a = C.tg(d, k)
    if not (a.n == 1 and a.cx):
        return None
    p = C.num(d[a.v:a.v + a.len])
    k = a.v + a.len
    a = C.tg(d, k)
    if a.n == 2 and a.cx and not a.o:
        k = a.v + a.len
        a = C.tg(d, k)
    if not (a.n == 3 and a.o == 1):
        return None
    return {'o': o, 'p': p, 'it': ex_vals(d, a.v, L)[0]}


def ex_dec_rpm(d, k, L):
    out = []
    while k < L and d[k] == 0x0C:
        o = C.num(d[k + 1:k + 5])
        k += 5
        if d[k] != 0x1E:
            break
        k += 1
        pr = {}
        while k < L and d[k] != 0x1F:
            a = C.tg(d, k)
            if not (a.n == 2 and a.cx):
                break
            p = C.num(d[a.v:a.v + a.len])
            k = a.v + a.len
            b = C.tg(d, k)
            if b.n == 3 and b.cx and not b.o:
                k = b.v + b.len
                b = C.tg(d, k)
            if b.n == 4 and b.o == 1:
                it, k = ex_vals(d, b.v, L)
                pr[p] = it
            elif b.n == 5 and b.o == 1:
                pr[p] = None
                k = C.skip(d, b.v, L)
            else:
                break
        k += 1
        out.append({'o': o, 'pr': pr})
    return out


def hex2(b):
    return bytes(b).hex()


def sa_bytes(s):
    import re
    s = str(s or '')
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)\.(\d+):(\d+)$', s)
    if m:
        p = int(m.group(5))
        return [int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), p >> 8, p & 255]
    m = re.match(r'^MAC (\d+)$', s)
    if m:
        return [int(m.group(1))]
    out = []
    for x in s.split(':'):
        try:
            out.append(int(x, 16))
        except ValueError:
            pass
    return out


def ip_of(k):
    import re
    m = re.match(r'^(\d+\.\d+\.\d+\.\d+)', str(k or ''))
    return m.group(1) if m else ''


def pv_text(row_ty, v):
    """Present-value text: binary objects show active / inactive."""
    s = v['s']
    if 3 <= row_ty <= 5 and v['n'] == 9:
        s = 'active' if v['raw'] == 1 else 'inactive' if v['raw'] == 0 else s
    return s


class _Pending:
    __slots__ = ('dev', 'ev', 'res')

    def __init__(self, dev):
        self.dev, self.ev, self.res = dev, threading.Event(), None


class Explorer:
    """State and network work behind the Discover view. Long operations run on worker threads;
    `notify` is called (from any thread) whenever something visible changed."""

    def __init__(self, relay, store, notify=lambda: None):
        self.relay = relay
        self.store = store
        self.notify = notify
        self.devs = {}
        self.seq = 0
        self.inv = 0
        self.pend = {}
        self.lock = threading.Lock()
        self.busy = ''
        self.msg = ''
        self.stop = False
        self.on = False
        self.bbmd_rc = None
        self.scan_at = 0
        self.arm_until = 0.0
        self.opt = {'to': '', 'lo': '', 'hi': '', 'bbmd': '', 'lab': 1, 'auto': 1}
        self.opt.update(store.get('bi_discopt', {}) or {})
        self.wlog = store.get('bi_wlog', []) or []
        self.auto_labels = set(store.get('bi_autolab', []) or [])
        c = store.get('bi_disc')
        if c:
            self.scan_at = c.get('at') or 0
            for d in c.get('d') or []:
                d = dict(d)
                d.update(st='last scan', old=1, objs=None)
                self.devs[d['key']] = d
        self.pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix='bacnet-discover')

    # -------------------------------------------------------------- plumbing --
    def armed(self):
        return self.arm_until > time.time()

    def arm(self, minutes):
        left = self.relay.arm(minutes)
        self.arm_until = time.time() + left if left else 0.0
        return left

    def save_opt(self):
        self.store.set('bi_discopt', self.opt)

    def cache(self):
        keep = ('key', 'id', 'ip', 'port', 'route', 'sn', 'sa', 'mx', 'sg', 'vn', 'name', 'vendor', 'model', 'fw', 'sw',
                'desc', 'loc')
        self.store.set('bi_disc', {'at': self.scan_at, 'd': [{k: d.get(k) for k in keep} for d in list(self.devs.values())]})

    def send(self, dest, b):
        err = self.relay.send(dest, bytes(b))
        if err:
            raise RuntimeError(err)

    def pump(self):
        """Start the receive loop (once)."""
        if self.on:
            return
        self.on = True
        self.relay.open()
        threading.Thread(target=self._pump, daemon=True, name='bacnet-discover-rx').start()

    def _pump(self):
        while self.on:
            try:
                r = self.relay.recv(self.seq, 1.0)
                self.seq = r['seq']
                armed = r.get('armed')
                if armed is not None and (armed > 0) != self.armed():
                    self.arm_until = time.time() + armed if armed else 0
                    self.notify()
                for x in r['items']:
                    try:
                        self._rx(x)
                    except (IndexError, ValueError, KeyError):
                        pass
            except Exception:
                time.sleep(1.5)

    def _rx(self, it):
        raw = bytes.fromhex(it['hex'])
        L = len(raw)
        d = raw + C._PAD
        if d[0] != 0x81:
            return
        if d[1] == 0:
            self.bbmd_rc = d[4] << 8 | d[5]
            return
        ip, port = it['ip'], it['port']
        i = 4
        if d[1] == 0x04:
            ip = '.'.join(str(x) for x in d[4:8])
            port = d[8] << 8 | d[9]
            i = 10
        if d[i] != 1:
            return
        c = d[i + 1]
        i += 2
        if c & 32:
            i += 3 + d[i + 2]
        sn = None
        sa = []
        if c & 8:
            sn = d[i] << 8 | d[i + 1]
            l = d[i + 2]
            sa = list(d[i + 3:i + 3 + l])
            i += 3 + l
        if c & 32:
            i += 1
        if c & 128:
            return
        t = d[i] >> 4
        if t == 1 and d[i + 1] == 0:                       # I-Am
            k = i + 2
            a = C.tg(d, k)
            if not (a.n == 12 and not a.cx):
                return
            o = C.num(d[a.v:a.v + 4])
            k = a.v + 4
            a = C.tg(d, k)
            mx = C.num(d[a.v:a.v + a.len])
            k = a.v + a.len
            a = C.tg(d, k)
            sg = C.num(d[a.v:a.v + a.len])
            k = a.v + a.len
            a = C.tg(d, k)
            vn = C.num(d[a.v:a.v + a.len])
            if o_t(o) != 8:
                return
            did = o_i(o)
            key = f'{did}@{ip}' + (f'/{sn}:{hex2(sa)}' if sn is not None else '')
            sas = ''
            if sa:
                sas = ('.'.join(str(x) for x in sa[:4]) + ':' + str(sa[4] << 8 | sa[5]) if len(sa) == 6 else
                       'MAC ' + str(sa[0]) if len(sa) == 1 else hex2(sa))
            nd = {'key': key, 'id': did, 'ip': ip, 'port': port, 'route': {'dnet': sn, 'dadr': sa} if sn is not None else None,
                  'sn': sn, 'sa': sas, 'mx': mx, 'sg': sg, 'vn': vn, 'st': 'found', 'objs': None}
            old = self.devs.get(key)
            if old:
                keep = {k: old.get(k) for k in ('name', 'vendor', 'model', 'fw', 'sw', 'desc', 'loc', 'objs')}
                old.update(nd)
                old.update(keep)
                old['old'] = 0
                old['st'] = 'ok' if old.get('name') else 'found'
            else:
                self.devs[key] = nd
            self.notify()
            return
        seg = d[i] & 8
        inv = d[i + 1]
        with self.lock:
            p = self.pend.get(inv)
        if not p or p.dev['ip'] != ip:
            return

        def fin(res):
            with self.lock:
                self.pend.pop(inv, None)
            p.res = res
            p.ev.set()
        if t == 2:
            fin({'ok': 1})
        elif t == 3:
            if seg:
                return fin({'err': 'the answer was too long for one message (segmented)', 'seg': 1})
            fin({'d': d, 'L': L, 'k': i + 3})
        elif t == 5:
            c1, c2 = C.error_codes(d, i + 3, L)
            fin({'err': C.error_text(c1, c2), 'code': c2})
        elif t == 6:
            fin({'err': 'rejected: ' + (C.RR.get(d[i + 2]) or 'no reason given'), 'rej': 1})
        elif t == 7:
            fin({'err': 'cancelled: ' + (C.AR.get(d[i + 2]) or 'no reason given'), 'abort': 1})

    def req(self, dev, apdu, tmo=3.0, tries=2):
        """Send one confirmed request and wait for its answer: {'d','L','k'} / {'ok'} / {'err'} / {'to'}."""
        apdu = list(apdu)
        with self.lock:
            self.inv = (self.inv + 1) & 255
            inv = self.inv
            apdu[2] = inv
            p = _Pending(dev)
            self.pend[inv] = p
        for _ in range(tries):
            try:
                self.send(f"{dev['ip']}:{dev['port']}", ex_wrap(dev.get('route'), apdu, 1))
            except RuntimeError as e:
                with self.lock:
                    self.pend.pop(inv, None)
                return {'err': str(e), 'fatal': 1}
            if p.ev.wait(tmo):
                return p.res
        with self.lock:
            self.pend.pop(inv, None)
        return {'to': 1}

    def rpc(self, dev, o, p, idx=None):
        return self.req(dev, ex_rp(o, p, idx))

    def run(self, fn, *a):
        """Run fn on a worker thread."""
        self.pump()
        return self.pool.submit(self._guard, fn, *a)

    def _guard(self, fn, *a):
        try:
            return fn(*a)
        except Exception as e:                    # never let a worker die silently
            self.msg = f'Something went wrong: {e}'
            self.busy = ''
            self.notify()

    def pool_map(self, items, n, fn):
        """Run fn over items with n requests in flight (stops early when self.stop is set)."""
        it = iter(items)
        lk = threading.Lock()

        def worker():
            while not self.stop:
                with lk:
                    try:
                        x = next(it)
                    except StopIteration:
                        return
                fn(x)
        ts = [threading.Thread(target=worker, daemon=True) for _ in range(n)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

    # ---------------------------------------------------------------- devices --
    def info(self, dev):
        dev['st'] = 'reading…'
        self.notify()
        P = [77, 121, 70, 44, 28, 58, 12]
        r = self.req(dev, ex_rpm([[oid(8, dev['id']), P]]))
        if r.get('d'):
            L = ex_dec_rpm(r['d'], r['k'], r['L'])
            if L:
                x = L[0]

                def g(p):
                    v = x['pr'].get(p)
                    return unq(v[0]['s']) if v else ''
                dev.update(name=g(77), vendor=g(121), model=g(70), fw=g(44), desc=g(28), loc=g(58), sw=g(12))
                dev['st'] = 'ok'
        elif not r.get('fatal'):
            q = self.rpc(dev, oid(8, dev['id']), 77)
            if q.get('d'):
                x = ex_dec_rp(q['d'], q['k'], q['L'])
                if x and x['it']:
                    dev['name'] = unq(x['it'][0]['s'])
                dev['st'] = 'ok (name only)'
            else:
                dev['st'] = 'no answer' if q.get('to') else q.get('err')
        else:
            dev['st'] = r.get('err')
        self.notify()

    def scan(self, on_done=None):
        """Who-Is (twice), then read every new device's name. Runs on the calling (worker) thread."""
        self.stop = False
        self.busy = 'scan'
        self.msg = 'Looking for devices…'
        self.notify()
        o = self.opt
        try:
            lo, hi = int(o.get('lo') or ''), int(o.get('hi') or '')
            ok = hi >= lo
        except ValueError:
            ok = False

        def un(n):
            return [n] if n < 256 else [n >> 8, n & 255] if n < 65536 else [n >> 16, n >> 8 & 255, n & 255]
        ap = [0x10, 8, 0x08 | len(un(lo)), *un(lo), 0x18 | len(un(hi)), *un(hi)] if ok else [0x10, 8]
        dest = o.get('to') or 'broadcast'
        bbmd = (o.get('bbmd') or '').strip()
        for d in list(self.devs.values()):
            d['old'] = 1
        try:
            if bbmd:
                self.bbmd_rc = None
                self.send(bbmd + ':47808', bytes([0x81, 0x05, 0, 6, 1, 0x2C]))
                time.sleep(0.7)
                if self.bbmd_rc:
                    self.msg = f'The BBMD at {bbmd} refused the registration (code 0x{self.bbmd_rc:x}). Scanning this subnet only.'
            for _ in range(2):
                if self.stop:
                    break
                if dest == 'broadcast':
                    self.send('broadcast', ex_wrap(None, ap, 0, True))
                else:
                    self.send(dest + ':47808', ex_wrap(None, ap, 0, False, 0x0B))
                if bbmd and not self.bbmd_rc:
                    self.send(bbmd + ':47808', ex_wrap(None, ap, 0, False, 0x09))
                time.sleep(2.2)
        except RuntimeError as e:
            self.busy = ''
            self.msg = 'Could not send: ' + str(e)
            self.notify()
            return
        found = [d for d in list(self.devs.values()) if not d.get('old')]
        todo = [d for d in found if not d.get('name') or d.get('st') == 'found']
        self.msg = f'Found {len(found)} – reading names…'
        self.notify()
        self.pool_map(todo, 4, self.info)
        self.busy = ''
        self.scan_at = time.time()
        self.cache()
        n = self.labels_from_names()
        nfound = len([d for d in list(self.devs.values()) if not d.get('old')])
        self.msg = 'Stopped.' if self.stop else f"Done – {nfound} device(s) found.{f' {n} name(s) added as labels.' if n else ''}"
        self.notify()
        if on_done:
            on_done(n)

    def labels_from_names(self):
        """Copy discovered device names into the label list (when that option is on). Returns how many changed."""
        if not self.opt.get('lab'):
            return 0
        lb = self.store.labels()
        n = 0
        for d in list(self.devs.values()):
            if not d.get('name') or d.get('old'):
                continue
            k = str(d['id'])
            if k not in lb['d'] or (d['id'] in self.auto_labels and lb['d'][k] != d['name']):
                lb['d'][k] = d['name']
                self.auto_labels.add(d['id'])
                n += 1
        if n:
            self.store.save_labels()
            self.store.set('bi_autolab', sorted(self.auto_labels))
        return n

    def browse(self, dev):
        """Read the object list, then name / value / units / description of every object."""
        if dev.get('objs') and not dev.get('stale'):
            return self.values_all(dev)
        self.stop = False
        self.busy = 'browse'
        dev['pm'] = 'Reading the object list…'
        self.notify()
        dob = oid(8, dev['id'])
        lst = None
        r = self.rpc(dev, dob, 76)
        if r.get('d'):
            x = ex_dec_rp(r['d'], r['k'], r['L'])
            if x:
                lst = [v['raw'] for v in x['it'] if v['n'] == 12]
        if lst is None and not r.get('fatal') and not r.get('to'):
            c = self.rpc(dev, dob, 76, 0)
            x = ex_dec_rp(c['d'], c['k'], c['L']) if c.get('d') else None
            n = x['it'][0]['raw'] if x and x['it'] else None
            if n is None:
                dev['pm'] = 'Could not read the object list: ' + str(c.get('err') or r.get('err') or 'no answer')
                self.busy = ''
                self.notify()
                return
            lst = []

            def one(i):
                dev['pm'] = f'Reading the object list… {len(lst)} of {n}'
                self.notify()
                q = self.rpc(dev, dob, 76, i)
                y = ex_dec_rp(q['d'], q['k'], q['L']) if q.get('d') else None
                if y and y['it'] and y['it'][0]['n'] == 12:
                    lst.append(y['it'][0]['raw'])
            self.pool_map(range(1, n + 1), 4, one)
        if lst is None:
            dev['pm'] = 'Could not read the object list: ' + str(r.get('err') or 'no answer')
            self.busy = ''
            self.notify()
            return
        lst.sort(key=lambda o: (o_t(o), o_i(o)))
        dev['objs'] = [{'o': o, 'ty': o_t(o), 'inst': o_i(o), 'name': '', 'val': '', 'u': '', 'desc': ''} for o in lst]
        dev['stale'] = 0
        self.values_all(dev)

    def _fill(self, row, pr):
        def g(p):
            v = pr.get(p)
            return v[0] if v else None
        nm, v, u, ds = g(77), g(85), g(117), g(28)
        if nm:
            row['name'] = unq(nm['s'])
        if ds:
            row['desc'] = unq(ds['s'])
        row['val'] = pv_text(row['ty'], v) if v else ''
        row['u'] = EXU.get(u['raw'], '') if u and u['raw'] is not None else ''
        row['ok'] = 1

    def values_all(self, dev):
        self.stop = False
        self.busy = 'browse'
        rows = dev.get('objs') or []
        B = [rows[i:i + 4] for i in range(0, len(rows), 4)]
        done = [0]

        def one(b):
            r = self.req(dev, ex_rpm([[x['o'], [77, 85, 117, 28]] for x in b]), 4.0)
            if r.get('d'):
                for e in ex_dec_rpm(r['d'], r['k'], r['L']):
                    row = next((x for x in b if x['o'] == e['o']), None)
                    if row:
                        self._fill(row, e['pr'])
            elif len(b) > 1 and not r.get('fatal'):
                for x in b:
                    q = self.req(dev, ex_rpm([[x['o'], [77, 85, 117, 28]]]), 4.0)
                    if q.get('d'):
                        L = ex_dec_rpm(q['d'], q['k'], q['L'])
                        if L:
                            self._fill(x, L[0]['pr'])
            done[0] += len(b)
            dev['pm'] = f'Reading values… {min(done[0], len(rows))} of {len(rows)}'
            self.notify()
        self.pool_map(B, 4, one)
        dev['pm'] = ''
        self.busy = ''
        self.notify()

    def read_one(self, dev, row):
        dev['pm'] = 'Reading ' + (row.get('name') or f"{sd_ty(row['ty'])} {row['inst']}") + '…'
        self.notify()
        r = self.req(dev, ex_rpm([[row['o'], [77, 85, 117, 28]]]), 4.0)
        if r.get('d'):
            L = ex_dec_rpm(r['d'], r['k'], r['L'])
            if L:
                self._fill(row, L[0]['pr'])
            dev['pm'] = ''
        else:
            dev['pm'] = 'No answer from the device.' if r.get('to') else (r.get('err') or 'Could not read')
        self.notify()

    def read_detail(self, dev, row):
        pd = {'ok': 0}
        r = self.req(dev, ex_rpm([[row['o'], [77, 28, 85, 117, 22, 106, 69, 65, 81, 103, 167, 104, 87]]]), 5.0)
        if r.get('d'):
            L = ex_dec_rpm(r['d'], r['k'], r['L'])
            if L:
                pr = L[0]['pr']

                def g(p):
                    v = pr.get(p)
                    return v[0] if v else None

                def S(p):
                    v = g(p)
                    return unq(v['s']) if v else ''
                pd['ok'] = 1
                pd.update(cov=S(22), res=S(106), min=S(69), max=S(65), rel=S(103), prof=S(167), rd=S(104))
                o = g(81)
                pd['oos'] = (o['raw'] == 1 or 'true' in o['s'].lower()) if o else None
                binary = 3 <= row['ty'] <= 5

                def fm(v):
                    if v['n'] == 0:
                        return ''
                    if binary and v['n'] == 9:
                        return 'active' if v['raw'] == 1 else 'inactive'
                    return v['s']
                pd['pa'] = [{'a': v['n'] != 0, 's': fm(v)} for v in pr[87]] if pr.get(87) else None
                if g(77):
                    row['name'] = unq(g(77)['s'])
                if g(28):
                    row['desc'] = unq(g(28)['s'])
                v, u = g(85), g(117)
                if v:
                    row['val'] = fm(v) or v['s']
                if u and u['raw'] is not None:
                    row['u'] = EXU.get(u['raw'], '')
            else:
                pd['err'] = 'No details came back.'
        else:
            pd['err'] = 'No answer from the device.' if r.get('to') else (r.get('err') or 'Could not read the details.')
        row['pd'] = pd
        self.notify()

    def read_prop_list(self, dev, row):
        r = self.req(dev, ex_rpm([[row['o'], [371]]]), 5.0)
        L = []
        if r.get('d'):
            x = ex_dec_rpm(r['d'], r['k'], r['L'])
            it = x[0]['pr'].get(371) if x else None
            if it:
                L = [C.prname(v['raw']) for v in it]
        row['pl'] = L or ['(the device did not list its properties)']
        row['pll'] = 0
        self.notify()

    def ensure(self, d):
        """A discovery entry for a device seen in a capture, so it can be read over IP."""
        ip = ip_of(d['key'])
        if not ip:
            return None
        for x in list(self.devs.values()):
            if x['id'] == d['id'] and (x['ip'] == ip or (x.get('sn') == d['sn'] and d['sn'] is not None)):
                return x
        try:
            port = int(str(d['key']).split(':')[1])
        except (IndexError, ValueError):
            port = 47808
        sab = sa_bytes(d['sa']) if d['sn'] is not None else []
        e = {'key': f"{d['id']}@{ip}" + (f"/{d['sn']}:{hex2(sab)}" if d['sn'] is not None else ''), 'id': d['id'],
             'ip': ip, 'port': port, 'route': {'dnet': d['sn'], 'dadr': sab} if d['sn'] is not None else None,
             'sn': d['sn'], 'sa': d['sa'] or '', 'mx': 480, 'sg': 3, 'vn': d['v'], 'st': 'from capture', 'objs': None}
        self.devs[e['key']] = e
        return e

    # ------------------------------------------------------------------ write --
    def write(self, dev, row, val, pri, release, shown):
        """WriteProperty present-value, then read it back. Returns (log entry, message, ok)."""
        tn = f"{sd_ty(row['ty'])} {row['inst']}"
        e = {'t': time.time() * 1000, 'dev': dev['id'], 'dname': dev.get('name') or '', 'obj': tn,
             'pname': row.get('name') or '', 'val': '(release)' if release else shown.strip(), 'pri': pri, 'res': ''}
        if not self.armed():
            return e, 'Write access switched off while this was open.', False
        r = self.req(dev, ex_wp(row['o'], val, pri), 4.0, 1)
        binary = row['ty'] in (4, 5)
        if r.get('ok'):
            e['res'] = 'accepted'
            b = self.req(dev, ex_rpm([[row['o'], [85, 87]]]), 4.0)
            rb = ''
            if b.get('d'):
                L = ex_dec_rpm(b['d'], b['k'], b['L'])
                x = L[0] if L else None
                pv0 = x['pr'].get(85)[0] if x and x['pr'].get(85) else None
                pa = x['pr'].get(87) if x else None
                if pv0:
                    s = pv0['s']
                    if binary and pv0['n'] == 9:
                        s = 'active' if pv0['raw'] == 1 else 'inactive'
                    row['val'] = s
                    e['rb'] = s
                    rb = f"Present value now: {s} {row.get('u') or ''}."
                if pa:
                    hi = next((i for i, v in enumerate(pa) if v['n'] != 0), -1)
                    if hi >= 0:
                        hp = hi + 1
                        rb += (f" Highest active command: priority {hp} = {pa[hi]['s']}" +
                               (' (yours)' if hp == pri else ' – a higher-priority command is overriding yours' if hp < pri
                                else ' – that is now in control' if release else ' (lower priority than yours)') + '.')
                        e['hi'] = hp
                        e['ov'] = hp < pri
                    else:
                        rb += ' No commands are active (the point is at its default).'
            else:
                rb = 'Could not read the value back (' + str(b.get('err') or 'no answer') + ').'
            msg, ok = 'The device accepted the write. ' + rb, True
        else:
            e['res'] = 'no answer' if r.get('to') else (r.get('err') or 'failed')
            msg = ('No answer from the device – the write may or may not have happened.' if r.get('to')
                   else 'Not written: ' + str(r.get('err') or 'failed'))
            for k, hint in WHINT:
                if k in str(r.get('err') or ''):
                    msg += ' ' + hint
                    break
            ok = False
        self.wlog.insert(0, e)
        del self.wlog[200:]
        self.store.set('bi_wlog', self.wlog)
        self.notify()
        return e, msg, ok

    # ------------------------------------------------------------------ misc --
    @staticmethod
    def cats(e):
        m = {}
        for o in e.get('objs') or []:
            if o['ty'] == 8:
                continue
            m.setdefault(o['ty'], []).append(o)
        return sorted(m.items(), key=lambda x: cat_ord(x[0]))

    @staticmethod
    def addr(d):
        return f"{d['ip']} → network {d['sn']}{', ' + d['sa'] if d.get('sa') else ''}" if d.get('sn') is not None else d['ip']

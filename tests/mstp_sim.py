"""A simulated MS/TP trunk with one or more controllers, to test bi_mstp + Discover without hardware."""
import collections
import math
import struct
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the app's folder
import bi_core as C  # noqa: E402
import bi_mstp as M  # noqa: E402


class Bus:
    """An RS-485 wire: every byte written by one port is received by all the others."""

    def __init__(self):
        self.ports = []
        self.lock = threading.Lock()
        self.log = []

    def port(self):
        p = Port(self)
        self.ports.append(p)
        return p


class Port:
    def __init__(self, bus):
        self.bus = bus
        self.buf = collections.deque()
        self.cv = threading.Condition()
        self.closed = False

    def write(self, b):
        with self.bus.lock:
            for f in M.Parser().feed(bytes(b)):
                self.bus.log.append((time.perf_counter(), f[0], f[1], f[2]))
            for p in self.bus.ports:
                if p is not self and not p.closed:
                    with p.cv:
                        p.buf.extend(b)
                        p.cv.notify_all()

    @property
    def in_waiting(self):
        return len(self.buf)

    def read(self, n=1):
        with self.cv:
            if not self.buf:
                self.cv.wait(0.001)
            out = bytearray()
            while self.buf and len(out) < max(n, 1):
                out.append(self.buf.popleft())
            return bytes(out)

    def close(self):
        self.closed = True


def ctx(n, b):
    return bytes([(n << 4) | 8 | len(b)]) + b


def cstr(s):
    b = b'\x00' + s.encode()
    return (bytes([0x70 | len(b)]) if len(b) < 5 else bytes([0x75, len(b)])) + b


def real(f):
    return b'\x44' + struct.pack('>f', f)


def enum(v):
    return bytes([0x91, v])


def unsigned(v):
    return bytes([0x21, v]) if v < 256 else bytes([0x22, v >> 8, v & 255])


def oidb(t, i):
    return struct.pack('>I', t * 4194304 + i)


class SimController(threading.Thread):
    """A master node: passes the token, polls for new masters, answers Who-Is and reads."""

    def __init__(self, bus, mac, dev_id, name, objs):
        super().__init__(daemon=True)
        self.p = bus.port()
        self.mac, self.dev, self.name = mac, dev_id, name
        self.objs = objs                     # {(type, inst): {prop: encoded value}}
        self.parser = M.Parser()
        self.ns = None
        self.ps = (mac + 1) % 128
        self.out = collections.deque()       # frames to send when we hold the token
        self.on = True
        self.tokens = 0
        self.trend = []                      # [(date bytes, time bytes), value] of trend log 1, when there is one
        self.clock_off = 0.0                 # how far the device clock is from the PC's, in seconds
        self.password = ''                   # ReinitializeDevice / DeviceCommunicationControl password
        self.reinits = []                    # restarts asked for: 0 cold, 1 warm
        self.dcc = 0                         # 0 enabled, 1 disabled, 2 initiation disabled
        self.cov = {}                        # object id -> (subscriber MAC, lifetime)
        self.cov_refuse = set()              # object ids that refuse COV subscriptions
        self.synced = []                     # time synchronisations received: (service, date, time)

    def send(self, ty, dst, data=b''):
        self.p.write(M.frame(ty, dst, self.mac, data))

    def frames(self, wait):
        end = time.perf_counter() + wait
        out = []
        while not out and time.perf_counter() < end:
            out = [f for f in self.parser.feed(self.p.read(256)) if f[2] != self.mac]
        return out

    def run(self):
        # the lowest master starts the ring once the line has been quiet
        tok = self.mac == min(c.mac for c in SIMS)
        time.sleep(0.05)
        while self.on:
            if not tok:
                for ty, dst, src, data in self.frames(0.02):
                    if ty == M.TOKEN and dst == self.mac:
                        tok = True
                    elif ty == M.PFM and dst == self.mac:
                        self.send(M.REPLY_PFM, src)
                    elif ty in (M.DER, M.DNER) and dst in (self.mac, 255):
                        self.serve(src, data, ty == M.DER and dst == self.mac)
                continue
            self.tokens += 1
            while self.out:
                self.p.write(self.out.popleft())
            # poll one free address after us every token (fast, so the test is quick)
            a = self.ps
            nxt = self.ns if self.ns is not None else self.mac
            if a != self.mac and ((a - self.mac) % 128 < (nxt - self.mac) % 128 or self.ns is None):
                self.send(M.PFM, a)
                for ty, dst, src, _d in self.frames(0.03):
                    if ty == M.REPLY_PFM and dst == self.mac and src == a:
                        self.ns = a
            self.ps = (a + 1) % 128
            if self.ps == self.mac or (self.ns is not None and self.ps == self.ns):
                self.ps = (self.mac + 1) % 128
            if self.ns is None:
                time.sleep(0.002)
                continue
            self.send(M.TOKEN, self.ns)
            got = self.frames(0.06)
            if not got:
                self.send(M.TOKEN, self.ns)
                got = self.frames(0.06)
            if not got:
                self.ns = None                      # next station died: keep the token, poll again
                continue
            tok = False
            for ty, dst, src, data in got:
                if ty == M.TOKEN and dst == self.mac:
                    tok = True
                elif ty == M.PFM and dst == self.mac:
                    self.send(M.REPLY_PFM, src)
                elif ty in (M.DER, M.DNER) and dst in (self.mac, 255):
                    self.serve(src, data, ty == M.DER and dst == self.mac)

    def serve(self, src, d, reply_now):
        """Answer a BACnet request (NPDU in d)."""
        c = d[1]
        i = 2
        if c & 0x20:
            i += 3 + d[i + 2]
        if c & 0x08:
            i += 3 + d[i + 2]
        if c & 0x20:
            i += 1
        if c & 0x80:
            return
        t = d[i] >> 4
        if self.dcc == 1 and not (t == 0 and d[i + 3] in (17, 20)):
            return                                 # communication disabled: only DCC and restart are answered
        if t == 1 and d[i + 1] == 8:              # Who-Is -> I-Am when we next hold the token
            iam = b'\x01\x00' + b'\x10\x00\xc4' + oidb(8, self.dev) + b'\x22\x01\xe0' + enum(3) + unsigned(8)
            self.out.append(M.frame(M.DNER, 255, self.mac, iam))
            return
        if t == 1 and d[i + 1] == 7:              # Who-Has -> I-Have
            self.who_has(d, i + 2)
            return
        if t == 1 and d[i + 1] in (6, 9):         # (UTC) Time Synchronization: set our clock
            dt, tm = d[i + 3:i + 7], d[i + 8:i + 12]
            self.synced.append((d[i + 1], bytes(dt), bytes(tm)))
            want = time.mktime((1900 + dt[0], dt[1], dt[2], tm[0], tm[1], tm[2], 0, 0, -1))
            if d[i + 1] == 9:
                want -= time.timezone if not time.localtime().tm_isdst else time.altzone
            self.clock_off = want - time.time()
            return
        if t != 0:
            return
        inv, sv = d[i + 2], d[i + 3]
        k = i + 4
        if sv == 20:                              # ReinitializeDevice
            pw = self._password(d, k + 2, 1)
            if pw != self.password:
                body = b'\x50' + bytes([inv, 20]) + enum(2) + enum(26)          # security / password failure
            else:
                self.reinits.append(d[k + 1])
                body = b'\x20' + bytes([inv, 20])
            return self._reply(src, body, reply_now)
        if sv == 17:                              # DeviceCommunicationControl
            j = k
            if d[j] >> 4 == 0:
                j += 1 + (d[j] & 7)
            mode = d[j + 1]
            if self._password(d, j + 2, 2) != self.password:
                return self._reply(src, b'\x50' + bytes([inv, 17]) + enum(2) + enum(26), reply_now)
            self.dcc = mode
            return self._reply(src, b'\x20' + bytes([inv, 17]), reply_now)
        if sv == 5:                               # SubscribeCOV
            o = C.num(d[k + 3:k + 7]) if d[k] == 0x09 else None
            if o in self.cov_refuse:
                return self._reply(src, b'\x50' + bytes([inv, 5]) + enum(5) + enum(45), reply_now)  # services / optional functionality
            if len(d) <= k + 7:
                self.cov.pop(o, None)
            else:
                self.cov[o] = (src, C.num(d[k + 10:]))
            self._reply(src, b'\x20' + bytes([inv, 5]), reply_now)
            if o in self.cov:
                self.notify_cov(o)
            return
        if sv == 12:
            o = C.num(d[k + 1:k + 5])
            p = d[k + 6]
            idx = d[k + 8] if len(d) > k + 7 and d[k + 7] == 0x29 else None
            val = self.prop(o, p, idx)
            body = b'\x30' + bytes([inv, 12]) + b'\x0c' + struct.pack('>I', o) + ctx(1, bytes([p]))
            if idx is not None:
                body += ctx(2, bytes([idx]))
            body += b'\x3e' + val + b'\x3f'
        elif sv == 14:
            body = b'\x30' + bytes([inv, 14])
            while k < len(d) and d[k] == 0x0C:
                o = C.num(d[k + 1:k + 5])
                k += 6
                body += b'\x0c' + struct.pack('>I', o) + b'\x1e'
                while d[k] != 0x1F:
                    p = d[k + 1]
                    k += 2
                    if p == 8:                     # ALL properties
                        t_, i_ = o // 4194304, o % 4194304
                        props = list(self.objs.get((t_, i_), {})) + [75, 79, 111] if t_ != 8 else [77, 121, 70, 44]
                        for q in props:
                            body += ctx(2, bytes([q])) + b'\x4e' + self.prop(o, q) + b'\x4f'
                        continue
                    body += ctx(2, bytes([p])) + b'\x4e' + self.prop(o, p) + b'\x4f'
                k += 1
                body += b'\x1f'
        elif sv == 26 and self.trend:               # Read Range by position on a trend log's log-buffer
            o = C.num(d[k + 1:k + 5])
            j = k + 8                                # after the object, the property and the opening tag
            a = C.tg(d, j)
            start = C.num(d[a.v:a.v + a.len])
            b = C.tg(d, a.v + a.len)
            cnt = C.num(d[b.v:b.v + b.len])
            recs = self.trend[start - 1:start - 1 + cnt]
            more = start - 1 + cnt < len(self.trend)
            items = b''.join(b'\x0e' + bytes([0xA4, *dt[0]]) + bytes([0xB4, *dt[1]]) + b'\x0f' + b'\x1e\x2c' + struct.pack('>f', v)
                             + b'\x1f' + b'\x2a\x04\x00' for dt, v in recs)
            body = (b'\x30' + bytes([inv, 26]) + b'\x0c' + struct.pack('>I', o) + b'\x19\x83'
                    + b'\x3a\x05' + bytes([(0x80 if start == 1 else 0) | (0x40 if not more else 0) | (0x20 if more else 0)])
                    + b'\x49' + bytes([len(recs)]) + b'\x5e' + items + b'\x5f')
        elif sv == 29:                              # Get Event Information: AI 1 is in high-limit alarm, not acknowledged
            body = (b'\x30' + bytes([inv, 29]) + b'\x0e' + b'\x0c' + oidb(0, 1) + b'\x19\x03' + b'\x2a\x05\x00'
                    + b'\x3e' + b'\x3f' + b'\x49\x00' + b'\x5a\x05\xe0' + b'\x6e' + unsigned(1) + unsigned(1) + unsigned(1) + b'\x6f'
                    + b'\x0f' + b'\x19\x00')
        elif sv == 15:
            body = b'\x20' + bytes([inv, 15])       # simple ACK: accepted
            o = C.num(d[k + 1:k + 5])
            p = d[k + 6]
            j = C.skip(d, k + 8, len(d))            # after the closing tag of the value
            val = bytes(d[k + 8:j - 1])
            pri = d[j + 1] if j + 1 < len(d) and d[j] == 0x49 else 16
            ob = self.objs[(o // 4194304, o % 4194304)]
            if p == 85 and 87 in ob:                # commandable: the priority array decides the present value
                pa = self.split_pa(ob[87])
                pa[pri - 1] = val if val != b'\x00' else b'\x00'
                ob[87] = b''.join(pa)
                act = next((x for x in pa if x != b'\x00'), None)
                ob[85] = act if act is not None else ob.get(104, ob[85])
            elif p == 85:
                ob[85] = val
            else:
                ob[p] = val
            if o in self.cov:
                self.notify_cov(o)
        else:
            return
        self._reply(src, body, reply_now)

    def _reply(self, src, body, reply_now):
        f = M.frame(M.DNER, src, self.mac, b'\x01\x00' + body)
        if reply_now:
            self.p.write(f)                         # answer straight away (allowed while the requester holds the token)
        else:
            self.out.append(f)

    @staticmethod
    def _password(d, k, n):
        """The character string in context tag n at d[k] ('' when there is none)."""
        if k >= len(d) or d[k] >> 4 != n:
            return ''
        ln = d[k] & 7
        j = k + 1
        if ln == 5:
            ln, j = d[k + 1], k + 2
        return bytes(d[j + 1:j + ln]).decode('utf-8', 'replace')

    @staticmethod
    def split_pa(b):
        """A priority array's 16 encoded values."""
        out, k = [], 0
        while k < len(b) and len(out) < 16:
            a = C.tg(b, k)
            n = 1 if a.n == 0 else a.v + a.len - k
            out.append(bytes(b[k:k + n]))
            k += n
        return out + [b'\x00'] * (16 - len(out))

    def notify_cov(self, o):
        """Send an unconfirmed COV notification with the present value and status flags of object o."""
        src, life = self.cov[o]
        body = (b'\x10\x02' + b'\x09\x57' + b'\x1c' + oidb(8, self.dev) + b'\x2c' + struct.pack('>I', o) + b'\x39' + bytes([min(life, 255)])
                + b'\x4e' + b'\x09\x55\x2e' + self.prop(o, 85) + b'\x2f' + b'\x09\x6f\x2e' + self.prop(o, 111) + b'\x2f' + b'\x4f')
        self.out.append(M.frame(M.DNER, src, self.mac, b'\x01\x00' + body))

    def who_has(self, d, k):
        """Answer Who-Has (by object identifier or by name) when we have the object."""
        lo = hi = None
        a = C.tg(d, k)
        if a.cx and a.n == 0:
            lo = C.num(d[a.v:a.v + a.len])
            k = a.v + a.len
            b = C.tg(d, k)
            hi = C.num(d[b.v:b.v + b.len])
            k = b.v + b.len
            a = C.tg(d, k)
        if lo is not None and not lo <= self.dev <= hi:
            return
        hit = None
        if a.n == 2:
            o = C.num(d[a.v:a.v + 4])
            ob = self.objs.get((o // 4194304, o % 4194304))
            hit = (o, ob) if ob else None
        else:
            name = bytes(d[a.v + 1:a.v + a.len]).decode('utf-8', 'replace')
            for (t_, i_), ob in self.objs.items():
                if ob.get(77) == cstr(name):
                    hit = (t_ * 4194304 + i_, ob)
        if hit:
            o, ob = hit
            body = b'\x10\x01' + b'\xc4' + oidb(8, self.dev) + b'\xc4' + struct.pack('>I', o) + ob.get(77, cstr(''))
            self.out.append(M.frame(M.DNER, 255, self.mac, b'\x01\x00' + body))

    def prop(self, o, p, idx=None):
        t, inst = o // 4194304, o % 4194304
        if t == 8:
            if p == 76:
                lst = [(8, self.dev)] + list(self.objs)
                if idx == 0:
                    return unsigned(len(lst))
                return b''.join(b'\xc4' + oidb(*x) for x in lst)
            if p in (56, 57):
                tm = time.localtime(time.time() + self.clock_off)
                return (bytes([0xA4, tm.tm_year - 1900, tm.tm_mon, tm.tm_mday, tm.tm_wday + 1]) if p == 56
                        else bytes([0xB4, tm.tm_hour, tm.tm_min, tm.tm_sec, 0]))
            if p == 112:
                return enum(0)
            return {77: cstr(self.name), 121: cstr('Delta Controls'), 70: cstr('Sim-MSTP'), 44: cstr('4.1'),
                    28: cstr('simulated controller'), 58: cstr('Plant room'), 12: cstr('1.0')}.get(p, b'\x00')
        ob = self.objs.get((t, inst), {})
        if t == 17 and p == 123 and 123 in ob:       # a weekly schedule that was written: given back as written
            if idx is None:
                return ob[123]
            days, k = [], 0
            while k < len(ob[123]):
                j = C.skip(ob[123], k + 1, len(ob[123]))
                days.append(ob[123][k:j])
                k = j
            return unsigned(len(days)) if idx == 0 else days[idx - 1]
        if t == 17 and p == 123:                     # weekly schedule: on 07:00, off 18:00 on weekdays
            day = b'\x0e' + b'\xb4\x07\x00\x00\x00' + enum(1) + b'\xb4\x12\x00\x00\x00' + enum(0) + b'\x0f'
            week = [day] * 5 + [b'\x0e\x0f'] * 2
            if idx == 0:
                return unsigned(7)
            return week[idx - 1] if idx else b''.join(week)
        if p == 110 and 'st' in ob:                  # state text: the whole list, its length or one state
            st = ob['st']
            return unsigned(len(st)) if idx == 0 else cstr(st[idx - 1]) if idx else b''.join(cstr(x) for x in st)
        if t == 20 and p == 141:
            return unsigned(len(self.trend))
        if p == 75:
            return b'\xc4' + oidb(t, inst)
        if p == 79:
            return enum(t)
        if p == 111:                                 # AI 1: in alarm; out of service when 81 says so
            return b'\x82\x04' + bytes([(0x80 if (t, inst) == (0, 1) else 0) | (0x10 if ob.get(81) == b'\x11' else 0)])
        if p == 36:
            return enum(3) if (t, inst) == (0, 1) else enum(0)
        if p == 45:
            return real(12.0)
        return ob.get(p, b'\x00' if p not in (87,) else b'\x00' * 16)


SIMS = []


def make_trunk(controllers, site=False):
    """site=True adds what the site tools look for: a trend log with history, a schedule, a point out of service,
    one in fault, the fan overridden at priority 8, and the second controller's clock 5 minutes fast."""
    bus = Bus()
    SIMS.clear()
    for n, (mac, did, name) in enumerate(controllers):
        objs = {(0, 1): {77: cstr('SAT'), 85: real(13.2), 117: enum(62), 28: cstr('Supply air temp')},
                (2, 7): {77: cstr('SAT SP'), 85: real(13.0), 117: enum(62), 28: cstr('')},
                (4, 2): {77: cstr('Fan'), 85: enum(1), 117: enum(95), 28: cstr('Supply fan')}}
        sim = SimController(bus, mac, did, name, objs)
        if site:
            objs[(0, 2)] = {77: cstr('RAT'), 85: real(21.0), 117: enum(62), 28: cstr(''), 81: b'\x11'}
            objs[(0, 3)] = {77: cstr('OAT'), 85: real(0.0), 117: enum(62), 28: cstr(''), 103: enum(1)}
            objs[(4, 2)][87] = b'\x00' * 7 + enum(1) + b'\x00' * 8
            objs[(4, 2)][104] = enum(0)
            objs[(4, 2)][81] = b'\x10'
            objs[(6, 1)] = {77: cstr('Holidays'), 85: b'\x10', 28: cstr(''),
                            23: b'\x0c' + bytes([126, 12, 25, 255]) + b'\x1e\xa4' + bytes([126, 12, 31, 255])
                                + b'\xa4' + bytes([127, 1, 1, 255]) + b'\x1f'}
            objs[(19, 1)] = {77: cstr('Fan speed'), 85: unsigned(2), 28: cstr(''), 'st': ['Off', 'Low', 'High']}
            objs[(13, 1)] = {77: cstr('Mode'), 85: unsigned(1), 28: cstr('')}
            objs[(17, 1)] = {77: cstr('Occupancy'), 85: enum(1), 174: enum(0), 32: b'\xa4\xff\xff\xff\xff' * 2,
                             38: b'\x0e\x0c' + bytes([126, 12, 25, 255]) + b'\x0f\x2e\xb4\x00\x00\x00\x00' + enum(0)
                                 + b'\x2f\x39\x0a'}
            objs[(20, 1)] = {77: cstr('SAT trend'), 133: b'\x11', 134: b'\x23\x01\x5f\x90', 126: unsigned(500),
                             132: b'\x0c' + oidb(0, 1) + b'\x19\x55'}
            objs[(20, 2)] = {77: cstr('Old trend'), 133: b'\x10', 134: b'\x23\x01\x5f\x90', 126: unsigned(500),
                             132: b'\x0c' + oidb(0, 1) + b'\x19\x55'}
            t0 = time.time() - 300 * 900
            for j in range(300):
                tm = time.localtime(t0 + j * 900)
                sim.trend.append((((tm.tm_year - 1900, tm.tm_mon, tm.tm_mday, tm.tm_wday + 1),
                                   (tm.tm_hour, tm.tm_min, tm.tm_sec, 0)), 13 + 3 * math.sin(j / 12)))
            sim.clock_off = 300.0 if n == 1 else 0.0
        SIMS.append(sim)
    for s in SIMS:
        s.start()
    return bus

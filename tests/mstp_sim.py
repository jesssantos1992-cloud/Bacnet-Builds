"""A simulated MS/TP trunk with one or more controllers, to test bi_mstp + Discover without hardware."""
import collections
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
        if t == 1 and d[i + 1] == 8:              # Who-Is -> I-Am when we next hold the token
            iam = b'\x01\x00' + b'\x10\x00\xc4' + oidb(8, self.dev) + b'\x22\x01\xe0' + enum(3) + unsigned(8)
            self.out.append(M.frame(M.DNER, 255, self.mac, iam))
            return
        if t != 0:
            return
        inv, sv = d[i + 2], d[i + 3]
        k = i + 4
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
        elif sv == 29:                              # Get Event Information: AI 1 is in high-limit alarm, not acknowledged
            body = (b'\x30' + bytes([inv, 29]) + b'\x0e' + b'\x0c' + oidb(0, 1) + b'\x19\x03' + b'\x2a\x05\x00'
                    + b'\x3e' + b'\x3f' + b'\x49\x00' + b'\x5a\x05\xe0' + b'\x6e' + unsigned(1) + unsigned(1) + unsigned(1) + b'\x6f'
                    + b'\x0f' + b'\x19\x00')
        elif sv == 15:
            body = b'\x20' + bytes([inv, 15])       # simple ACK: accepted
            o = C.num(d[k + 1:k + 5])
            self.objs[(o // 4194304, o % 4194304)][85] = d[k + 9:k + 14] if d[k + 8] == 0x44 else d[k + 8:k + 10]
        else:
            return
        f = M.frame(M.DNER, src, self.mac, b'\x01\x00' + body)
        if reply_now:
            self.p.write(f)                         # answer straight away (allowed while the requester holds the token)
        else:
            self.out.append(f)

    def prop(self, o, p, idx=None):
        t, inst = o // 4194304, o % 4194304
        if t == 8:
            if p == 76:
                lst = [(8, self.dev)] + list(self.objs)
                if idx == 0:
                    return unsigned(len(lst))
                return b''.join(b'\xc4' + oidb(*x) for x in lst)
            return {77: cstr(self.name), 121: cstr('Delta Controls'), 70: cstr('Sim-MSTP'), 44: cstr('4.1'),
                    28: cstr('simulated controller'), 58: cstr('Plant room'), 12: cstr('1.0')}.get(p, b'\x00')
        ob = self.objs.get((t, inst), {})
        if p == 75:
            return b'\xc4' + oidb(t, inst)
        if p == 79:
            return enum(t)
        if p == 111:
            return b'\x82\x04\x80' if (t, inst) == (0, 1) else b'\x82\x04\x00'     # AI 1: in alarm
        if p == 36:
            return enum(3) if (t, inst) == (0, 1) else enum(0)
        if p == 45:
            return real(12.0)
        return ob.get(p, b'\x00' if p not in (87,) else b'\x00' * 16)


SIMS = []


def make_trunk(controllers):
    bus = Bus()
    SIMS.clear()
    for mac, did, name in controllers:
        objs = {(0, 1): {77: cstr('SAT'), 85: real(13.2), 117: enum(62), 28: cstr('Supply air temp')},
                (2, 7): {77: cstr('SAT SP'), 85: real(13.0), 117: enum(62), 28: cstr('')},
                (4, 2): {77: cstr('Fan'), 85: enum(1), 117: enum(95), 28: cstr('Supply fan')}}
        SIMS.append(SimController(bus, mac, did, name, objs))
    for s in SIMS:
        s.start()
    return bus

"""
bi_sample.py - a made-up BACnet/IP capture of a small building, for Help > Open sample capture and the tests:
a front-end polling four controllers, COV value changes, writes (one override left in place), an alarm,
refused requests, a foreign device that lets its registration lapse and broadcasts forwarded by two BBMDs.
No real site's data is in it.
"""
from __future__ import annotations

import math
import random
import struct

PORT = 47808
FRONT = '10.20.1.10'                     # the front-end (workstation)
LAPTOP = '10.30.5.77'                    # a foreign device on another subnet
BBMD_A, BBMD_B = '10.20.1.1', '10.20.1.2'
DEVICES = [  # (ip, device ID, name, vendor ID)
    ('10.20.1.21', 1021, 'AHU-1', 5), ('10.20.1.22', 1022, 'AHU-2', 5),
    ('10.20.1.31', 1031, 'Boiler Plant', 24), ('10.20.1.41', 1041, 'VAV Floor 1', 36)]
AI, AO, AV, BO, DEV = 0, 1, 2, 4, 8
PV, NAME = 85, 77


def oid(t, i):
    return struct.pack('>I', t << 22 | i)


def ctx(n, b):
    """A context tag with a short payload."""
    return bytes([n << 4 | 8 | len(b)]) + b if len(b) <= 4 else bytes([n << 4 | 8 | 5, len(b)]) + b


def uint(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), 'big')
    return b


def app_uint(v):
    b = uint(v)
    return bytes([0x20 | len(b)]) + b


def app_real(v):
    return b'\x44' + struct.pack('>f', v)


def app_enum(v):
    b = uint(v)
    return bytes([0x90 | len(b)]) + b


def app_text(s):
    b = b'\x00' + s.encode()
    return (bytes([0x70 | len(b)]) if len(b) <= 4 else bytes([0x75, len(b)])) + b


def opening(n):
    return bytes([n << 4 | 0x0E])


def closing(n):
    return bytes([n << 4 | 0x0F])


class Cap:
    def __init__(self):
        self.out = [struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
        self.t = 1_788_000_000.0          # a fixed start, so the sample is the same every time
        self.ipid = 0

    def udp(self, src, dst, bvlc):
        self.ipid += 1
        u = struct.pack('>HHHH', PORT, PORT, 8 + len(bvlc), 0) + bvlc
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), self.ipid & 0xFFFF, 0, 64, 17, 0,
                         bytes(int(x) for x in src.split('.')), bytes(int(x) for x in dst.split('.')))
        dmac = b'\xff' * 6 if dst.endswith('.255') else bytes([0, 0x1c, 0x11, 0, 0, int(dst.split('.')[-1])])
        eth = dmac + bytes([0, 0x1c, 0x11, 0, 0, int(src.split('.')[-1])]) + b'\x08\x00' + ip + u
        sec = int(self.t)
        self.out.append(struct.pack('<IIII', sec, int((self.t - sec) * 1e6), len(eth), len(eth)) + eth)

    def bacnet(self, src, dst, apdu, reply=False, bcast=False):
        npdu = bytes([1, 4 if reply else 0]) + apdu
        f = 0x0B if bcast else 0x0A
        self.udp(src, dst, bytes([0x81, f]) + struct.pack('>H', 4 + len(npdu)) + npdu)

    def forwarded(self, bbmd, orig, apdu):
        npdu = b'\x01\x00' + apdu
        a = bytes(int(x) for x in orig.split('.')) + struct.pack('>H', PORT)
        self.udp(bbmd, '10.20.1.255', b'\x81\x04' + struct.pack('>H', 10 + len(npdu)) + a + npdu)

    def register(self, fd, bbmd, ttl):
        self.udp(fd, bbmd, b'\x81\x05\x00\x06' + struct.pack('>H', ttl))
        self.udp(bbmd, fd, b'\x81\x00\x00\x06\x00\x00')

    def step(self, s):
        self.t += s


def build(minutes=12, seed=7):
    """The sample capture as pcap bytes."""
    rnd = random.Random(seed)
    c = Cap()
    inv = [0]

    def nid():
        inv[0] = (inv[0] + 1) % 256
        return inv[0]

    def read(dev, obj, prop, val):
        i = nid()
        c.bacnet(FRONT, dev[0], bytes([0x00, 0x05, i, 0x0C]) + ctx(0, obj) + ctx(1, uint(prop)), reply=True)
        c.step(0.004 + rnd.random() * (0.03 if dev[1] != 1041 else 0.35))
        c.bacnet(dev[0], FRONT, bytes([0x30, i, 0x0C]) + ctx(0, obj) + ctx(1, uint(prop)) + opening(3) + val + closing(3))

    def write(dev, obj, val, pri):
        i = nid()
        c.bacnet(FRONT, dev[0], bytes([0x00, 0x05, i, 0x0F]) + ctx(0, obj) + ctx(1, uint(PV)) + opening(3) + val + closing(3)
                 + ctx(4, uint(pri)), reply=True)
        c.step(0.01)
        c.bacnet(dev[0], FRONT, bytes([0x20, i, 0x0F]))

    def cov(dev, obj, val):
        c.bacnet(dev[0], FRONT, bytes([0x10, 0x02]) + ctx(0, uint(1)) + ctx(1, oid(DEV, dev[1])) + ctx(2, obj) + ctx(3, uint(300))
                 + opening(4) + ctx(0, uint(PV)) + opening(2) + val + closing(2)
                 + ctx(0, uint(111)) + opening(2) + b'\x82\x04\x00' + closing(2) + closing(4))

    # discovery: Who-Is, every device answers I-Am, the front-end reads the names
    c.bacnet(FRONT, '10.20.1.255', b'\x10\x08', bcast=True)
    for d in DEVICES:
        c.step(0.02 + rnd.random() * 0.05)
        c.bacnet(d[0], '10.20.1.255', b'\x10\x00\xc4' + oid(DEV, d[1]) + app_uint(1476) + app_enum(3) + app_uint(d[3]), bcast=True)
    for d in DEVICES:
        c.step(0.05)
        read(d, oid(DEV, d[1]), NAME, app_text(d[2]))
    c.register(LAPTOP, BBMD_A, 60)
    temps = {d[1]: 20 + rnd.random() * 3 for d in DEVICES}
    end = c.t + minutes * 60
    tick, wrote, released, alarm, lapse = 0, False, False, False, False
    while c.t < end:
        tick += 1
        for d in DEVICES:
            c.step(0.2 + rnd.random() * 0.3)
            temps[d[1]] += math.sin(tick / 9 + d[1]) * 0.15 + (rnd.random() - 0.5) * 0.05
            read(d, oid(AI, 1), PV, app_real(round(temps[d[1]], 2)))
            if d[1] == 1031 and tick % 7 == 0:                 # the boiler plant has no AI 2: refused every time
                i = nid()
                c.bacnet(FRONT, d[0], bytes([0x00, 0x05, i, 0x0C]) + ctx(0, oid(AI, 2)) + ctx(1, uint(PV)), reply=True)
                c.step(0.01)
                c.bacnet(d[0], FRONT, bytes([0x50, i, 0x0C]) + app_enum(1) + app_enum(31))
        if tick % 3 == 0:
            for d in DEVICES[:2]:
                cov(d, oid(AV, 5), app_real(round(55 + 3 * math.sin(tick / 5 + d[1]), 1)))
        t = c.t - (end - minutes * 60)
        if not wrote and t > 120:                              # a technician overrides a fan and a damper
            write(DEVICES[0], oid(BO, 1), app_enum(1), 8)
            write(DEVICES[1], oid(AO, 3), app_real(40.0), 8)
            wrote = True
        if wrote and not released and t > 300:                 # ...and releases only the damper
            write(DEVICES[1], oid(AO, 3), b'\x00', 8)
            released = True
        if not alarm and t > 200:
            d = DEVICES[2]
            c.bacnet(d[0], FRONT, bytes([0x10, 0x03]) + ctx(0, uint(1)) + ctx(1, oid(DEV, d[1])) + ctx(2, oid(AI, 1))
                     + opening(3) + ctx(1, uint(1)) + closing(3) + ctx(4, uint(1)) + ctx(5, uint(100)) + ctx(6, uint(5))
                     + ctx(8, uint(0)) + ctx(9, b'\x01') + ctx(10, uint(0)) + ctx(11, uint(3)))
            alarm = True
        if t > 30 and tick % 40 == 0:                           # a Who-Is from the other subnet arrives through both BBMDs
            c.forwarded(BBMD_A, LAPTOP, b'\x10\x08')
            c.step(0.003)
            c.forwarded(BBMD_B, LAPTOP, b'\x10\x08')
        if not lapse and t > 200:                              # the laptop renews its registration far too late
            c.register(LAPTOP, BBMD_A, 60)
            lapse = True
    return b''.join(c.out)


def write_sample(path):
    with open(path, 'wb') as f:
        f.write(build())
    return path

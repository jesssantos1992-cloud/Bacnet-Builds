"""
bi_mstp.py - BACnet MS/TP master node over a USB RS-485 adapter (ASHRAE 135 clause 9).

Lets Discover talk to an MS/TP trunk directly, without a router: the PC joins the token ring with
a free MAC address, sends its requests only while it holds the token, and passes the token on.

    link = MstpLink('COM3', 38400, mac=99, on_npdu=..., on_status=...)
    link.start()                          # opens the port, listens, then joins when polled
    link.send(dst_mac, npdu, expecting_reply=True)
    link.stop()

`listen()` watches the trunk for a few seconds without sending and reports which MAC addresses are
in use and which free ones the masters are polling (a safe address to join with).
"""
from __future__ import annotations

import collections
import threading
import time

import bi_core as C

TOKEN, PFM, REPLY_PFM, TEST_REQ, TEST_RESP, DER, DNER, POSTPONED = range(8)
T_NO_TOKEN = 0.500        # silence before a master may create a token
T_SLOT = 0.010
T_USAGE = 0.060           # wait for the next station to start using a token / answer a poll (spec 20-100 ms)
T_REPLY = 0.300           # wait for the answer to a Data-Expecting-Reply (spec >= 255 ms)
N_POLL = 50               # poll for new masters every 50 token passes
N_MAX_INFO = 4            # frames we may send per token


def frame(ty, dst, src, data=b''):
    """One MS/TP frame: preamble, header + header CRC, data + data CRC (low byte first)."""
    h = bytes([ty, dst, src, len(data) >> 8, len(data) & 255])
    out = b'\x55\xff' + h + bytes([C.c8(h)])
    if data:
        crc = C.c16(data)
        out += bytes(data) + bytes([crc & 255, crc >> 8])
    return out


class Parser:
    """Cuts valid frames (ty, dst, src, data) out of a byte stream."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, b):
        self.buf += b
        out = []
        buf = self.buf
        while True:
            i = buf.find(b'\x55\xff')
            if i < 0:
                del buf[:max(0, len(buf) - 1)]
                return out
            del buf[:i]
            if len(buf) < 8:
                return out
            if C.c8(buf[2:7]) != buf[7]:
                del buf[:2]
                continue
            ln = buf[5] << 8 | buf[6]
            if ln > 1500:
                del buf[:2]
                continue
            need = 8 + (ln + 2 if ln else 0)
            if len(buf) < need:
                return out
            data = bytes(buf[8:8 + ln])
            if ln and C.c16(data) != (buf[8 + ln] | buf[9 + ln] << 8):
                del buf[:need]                 # damaged data: drop the frame
                continue
            out.append((buf[2], buf[3], buf[4], data))
            del buf[:need]


def open_port(port, baud):
    import serial
    return serial.Serial(port, int(baud), timeout=0.001, write_timeout=1)


def listen(port, baud, secs=4.0, opener=None):
    """Watch the trunk without transmitting. Returns which addresses send, which are masters
    and which free addresses the masters poll (good candidates for our own MAC)."""
    sp = (opener or open_port)(port, baud)
    p = Parser()
    srcs, masters, polled, n, nb = set(), set(), set(), 0, 0
    try:
        end = time.time() + secs
        while time.time() < end:
            b = sp.read(sp.in_waiting or 1)
            nb += len(b)
            for ty, dst, src, _d in p.feed(b):
                n += 1
                srcs.add(src)
                if ty in (TOKEN, PFM):
                    masters.add(src)
                if ty == REPLY_PFM:
                    masters.add(src)
                if ty == PFM and dst != 255:
                    polled.add(dst)
    finally:
        sp.close()
    free_polled = sorted(m for m in polled if m not in srcs and m <= 127)
    return {'frames': n, 'bytes': nb, 'srcs': sorted(srcs), 'masters': sorted(masters), 'polled': sorted(polled),
            'free_polled': free_polled}


def suggest_mac(info):
    """A MAC for the PC: a free address the masters already poll; on a silent trunk, any address."""
    if info['free_polled']:
        return info['free_polled'][-1], 'a free address the masters on this trunk already poll'
    if not info['frames'] and info.get('bytes'):
        return None, ('data is arriving but none of it is valid MS/TP – the baud rate is probably wrong '
                      '(press Detect), or A and B are swapped')
    if not info['frames']:
        return 1, 'the trunk is silent, so any address works'
    used = set(info['srcs'])
    hi = max(info['masters'] or [0])
    for m in range(hi + 1, 128):
        if m not in used:
            return m, ('no free address is being polled – the masters’ Max Master is probably set to '
                       f'{hi}; raise it to at least {m} on the master below, or the PC will never be invited in')
    return None, 'every master address is in use'


class MstpLink:
    """An MS/TP master station. All bus work happens on one thread; send() just queues."""

    def __init__(self, port, baud, mac, on_npdu=None, on_status=None, max_master=127, opener=None,
                 allow_create=False):
        self.port, self.baud, self.ts = port, int(baud), int(mac)
        self.allow_create = allow_create   # only on a trunk seen to be silent (never on a wrong baud rate)
        self.max_master = max_master
        self.on_npdu = on_npdu or (lambda src, npdu, bc: None)
        self.on_status = on_status or (lambda: None)
        self.opener = opener
        self.q = collections.deque()
        self.on = False
        self.sp = None
        self.p = Parser()
        self.last_rx = time.perf_counter()
        self.tok = False
        self.ns = None                 # next station (master) to pass the token to
        self.ps = None                 # next address to poll for a new master
        self.masters = set()
        self.token_count = 0
        self.joined = False
        self.state = 'starting'
        self.error = ''
        self.lap = 0.0                 # seconds between our tokens
        self._last_tok = 0.0
        self._sent = collections.deque(maxlen=16)
        self.frames_rx = 0
        self.on_frame = None           # called with every raw frame sent or received (shown in the Live capture tab)

    # ------------------------------------------------------------------ public --
    def start(self):
        self.sp = (self.opener or open_port)(self.port, self.baud)     # raises if the port cannot be opened
        self.on = True
        self.state = 'listening'
        threading.Thread(target=self._run, daemon=True, name='mstp-link').start()

    def stop(self):
        self.on = False
        self.state = 'stopped'

    def send(self, dst, npdu, expecting_reply):
        self.q.append((int(dst), bytes(npdu), bool(expecting_reply) and dst != 255))

    def status_text(self):
        if self.error:
            return self.error
        if self.state == 'listening':
            return (f'Waiting to be invited into the token ring as MAC {self.ts}… (masters poll free addresses one at a '
                    'time, so this can take up to a minute)')
        if self.joined:
            ms = sorted(self.masters | {self.ts})
            lap = f' · token every {C.fmt_ms(self.lap * 1000)}' if self.lap else ''
            return (f'Joined the trunk as MAC {self.ts}{lap} · masters: {", ".join(map(str, ms[:20]))}'
                    + (' …' if len(ms) > 20 else ''))
        return self.state

    # ---------------------------------------------------------------- the bus --
    def _write(self, ty, dst, data=b''):
        f = frame(ty, dst, self.ts, data)
        self._sent.append(f)
        self.sp.write(f)
        if self.on_frame:
            self.on_frame(f)
        self.last_rx = time.perf_counter() + len(f) * 10 / self.baud      # the line is busy while we send

    def _read(self, wait=0.0):
        """Frames received within `wait` seconds (at least one read)."""
        end = time.perf_counter() + wait
        out = []
        while True:
            try:
                b = self.sp.read(self.sp.in_waiting or 1)
            except Exception as e:                        # adapter unplugged
                self._fail(f'Lost the connection to {self.port}: {e}')
                return []
            if b:
                self.last_rx = time.perf_counter()
                for f in self.p.feed(b):
                    if f[2] == self.ts:
                        if frame(f[0], f[1], f[2], f[3]) in self._sent:
                            continue                       # our own transmission echoed back
                        self._fail(f'Another device on the trunk is using MAC {self.ts}. Left the trunk – pick a free address.')
                        return []
                    self.frames_rx += 1
                    if self.on_frame:
                        self.on_frame(frame(*f))
                    out.append(f)
            if out or time.perf_counter() >= end:
                return out

    def _fail(self, msg):
        self.error = msg
        self.on = False
        self.state = 'stopped'
        self.on_status()

    def _run(self):
        try:
            while self.on:
                if self.tok:
                    self._use_token()
                    continue
                for f in self._read(0.002):
                    self._idle(f)
                    if self.tok or not self.on:
                        break
                if (not self.tok and self.on and (self.allow_create or self.joined)
                        and time.perf_counter() - self.last_rx > T_NO_TOKEN + T_SLOT * self.ts):
                    self.tok = True                         # silent trunk: create the token (we are the only master)
                    self._got_token()
        finally:
            try:
                self.sp.close()
            except Exception:
                pass
            self.on_status()

    def _idle(self, f):
        ty, dst, src, data = f
        if ty in (TOKEN, PFM, REPLY_PFM):
            self.masters.add(src)
        if ty == TOKEN and dst == self.ts:
            self.tok = True
            self._got_token()
        elif ty == PFM and dst == self.ts:
            self._write(REPLY_PFM, src)                     # "I am here": the poller will pass us the token
        elif ty == TEST_REQ and dst == self.ts:
            self._write(TEST_RESP, src, data)
        elif ty in (DER, DNER) and dst in (self.ts, 255):
            if ty == DER and dst == self.ts:
                self._write(POSTPONED, src)                 # we do not serve requests; free the sender
            if data:
                self.on_npdu(src, data, dst == 255)
        elif ty == POSTPONED:
            pass

    def _got_token(self):
        now = time.perf_counter()
        if self._last_tok:
            self.lap = now - self._last_tok
        self._last_tok = now
        if not self.joined:
            self.joined = True
            self.state = 'joined'
            self.on_status()
        if self.ns is None or self.ns == self.ts:
            others = sorted(m for m in self.masters if m != self.ts)
            self.ns = next((m for m in others if m > self.ts), others[0] if others else None)
        if self.ps is None:
            self.ps = (self.ts + 1) % (self.max_master + 1)

    def _use_token(self):
        self.token_count += 1
        for _ in range(N_MAX_INFO):
            if not self.q or not self.on:
                break
            dst, npdu, der = self.q.popleft()
            self._write(DER if der else DNER, dst, npdu)
            if der and not self._wait_reply(dst):
                return                                      # someone else took over the bus
        if not self.on:
            return
        sole = self.ns is None
        if sole or self.token_count % N_POLL == 0:
            self._poll_gap(sole)
        self._pass_token()

    def _wait_reply(self, dst):
        end = time.perf_counter() + T_REPLY
        while time.perf_counter() < end and self.on:
            for ty, fdst, src, data in self._read(0.005):
                if ty == TOKEN:                             # somebody else holds a token: we lost ours
                    self.tok = False
                    return False
                if fdst == self.ts and src == dst and ty in (DNER, POSTPONED, DER):
                    if data:
                        self.on_npdu(src, data, False)
                    if ty == DER:
                        self._write(POSTPONED, src)
                    return True
                if ty in (DNER, DER) and fdst == 255 and data:
                    self.on_npdu(src, data, True)
        return True

    def _poll_gap(self, sole):
        """Poll one address between us and our next station, so a new master can join."""
        span = self.max_master + 1
        nxt = self.ns if self.ns is not None else self.ts
        a = self.ps if self.ps is not None else (self.ts + 1) % span
        between = lambda x: (x - self.ts) % span < (nxt - self.ts) % span or sole  # noqa: E731
        if a == self.ts or not between(a):
            a = (self.ts + 1) % span
        if a == self.ts or (not sole and not between(a)):
            return
        self.ps = (a + 1) % span
        if self._poll(a):
            self.ns = a

    def _poll(self, a):
        self._write(PFM, a)
        end = time.perf_counter() + T_USAGE
        while time.perf_counter() < end and self.on:
            for ty, dst, src, _d in self._read(0.004):
                if ty == REPLY_PFM and dst == self.ts and src == a:
                    self.masters.add(a)
                    return True
        return False

    def _pass_token(self):
        if self.ns is None:                                 # still alone: keep the token, but do not hog the bus
            time.sleep(0.005)
            return
        for _attempt in range(2):
            self._write(TOKEN, self.ns)
            end = time.perf_counter() + T_USAGE
            while time.perf_counter() < end and self.on:
                fs = self._read(0.004)
                if fs:
                    self.tok = False
                    for f in fs:
                        self._idle(f)
                    return
        # the next station did not take the token: find a new one
        dead = self.ns
        self.masters.discard(dead)
        span = self.max_master + 1
        a = (dead + 1) % span
        while a != self.ts and self.on:
            if self._poll(a):
                self.ns = a
                self._write(TOKEN, a)
                self.tok = False
                return
            a = (a + 1) % span
        self.ns = None                                      # nobody else left: we are the only master

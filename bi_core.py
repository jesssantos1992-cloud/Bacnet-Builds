"""
bi_core.py - BACnet Inspector engine: capture-file parsing, packet decoding, display filters,
search, and the analysis behind every view (findings, devices, traffic, MS/TP, bus speed,
available IDs / networks, compare, report).

Pure Python, no UI. This is a port of the decoder that used to live in bacnet_inspector.html;
names follow the original so the two can be compared line by line.
"""
from __future__ import annotations

import decimal
import math
import re
import struct
import time

# ------------------------------------------------------------------ tables --
NM = {0: 'Who-Is-Router-To-Network', 1: 'I-Am-Router-To-Network', 3: 'Reject-Message-To-Network', 4: 'Router-Busy',
      5: 'Router-Available', 18: 'What-Is-Network-Number', 19: 'Network-Number-Is'}
MT = {0: 'Token', 1: 'Poll-For-Master', 2: 'Reply-To-Poll-For-Master', 3: 'Test-Request', 4: 'Test-Response',
      5: 'Data-Expecting-Reply', 6: 'Data-Not-Expecting-Reply', 7: 'Reply-Postponed'}
AT = ['Confirmed-Request', 'Unconfirmed-Request', 'Simple-ACK', 'Complex-ACK', 'Segment-ACK', 'Error', 'Reject', 'Abort']
OT = ['analog-input', 'analog-output', 'analog-value', 'binary-input', 'binary-output', 'binary-value', 'calendar',
      'command', 'device', 'event-enrollment', 'file', 'group', 'loop', 'multi-state-input', 'multi-state-output',
      'notification-class', 'program', 'schedule', 'averaging', 'multi-state-value', 'trend-log', 'life-safety-point',
      'life-safety-zone', 'accumulator', 'pulse-converter']
PR = {8: 'all properties', 28: 'description', 36: 'event-state', 62: 'max-APDU-length', 70: 'model-name',
      75: 'object-identifier', 76: 'object-list', 77: 'object-name', 79: 'object-type', 81: 'out-of-service',
      85: 'present-value', 87: 'priority-array', 98: 'protocol-version', 107: 'segmentation-supported',
      111: 'status-flags', 112: 'system-status', 117: 'units', 120: 'vendor-identifier', 121: 'vendor-name',
      139: 'protocol-revision'}
CSV = {0: ['Acknowledge Alarm', 'acknowledging an alarm'],
       1: ['COV Notification', 'telling a subscriber that a value changed (needs an acknowledgement)'],
       2: ['Event Notification', 'reporting an alarm or event (needs an acknowledgement)'],
       3: ['Get Alarm Summary', 'asking for the active alarms'], 4: ['Get Enrollment Summary', 'asking for event enrollments'],
       5: ['Subscribe COV', 'asking to be told whenever a value changes'], 6: ['Read File', 'reading a file from a device'],
       7: ['Write File', 'writing a file to a device'], 8: ['Add List Element', 'adding to a list'],
       9: ['Remove List Element', 'removing from a list'], 10: ['Create Object', 'creating a new object'],
       11: ['Delete Object', 'deleting an object'], 12: ['Read Property', 'asking a device for one value'],
       13: ['Read Property Conditional', 'reading values that match a condition'],
       14: ['Read Property Multiple', 'asking a device for several values at once'],
       15: ['Write Property', 'changing one value in a device'],
       16: ['Write Property Multiple', 'changing several values in a device'],
       17: ['Device Communication Control', 'turning a device’s communication on or off'],
       18: ['Private Transfer', 'a manufacturer-specific message'], 19: ['Text Message', 'sending a text message'],
       20: ['Reinitialize Device', 'restarting or resetting a device'], 26: ['Read Range', 'reading part of a log or list'],
       27: ['Life Safety Operation', 'a life-safety command'],
       28: ['Subscribe COV Property', 'asking to be told when one property changes'],
       29: ['Get Event Information', 'asking for the active events'],
       30: ['Subscribe COV Property Multiple', 'subscribing to several properties'],
       31: ['COV Notification Multiple', 'telling a subscriber that several values changed']}
UNC = {0: ['I-Am', 'a device announcing its device ID and address'],
       1: ['I-Have', 'a device announcing it has a named object'], 2: ['COV Notification', 'telling subscribers a value changed'],
       3: ['Event Notification', 'reporting an alarm or event'], 4: ['Private Transfer', 'a manufacturer-specific message'],
       5: ['Text Message', 'sending a text message'], 6: ['Time Sync', 'setting the clock on devices'],
       7: ['Who-Has', 'asking which device has a named object'], 8: ['Who-Is', 'asking which devices are out there'],
       9: ['UTC Time Sync', 'setting the UTC clock on devices'], 10: ['Write Group', 'writing values to a group of devices'],
       11: ['COV Notification Multiple', 'telling subscribers that several values changed']}
RJ = {0: 'other error', 1: 'the router has no route to that network', 2: 'the router is busy', 3: 'unknown message type',
      4: 'message too long', 5: 'security error', 6: 'addressing error'}
EC = {0: 'device', 1: 'object', 2: 'property', 3: 'resources', 4: 'security', 5: 'services', 6: 'vt', 7: 'communication'}
# BACnet error codes (ASHRAE 135), worded so a technician can read them
ECD = {0: 'other', 1: 'authentication failed', 2: 'configuration in progress', 3: 'device busy',
       4: 'dynamic creation not supported', 5: 'file access denied', 6: 'incompatible security levels',
       7: 'inconsistent parameters', 8: 'inconsistent selection criterion', 9: 'invalid data type',
       10: 'invalid file access method', 11: 'invalid file start position', 12: 'invalid operator name',
       13: 'invalid parameter data type', 14: 'invalid time stamp', 15: 'key generation error',
       16: 'missing required parameter', 17: 'no objects of specified type', 18: 'no space for object',
       19: 'no space to add list element', 20: 'no space to write property', 21: 'no VT sessions available',
       22: 'property is not a list', 23: 'object deletion not permitted', 24: 'object identifier already exists',
       25: 'operational problem', 26: 'password failure', 27: 'read access denied', 28: 'security not supported',
       29: 'service request denied', 30: 'timeout', 31: 'unknown object', 32: 'unknown property', 34: 'unknown VT class',
       35: 'unknown VT session', 36: 'unsupported object type', 37: 'value out of range', 38: 'VT session already closed',
       39: 'VT session termination failure', 40: 'write access denied', 41: 'character set not supported',
       42: 'invalid array index', 43: 'COV subscription failed', 44: 'not a COV property',
       45: 'optional functionality not supported', 46: 'invalid configuration data', 47: 'data type not supported',
       48: 'duplicate name', 49: 'duplicate object ID', 50: 'property is not an array'}
EC_WORD = {0: 'device', 1: 'object', 2: 'property', 3: 'resource', 4: 'security', 5: 'service', 6: 'terminal session',
           7: 'communication'}
RR = {0: 'other', 1: 'buffer overflow', 2: 'inconsistent parameters', 3: 'invalid parameter type', 4: 'invalid tag',
      5: 'missing required parameter', 6: 'parameter out of range', 7: 'too many arguments', 8: 'undefined enumeration',
      9: 'unrecognized service'}


def error_text(c1, c2):
    """Plain-English text for a BACnet error (class c1, code c2) - no raw numbers."""
    cls = EC_WORD.get(c1, '')
    if c2 in ECD and c2 != 0:
        return ECD[c2]
    if cls:
        return f'a {cls} problem (no detail given)' if c2 == 0 else f'a {cls} problem the device did not explain'
    return 'a problem the device did not explain'


def error_codes(d, k, L):
    """Error class and code from an Error PDU starting at k. Some services wrap them in extra
    context tags (e.g. Private Transfer, Write Property Multiple), so take the first two enumerated values."""
    found = []
    n = 0
    while k < L and len(found) < 2 and n < 12:
        a = tg(d, k)
        n += 1
        if a.cx and a.o:
            k = a.v
            continue
        if not a.cx and a.n == 9:
            found.append(num(d[a.v:a.v + a.len]))
        k = a.v + (0 if (not a.cx and a.n == 1) else a.len)
    return (found + [None, None])[:2]
AR = {0: 'other', 1: 'buffer overflow', 2: 'invalid state', 3: 'preempted by higher-priority task',
      4: 'segmentation not supported', 5: 'security error', 6: 'insufficient security', 7: 'window size out of range',
      8: 'application exceeded reply time', 9: 'out of resources', 10: 'timeout', 11: 'message too long'}
BX = {0: 'The reply to a BBMD or foreign-device request (success or refusal).',
      4: 'A BBMD forwarding a broadcast it received from another subnet.',
      5: 'A device on another subnet asking this BBMD to include it in broadcasts.',
      9: 'A foreign device asking the BBMD to broadcast its message on the local network.',
      10: 'A message sent directly to one device.', 11: 'A message sent to every device on this subnet.'}
MX = {0: 'MS/TP devices take turns: only the device holding the token may send. This frame hands the token to the next device.',
      1: 'A master checks whether another master exists at that address, so it can be added to the token ring.',
      2: 'A device replies to a poll to say it is present and ready to receive the token.',
      3: 'A link test request.', 4: 'A link test response.',
      7: 'A device asks the sender to wait because it needs more time to prepare its reply.'}
B6 = {0: 'BVLC-Result', 1: 'Original-Unicast-NPDU', 2: 'Original-Broadcast-NPDU', 3: 'Address-Resolution',
      4: 'Forwarded-Address-Resolution', 5: 'Address-Resolution-ACK', 6: 'Virtual-Address-Resolution',
      7: 'Virtual-Address-Resolution-ACK', 8: 'Forwarded-NPDU', 9: 'Register-Foreign-Device',
      10: 'Delete-Foreign-Device-Table-Entry', 11: 'Secure-BVLL', 12: 'Distribute-Broadcast-To-Network'}
BX6 = {0: 'The reply to a BBMD or foreign-device request.',
       1: 'A message sent directly to one device (devices are identified by a 3-byte virtual address, VMAC).',
       2: 'A message sent to every device on this IPv6 network.',
       3: 'A device asking which IPv6 address belongs to a virtual address.', 5: 'The answer to an address lookup.',
       8: 'A BBMD forwarding a broadcast it received from another network.',
       9: 'A device on another network asking this BBMD to include it in broadcasts.',
       12: 'A device asking the BBMD to broadcast its message.'}
RIS = ['cold start (full restart)', 'warm start (restart)', 'start backup', 'end backup', 'start restore', 'end restore',
       'abort restore', 'activate changes']
PN = {12: 'sw', 28: 'desc', 44: 'fw', 58: 'loc', 70: 'model', 77: 'name', 121: 'vendor', 372: 'serial'}

from bi_vendors import VN  # noqa: E402  (BACnet vendor ID -> manufacturer)
__all__ = ['VN']          # re-exported: other modules use C.VN (keeps the import from looking unused)

# ------------------------------------------------------- JS-compatible text --
_NUMRE = re.compile(r'^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$')


def jsnum(x) -> str:
    """Format a number the way JavaScript's String(number) does."""
    if isinstance(x, bool):
        return 'true' if x else 'false'
    if isinstance(x, int):
        return str(x)
    if x != x:
        return 'NaN'
    if x in (math.inf, -math.inf):
        return 'Infinity' if x > 0 else '-Infinity'
    if x == 0:
        return '0'
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    s = repr(x)
    ax = abs(x)
    if 1e-6 <= ax < 1e21:
        if 'e' in s or 'E' in s:
            s = format(decimal.Decimal(s), 'f')
        return s
    m, e = s.split('e') if 'e' in s else (s, '0')
    e = int(e)
    return f"{m}e{'+' if e >= 0 else '-'}{abs(e)}"


def jstonum(s) -> float:
    """JavaScript's unary + on a string: Number(s)."""
    if isinstance(s, (int, float)):
        return s
    s = str(s).strip()
    if s == '':
        return 0
    if _NUMRE.match(s):
        return float(s)
    low = s.lower()
    try:
        if low.startswith('0x'):
            return int(s[2:], 16)
        if low.startswith('0o'):
            return int(s[2:], 8)
        if low.startswith('0b'):
            return int(s[2:], 2)
    except ValueError:
        return math.nan
    if s in ('Infinity', '+Infinity'):
        return math.inf
    if s == '-Infinity':
        return -math.inf
    return math.nan


def jsstr(x) -> str:
    if x is None:
        return 'null'
    if isinstance(x, (int, float)) and not isinstance(x, bool):
        return jsnum(x)
    return str(x)


def tofixed(x, n) -> str:
    """Number.prototype.toFixed (round half away from zero on the decimal value)."""
    if x != x:
        return 'NaN'
    d = decimal.Decimal(float(x)) if not isinstance(x, int) else decimal.Decimal(x)   # exact binary value, like JS
    q = decimal.Decimal(1).scaleb(-n)
    r = d.quantize(q, rounding=decimal.ROUND_HALF_UP)
    s = format(r, 'f')
    if s.startswith('-') and float(r) == 0:
        s = s[1:]
    return s


def locale_int(n) -> str:
    """toLocaleString() for whole numbers (en-US grouping)."""
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


_DIGITS = re.compile(r'(\d+)')


def natural_key(s):
    """Sort key that orders 'MAC 9' before 'MAC 10' (like localeCompare with numeric: true)."""
    return tuple((0, int(p), '') if i & 1 else (1, 0, p)
                 for i, p in enumerate(_DIGITS.split(str(s).lower())) if p)


def jsround(x) -> int:
    """Math.round: halves go up."""
    return int(math.floor(x + 0.5))


# ------------------------------------------------------------------- CRCs --
T8, T16 = [], []
for _i in range(256):
    _a = _b = _i
    for _k in range(8):
        _a = (_a >> 1) ^ 129 if _a & 1 else _a >> 1
        _b = (_b >> 1) ^ 33800 if _b & 1 else _b >> 1
    T8.append(_a)
    T16.append(_b)


def c8(a) -> int:
    c = 255
    for x in a:
        c = T8[c ^ x]
    return ~c & 255


def c16(a) -> int:
    c = 65535
    for x in a:
        c = (c >> 8) ^ T16[(c ^ x) & 255]
    return ~c & 65535


def num(b) -> int:
    return int.from_bytes(b, 'big') if b else 0


def hm(d, o) -> str:
    return ':'.join(f'{x:02x}' for x in d[o:o + 6])


def mh(d, k, n) -> str:
    return ':'.join(f'{x:02x}' for x in d[k:k + n])


# ------------------------------------------------------------- tag parsing --
class Tag:
    __slots__ = ('n', 'cx', 'o', 'len', 'v')

    def __init__(self, n, cx, o, ln, v):
        self.n, self.cx, self.o, self.len, self.v = n, cx, o, ln, v


def tg(d, k) -> Tag:
    t = d[k]
    n = t >> 4
    j = k + 1
    if n == 15:
        n = d[j]
        j += 1
    cx = bool(t & 8)
    l = t & 7
    if cx and l > 5:
        return Tag(n, cx, l - 5, 0, j)
    if not cx and n == 1:
        return Tag(n, cx, 0, 0, j)
    ln = l
    if l == 5:
        ln = d[j]
        j += 1
        if ln == 254:
            ln = d[j] << 8 | d[j + 1]
            j += 2
        elif ln == 255:
            ln = num(d[j:j + 4])
            j += 4
    return Tag(n, cx, 0, ln, j)


def skip(d, k, L) -> int:
    dp = 1
    while k < L and dp:
        a = tg(d, k)
        if a.o == 1:
            dp += 1
        elif a.o == 2:
            dp -= 1
        k = a.v + (0 if a.o else a.len)
    return k


def cs(d, a) -> str:
    enc = d[a.v]
    codec = 'utf-16-be' if enc == 4 else 'latin-1' if enc == 5 else 'utf-8'
    return bytes(d[a.v + 1:a.v + a.len]).decode(codec, errors='replace')


def objname(o) -> str:
    ty = o // 4194304
    return f"{OT[ty] if ty < len(OT) else 'object type ' + str(ty)} {o % 4194304}"


def tyname(ty) -> str:
    return OT[ty] if 0 <= ty < len(OT) else 'object type ' + str(ty)


def prname(p) -> str:
    return PR.get(p) or 'property ' + str(p)


def grab(d, L, sv, k, r):
    def put(o, p, a):
        if o // 4194304 == 8 and p in PN and not a.cx and a.n == 7:
            if r.names is None:
                r.names = []
            r.names.append({'inst': o % 4194304, 'k': PN[p], 'v': cs(d, a)})
    if sv == 12:
        if d[k] != 0x0C:
            return
        o = num(d[k + 1:k + 5])
        k += 5
        a = tg(d, k)
        if a.n != 1 or not a.cx:
            return
        p = num(d[a.v:a.v + a.len])
        k = a.v + a.len
        a = tg(d, k)
        if a.n == 2 and a.cx and not a.o:
            k = a.v + a.len
            a = tg(d, k)
        if a.n == 3 and a.o == 1:
            put(o, p, tg(d, a.v))
    elif sv == 14:
        while k < L and d[k] == 0x0C:
            o = num(d[k + 1:k + 5])
            k += 5
            if d[k] != 0x1E:
                break
            k += 1
            while k < L and d[k] != 0x1F:
                a = tg(d, k)
                if a.n != 2 or not a.cx:
                    break
                p = num(d[a.v:a.v + a.len])
                k = a.v + a.len
                b = tg(d, k)
                if b.n == 3 and b.cx and not b.o:
                    k = b.v + b.len
                    b = tg(d, k)
                if b.n == 4 and b.o == 1:
                    put(o, p, tg(d, b.v))
                    k = skip(d, b.v, L)
                elif b.n == 5 and b.o == 1:
                    k = skip(d, b.v, L)
                else:
                    break
            k += 1


def pv(d, a, t0) -> str:
    b = d[a.v:a.v + a.len]
    n = a.n
    if n == 0:
        return 'null'
    if n == 1:
        return 'true' if t0 & 1 else 'false'
    if n == 2:
        return str(num(b))
    if n == 3:
        x = num(b)
        if len(b) and b[0] & 128:
            x -= 256 ** len(b)
        return str(x)
    if n == 4:
        if len(b) != 4:
            return '?'
        f = struct.unpack('>f', bytes(b))[0]
        return jsnum(float('%.7g' % f)) if f == f and abs(f) != math.inf else jsnum(f)
    if n == 5:
        if len(b) != 8:
            return '?'
        f = struct.unpack('>d', bytes(b))[0]
        return jsnum(float('%.10g' % f)) if f == f and abs(f) != math.inf else jsnum(f)
    if n == 6:
        return '0x' + ''.join(f'{x:02x}' for x in b)
    if n == 7:
        return '"' + cs(d, a) + '"'
    if n == 8:
        u = b[0] if len(b) else 0
        bits = []
        for i in range(1, len(b)):
            for k in range(7, -1, -1):
                bits.append(str(b[i] >> k & 1))
        if u:
            bits = bits[:max(0, len(bits) - u)]
        return ''.join(bits)
    if n == 9:
        return str(num(b))
    if n == 10:
        return f'{b[0] + 1900}-{b[1]}-{b[2]}' if len(b) == 4 else 'date'
    if n == 11:
        return f'{b[0]}:{b[1]:02d}:{b[2]:02d}' if len(b) == 4 else 'time'
    if n == 12:
        return objname(num(b))
    return '?'


def vals(d, k, lim, pp, ot):
    out = []
    while k < lim and len(out) < 12:
        t = d[k]
        a = tg(d, k)
        if a.cx and a.o == 2:
            return ', '.join(out), a.v
        if a.cx and a.o == 1:
            s, k = vals(d, a.v, lim, pp, ot)
            out.append('{' + s + '}')
            continue
        if a.cx:
            out.append(str(num(d[a.v:a.v + a.len])))
            k = a.v + a.len
            continue
        s = pv(d, a, t)
        if a.n == 9 and pp == 85 and 3 <= ot <= 5:
            s = 'active' if s == '1' else 'inactive' if s == '0' else s
        out.append(s)
        k = a.v + a.len
    return ', '.join(out), k


def rv(d, L, sv, k) -> str:
    if sv == 12:
        if d[k] != 0x0C:
            return ''
        o = num(d[k + 1:k + 5])
        ot = o // 4194304
        k += 5
        a = tg(d, k)
        if a.n != 1 or not a.cx:
            return ''
        p = num(d[a.v:a.v + a.len])
        k = a.v + a.len
        a = tg(d, k)
        if a.n == 2 and a.cx and not a.o:
            k = a.v + a.len
            a = tg(d, k)
        if not (a.n == 3 and a.o == 1):
            return ''
        s, _ = vals(d, a.v, L, p, ot)
        return f'{tyname(ot)} {o % 4194304}, {prname(p)} = {s}'
    if sv == 14:
        out = []
        while k < L and d[k] == 0x0C and len(out) < 4:
            o = num(d[k + 1:k + 5])
            ot = o // 4194304
            k += 5
            if d[k] != 0x1E:
                break
            k += 1
            ps = []
            while k < L and d[k] != 0x1F:
                a = tg(d, k)
                if a.n != 2 or not a.cx:
                    break
                p = num(d[a.v:a.v + a.len])
                k = a.v + a.len
                b = tg(d, k)
                if b.n == 3 and b.cx and not b.o:
                    k = b.v + b.len
                    b = tg(d, k)
                if b.n == 4 and b.o == 1:
                    s, k = vals(d, b.v, L, p, ot)
                    ps.append(f'{prname(p)} = {s}')
                elif b.n == 5 and b.o == 1:
                    ps.append(prname(p) + ' = (error)')
                    k = skip(d, b.v, L)
                else:
                    break
            k += 1
            out.append(f'{tyname(ot)} {o % 4194304}: ' + '; '.join(ps))
        return ' | '.join(out)
    return ''


def wdec(d, L, sv, k, r, tree):
    nmv = {15: 'Write Property', 16: 'Write Property Multiple', 17: 'Device Communication Control',
           20: 'Reinitialize Device', 10: 'Create Object', 11: 'Delete Object', 7: 'Write File',
           8: 'Add List Element', 9: 'Remove List Element'}
    if sv not in nmv:
        return
    W = {'svc': nmv[sv], 'obj': '', 'prop': '', 'val': '', 'pri': None, 'sev': 0}
    if sv == 15:
        if d[k] != 0x0C:
            return
        o = num(d[k + 1:k + 5])
        ot = o // 4194304
        k += 5
        a = tg(d, k)
        if a.n != 1 or not a.cx:
            return
        p = num(d[a.v:a.v + a.len])
        k = a.v + a.len
        a = tg(d, k)
        if a.n == 2 and a.cx and not a.o:
            k = a.v + a.len
            a = tg(d, k)
        if not (a.n == 3 and a.o == 1):
            return
        s, k = vals(d, a.v, L, p, ot)
        a = tg(d, k)
        if a.n == 4 and a.cx and not a.o:
            W['pri'] = num(d[a.v:a.v + a.len])
        W['obj'] = objname(o)
        W['prop'] = prname(p)
        W['val'] = 'null (release the override)' if s == 'null' and W['pri'] is not None else s
    elif sv == 16:
        it = []
        n = 0
        while k < L and d[k] == 0x0C:
            o = num(d[k + 1:k + 5])
            ot = o // 4194304
            k += 5
            if d[k] != 0x1E:
                break
            k += 1
            while k < L and d[k] != 0x1F:
                a = tg(d, k)
                if not (a.n == 0 and a.cx and not a.o):
                    break
                p = num(d[a.v:a.v + a.len])
                k = a.v + a.len
                b = tg(d, k)
                if b.n == 1 and b.cx and not b.o:
                    k = b.v + b.len
                    b = tg(d, k)
                if not (b.n == 2 and b.o == 1):
                    break
                s, k = vals(d, b.v, L, p, ot)
                b = tg(d, k)
                if b.n == 3 and b.cx and not b.o:
                    W['pri'] = num(d[b.v:b.v + b.len])
                    k = b.v + b.len
                n += 1
                if len(it) < 4:
                    it.append(f'{objname(o)} {prname(p)} = {s}')
            k += 1
        W['obj'] = f'{n} values' if n > 1 else (' '.join(it[0].split(' ')[:2]) if it else '')
        W['prop'] = 'several points' if n > 1 else ''
        W['val'] = '; '.join(it) + (' …' if n > 4 else '')
        if not n:
            return
    elif sv == 17:
        a = tg(d, k)
        dur = None
        en = 0
        if a.n == 0 and a.cx and not a.o:
            dur = num(d[a.v:a.v + a.len])
            k = a.v + a.len
            a = tg(d, k)
        if a.n == 1 and a.cx and not a.o:
            en = num(d[a.v:a.v + a.len])
        W['obj'] = 'device'
        W['prop'] = 'communication'
        opts = ['enable communication', 'DISABLE communication', 'disable initiation (device stays silent unless asked)']
        W['val'] = opts[en] if en < len(opts) else 'state ' + str(en)
        if dur:
            W['val'] += f' for {dur} minutes'
        W['sev'] = 2 if en else 0
    elif sv == 20:
        a = tg(d, k)
        n = num(d[a.v:a.v + a.len]) if a.n == 0 and a.cx else -1
        W['obj'] = 'device'
        W['prop'] = 'restart'
        W['val'] = RIS[n] if 0 <= n < len(RIS) else 'state ' + str(n)
        W['sev'] = 2 if n <= 1 else 1
    elif sv == 11:
        if d[k] != 0xC4:
            return
        W['obj'] = objname(num(d[k + 1:k + 5]))
        W['val'] = 'delete this object'
        W['sev'] = 2
    elif sv == 10:
        W['obj'] = '(new object)'
        W['val'] = 'create object'
        W['sev'] = 1
    elif sv == 7:
        if d[k] != 0xC4:
            return
        W['obj'] = objname(num(d[k + 1:k + 5]))
        W['val'] = 'write file data'
    else:
        if d[k] != 0x0C:
            return
        W['obj'] = objname(num(d[k + 1:k + 5]))
        a = tg(d, k + 5)
        if a.n == 1 and a.cx:
            W['prop'] = prname(num(d[a.v:a.v + a.len]))
        W['val'] = 'add to list' if sv == 8 else 'remove from list'
    r.wr = W
    if tree is not None:
        tree.append([1, f"Change request: {W['svc']}{' – ' + W['obj'] if W['obj'] else ''}"
                        f"{', ' + W['prop'] if W['prop'] else ''}{' → ' + W['val'] if W['val'] else ''}"
                        f"{' (priority ' + str(W['pri']) + ')' if W['pri'] is not None else ''}"])


def covdec(d, k, r):
    a = tg(d, k)
    if a.n == 0 and a.cx and not a.o:
        k = a.v + a.len
        a = tg(d, k)
    dev = None
    if a.n == 1 and a.cx and not a.o:
        dev = num(d[a.v:a.v + 4]) % 4194304
        k = a.v + a.len
        a = tg(d, k)
    if a.n == 2 and a.cx and not a.o:
        o = num(d[a.v:a.v + 4])
        r.cov = {'dev': dev, 'obj': objname(o)}


def fa(a) -> str:
    if len(a) == 1:
        return 'MAC ' + str(a[0])
    if len(a) == 6:
        port = a[4] << 8 | a[5]
        if 47808 <= port <= 47823:
            return '.'.join(str(x) for x in a[:4]) + ':' + str(port)
    return ':'.join(f'{x:02x}' for x in a)


# --------------------------------------------------------------- packets --
class Pk:
    """One decoded frame. Unset optional fields read as None (like JavaScript's undefined)."""
    no = t = lt = ifc = 0
    src = dst = info = ''
    proto = 'Other'
    len = 0
    d = b''
    tree = None
    fl = bad = exp = mt = o = v = nak = dk = dn = sn = sa = key = adv = rb = nn = None
    iam = whois = rq = rs = sig = wr = cov = rp = er = val = names = bm = note = wrx = ob = None


_PAD = b'\0' * 64


def npdu(d, L, o, r, tree):
    if d[o] != 1:
        return 'Invalid NPDU'
    c = d[o + 1]
    i = o + 2
    dn = None
    if c & 32:
        dn = d[i] << 8 | d[i + 1]
        dl = d[i + 2]
        if dn != 0xFFFF and dl:
            r.dn = dn
            r.dk = f'network {dn}, {fa(d[i + 3:i + 3 + dl])}'
        i += 3 + dl
    if c & 8:
        r.sn = d[i] << 8 | d[i + 1]
        l = d[i + 2]
        r.sa = fa(d[i + 3:i + 3 + l])
        i += 3 + l
    if c & 32:
        i += 1
    if tree is not None:
        tree += [[0, 'BACnet NPDU'], [1, 'Control: 0x' + format(c, 'x') + (' (network message)' if c & 128 else '')]]
        if dn is not None:
            tree.append([1, 'Destination network: ' + str(dn)])
        if r.sn is not None:
            tree += [[1, f'Source: network {r.sn}, address {r.sa}'], [1, f'Came through gateway (router): {r.o}']]

    def n16(k):
        return d[k] << 8 | d[k + 1]
    if c & 128:
        Ls = []
        k = i + 1
        while k + 1 < L:
            Ls.append(n16(k))
            k += 2
        ns = ('network' + ('s ' if len(Ls) > 1 else ' ') + ', '.join(map(str, Ls))) if Ls else ''
        t = d[i]
        s = NM.get(t) or 'Network message 0x' + format(t, 'x')
        e = 'A message between routers about how to reach networks.'
        if t == 1:
            r.adv = Ls
            s = 'I-Am-Router-To-Network: can reach ' + ns
            e = 'A router announcing which networks it can reach. Other devices use this to learn where to send messages.'
        elif t == 0:
            s = 'Who-Is-Router-To-Network: ' + (f'which router leads to network {n16(i + 1)}?' if L > i + 2 else 'which routers are out there?')
            e = 'A device asking which router can reach a network, because it does not know the way.'
        elif t == 3 and L > i + 3:
            s = f'Reject-Message-To-Network: cannot deliver to network {n16(i + 2)} ({RJ.get(d[i + 1]) or "error " + str(d[i + 1])})'
            e = 'A router telling the sender it could not deliver its message.'
        elif t == 4:
            r.rb = 1
            s = 'Router-Busy: pause sending to ' + (ns or 'all networks behind this router')
            e = 'A router is overloaded and asks other devices to slow down.'
        elif t == 5:
            s = 'Router-Available: sending to ' + (ns or 'all networks') + ' can resume'
            e = 'A router that was busy is ready again.'
        elif t == 18:
            s = 'What-Is-Network-Number: what number does this network have?'
            e = 'A device asking for the number of the network it is on.'
        elif t == 19 and L > i + 2:
            r.nn = n16(i + 1)
            s = 'Network-Number-Is: this network is number ' + str(n16(i + 1)) + (' (configured)' if d[i + 3] == 1 else ' (learned)' if d[i + 3] == 0 else '')
            e = 'A router announcing the number of the network it is connected to.'
        r.exp = e
        if tree is not None:
            tree += [[0, 'BACnet Network Layer message'], [1, s], [1, 'Meaning: ' + e]]
        return s
    t = d[i] >> 4
    seg = d[i] & 8
    s = AT[t] if t < len(AT) else 'APDU'
    e = ''
    if tree is not None:
        tree += [[0, 'BACnet APDU'], [1, 'Type: ' + (AT[t] if t < len(AT) else str(t))]]

    def ob(k):
        if d[k] != 0x0C:
            return ''
        return objname(num(d[k + 1:k + 5]))

    def pr(k):
        if d[k] == 0x19:
            return prname(d[k + 1])
        if d[k] == 0x1A:
            return prname(d[k + 1] << 8 | d[k + 2])
        return ''
    if t == 1:
        v = d[i + 1]
        nm, ds = UNC.get(v) or ['Service ' + str(v), 'an unrecognised service']
        s = nm + ': ' + ds
        e = 'A notification or broadcast: ' + ds + '.'
        if v == 0:
            j = i + 7
            oid = num(d[i + 3:i + 7])
            vs = []
            for _ in range(3):
                l = d[j] & 7
                vs.append(num(d[j + 1:j + 1 + l]))
                j += 1 + l
            if oid // 4194304 == 8:
                r.iam = {'inst': oid % 4194304, 'vendor': vs[2]}
                s = f"I-Am: device {r.iam['inst']} announces itself"
                e = 'A device announcing its device ID, address and manufacturer. Sent at startup and in answer to a Who-Is.'
        elif v == 8:
            r.whois = 1
            lo = hi = None
            if L > i + 2:
                l = d[i + 2] & 7
                lo = num(d[i + 3:i + 3 + l])
                j = i + 3 + l
                if L > j:
                    hi = num(d[j + 1:j + 1 + (d[j] & 7)])
            s = 'Who-Is: ' + ('which devices are out there? (all devices)' if lo is None else f'is any device with ID {lo} to {jsstr(hi)} out there?')
            e = 'A device asking other devices to announce themselves. Every matching device answers with an I-Am.'
        elif v == 2:
            try:
                covdec(d, i + 2, r)
            except IndexError:
                pass
            cv = _cov_text(d, L, i)
            if cv:
                s = f'{nm}: {cv}'
    elif t == 0:
        sv = d[i + 5] if seg else d[i + 3]
        k = i + 6 if seg else i + 4
        inv = d[i + 2]
        nm, ds = CSV.get(sv) or ['Service ' + str(sv), 'an unrecognised service']
        x = ob(k)
        r.ob = x or None
        if x and sv in (12, 15):
            p = pr(k + 5)
            if p:
                x += ', ' + p
        elif x and sv == 14:
            x += ' …'
        r.rq = inv
        r.rs = nm
        r.sig = nm + (': ' + x if x else '')
        try:
            wdec(d, L, sv, k, r, tree)
        except IndexError:
            pass
        if sv == 1:
            try:
                covdec(d, k, r)
            except IndexError:
                pass
            x = _cov_text(d, L, i) or x
        s = f"{nm} request{': ' + x if x else ''} (#{inv})"
        e = f'Request #{inv}: {ds}. The device should answer with a response marked #{inv}.'
    elif 2 <= t <= 7:
        inv = d[i + 1]
        if t != 4:
            r.rp = inv
        if t in (2, 3, 5):
            sv = d[i + 4] if (t == 3 and seg) else d[i + 2]
            nm = (CSV.get(sv) or ['Service ' + str(sv)])[0]
            if t == 2:
                s = f'{nm} acknowledged – done (#{inv})'
                e = f'The device accepted request #{inv} and carried it out.'
            elif t == 3:
                s = f'{nm} response – data returned (#{inv})'
                e = f'The answer to request #{inv}.'
                try:
                    grab(d, L, sv, i + 5 if seg else i + 3, r)
                except IndexError:
                    pass
                try:
                    g = rv(d, L, sv, i + 5 if seg else i + 3)
                    if g:
                        s += ': ' + g
                        r.val = g
                except IndexError:
                    pass
            else:
                c1, c2 = error_codes(d, i + 3, L)
                why = error_text(c1, c2)
                s = f'{nm} failed: {why} (#{inv})'
                e = f'The device could not do request #{inv}: {why}.'
                r.er = {'k': 'error', 'txt': why, 'svc': nm}
        elif t == 4:
            s = f'Segment-ACK (#{inv})'
            e = 'Confirms receipt of one part of a long message that was split up.'
        elif t == 6:
            why = RR.get(d[i + 2]) or 'a reason the device did not explain'
            s = f'Reject (#{inv}): {why}'
            e = f'The device refused request #{inv} as invalid, without trying it.'
            r.er = {'k': 'reject', 'txt': why}
        else:
            why = AR.get(d[i + 2]) or 'a reason the device did not explain'
            s = f'Abort (#{inv}): {why}'
            e = f'The conversation about request #{inv} was cancelled.'
            r.er = {'k': 'abort', 'txt': why}
    r.exp = e
    if tree is not None:
        import bi_svc
        tree += [[1, s], [1, 'Meaning: ' + e]] + bi_svc.apdu_rows(d, L, i)
    return s


def _cov_text(d, L, i):
    """The changed values of a COV notification, for the Info column."""
    try:
        import bi_svc
        return bi_svc.cov_summary(d, L, i)
    except Exception:
        return ''


def v6s(a) -> str:
    g = [a[i] << 8 | a[i + 1] for i in range(0, 16, 2)]
    bs, bl = -1, 0
    i = 0
    while i < 8:
        if g[i]:
            i += 1
            continue
        j = i
        while j < 8 and not g[j]:
            j += 1
        if j - i > bl and j - i > 1:
            bs, bl = i, j - i
        i = j
    x = lambda n: format(n, 'x')  # noqa: E731
    if bs < 0:
        return ':'.join(map(x, g))
    return ':'.join(map(x, g[:bs])) + '::' + ':'.join(map(x, g[bs + bl:]))


_BN = {0: 'BVLC-Result', 4: 'Forwarded-NPDU', 5: 'Register-Foreign-Device', 9: 'Distribute-Broadcast',
       10: 'Original-Unicast', 11: 'Original-Broadcast'}


def dis(t, lt, data, no, ifc=0, want_tree=False) -> Pk:
    """Decode one frame (link type lt) into a Pk. With want_tree, also build the detail lines."""
    r = Pk()
    r.no, r.t, r.lt, r.ifc, r.d, r.len = no, t, lt, ifc or 0, data, len(data)
    L = len(data)
    d = data + _PAD
    tree = [] if want_tree else None
    try:
        if lt == 165:
            i = -1
            for k in range(min(16, L)):
                if d[k] == 0x55 and d[k + 1] == 0xff:
                    i = k
                    break
            if i < 0:
                raise ValueError
            ty, ds, sc = d[i + 2], d[i + 3], d[i + 4]
            ln = d[i + 5] << 8 | d[i + 6]
            r.proto = 'MS/TP'
            r.fl = 8 + (ln + 2 if ln else 0)
            r.src = 'MAC ' + str(sc)
            r.dst = 'Broadcast' if ds == 255 else 'MAC ' + str(ds)
            hok = c8(d[i + 2:i + 7]) == d[i + 7]
            dok = True
            if ln:
                b = data[i + 8:i + 8 + ln]
                dok = len(b) == ln and c16(b) == (d[i + 8 + ln] | d[i + 9 + ln] << 8)
            if tree is not None:
                tree += [[0, f'BACnet MS/TP: {MT.get(ty) or "type " + str(ty)}'],
                         [1, f"Source MAC {sc}, destination {'broadcast' if ds == 255 else ds}, data length {ln}"],
                         [1, 'Header CRC: ' + ('OK' if hok else 'BAD')],
                         [1, 'Data CRC: ' + (('OK' if dok else 'BAD') if ln else 'n/a')]]
            if not hok or not dok:
                r.bad = 1
                r.info = 'Damaged frame (CRC error)'
                r.exp = ('The error check failed, so this frame was damaged on the wire (noise, a wiring problem or a '
                         'baud-rate mismatch) and was thrown away.')
            else:
                r.mt = (ty, sc, ds)
                r.info = (f'Token: MAC {sc} hands the right to talk to MAC {ds}' if ty == 0 else
                          f'Poll-For-Master: MAC {sc} asks if a master is at MAC {ds}' if ty == 1 else
                          f'Reply-To-Poll-For-Master: MAC {sc} answers "I am here"' if ty == 2 else
                          (MT.get(ty) or 'frame type ' + str(ty)))
                r.exp = MX.get(ty, '')
                if r.exp and ty not in (5, 6) and tree is not None:
                    tree.append([1, 'Meaning: ' + r.exp])
                if ty in (5, 6) and ln:
                    r.o = 'MS/TP MAC ' + str(sc)
                    r.info = npdu(d, min(L, i + 8 + ln), i + 8, r, tree)      # stop before the data CRC
        else:
            o = -1
            et = 0
            if lt == 1:
                if L < 14:
                    raise ValueError
                e = 12
                et = d[e] << 8 | d[e + 1]
                while et in (0x8100, 0x88a8):
                    e += 4
                    et = d[e] << 8 | d[e + 1]
                o = e + 2
                if tree is not None:
                    tree.append([0, f'Ethernet: {hm(d, 6)} → {hm(d, 0)}'])
                if et <= 1500 and d[o] == 0x82 and d[o + 1] == 0x82 and d[o + 2] == 3:
                    r.proto = 'BACnet/Ethernet'
                    r.src = hm(d, 6)
                    r.dst = 'Broadcast' if d[0] == 255 and d[5] == 255 else hm(d, 0)
                    r.o = r.src
                    if tree is not None:
                        tree.append([0, 'IEEE 802.2 LLC: BACnet (DSAP 0x82, SSAP 0x82)'])
                    r.info = npdu(d, min(L, o + et) if et >= 3 else L, o + 3, r, tree)   # ignore Ethernet padding
                    et = -1
            elif lt == 113:
                et = d[14] << 8 | d[15]
                o = 16
            elif lt == 276:
                et = d[0] << 8 | d[1]
                o = 20
            elif lt in (101, 228):
                o = 0
                et = 0x86dd if d[0] >> 4 == 6 else 0x800
            elif lt in (0, 108):
                o = 4
                et = 0x86dd if d[4] >> 4 == 6 else 0x800
            src = dst = None
            u = -1
            end = L                       # end of the UDP payload (Ethernet pads short frames with zeros)
            if et == 0x800 and (d[o] >> 4) == 4 and d[o + 9] == 17:
                u = o + (d[o] & 15) * 4
                src = '.'.join(str(x) for x in d[o + 12:o + 16])
                dst = '.'.join(str(x) for x in d[o + 16:o + 20])
                r.v = 4
                tl = d[o + 2] << 8 | d[o + 3]
                if tl >= 20:
                    end = min(end, o + tl)
            elif et == 0x86dd and (d[o] >> 4) == 6:
                nx = d[o + 6]
                u = o + 40
                pl_ = d[o + 4] << 8 | d[o + 5]
                if pl_:
                    end = min(end, o + 40 + pl_)
                while nx in (0, 43, 60, 44) and u < L:
                    l = 8 if nx == 44 else (d[u + 1] + 1) * 8
                    nx = d[u]
                    u += l
                if nx != 17:
                    u = -1
                else:
                    src = '[' + v6s(d[o + 8:o + 24]) + ']'
                    dst = '[' + v6s(d[o + 24:o + 40]) + ']'
                    r.v = 6
            if u >= 0:
                sp = d[u] << 8 | d[u + 1]
                dp = d[u + 2] << 8 | d[u + 3]
                ul = d[u + 4] << 8 | d[u + 5]
                if ul >= 8:
                    end = min(end, u + ul)
                L = end
                b = u + 8
                r.src = f'{src}:{sp}'
                r.dst = f'{dst}:{dp}'
                r.proto = 'UDP'
                r.info = f'UDP {sp} → {dp}'
                if tree is not None:
                    tree.append([0, f'IPv{r.v} / UDP: {r.src} → {r.dst}'])
                if d[b] == 0x81:
                    r.proto = 'BACnet/IP'
                    f = d[b + 1]
                    r.info = _BN.get(f) or 'BVLC 0x' + format(f, 'x')
                    r.exp = BX.get(f, '')
                    if tree is not None:
                        tree.append([0, 'BACnet Virtual Link: ' + r.info])
                    r.o = r.src
                    q = b + 4
                    if f == 0:
                        c = d[b + 4] << 8 | d[b + 5]
                        if c:
                            r.nak = c
                        r.info = f'BVLC-Result: refused (code 0x{c:x})' if c else 'BVLC-Result: success'
                    elif f == 4:
                        r.o = '.'.join(str(x) for x in d[b + 4:b + 8]) + ':' + str(d[b + 8] << 8 | d[b + 9])
                        q = b + 10
                    if f == 5:
                        r.info = 'Register-Foreign-Device: asking this BBMD to include it'
                    if f in (4, 9, 10, 11):
                        r.info = npdu(d, L, q, r, tree)
                elif d[b] == 0x82:
                    r.proto = 'BACnet/IPv6'
                    f = d[b + 1]
                    r.info = B6.get(f) or 'BVLC6 0x' + format(f, 'x')
                    r.exp = BX6.get(f, '')
                    if tree is not None:
                        tree += [[0, 'BACnet/IPv6 Virtual Link: ' + r.info],
                                 [1, 'Source virtual address (VMAC): ' + mh(d, b + 4, 3)]]
                    r.o = 'VMAC ' + mh(d, b + 4, 3)
                    q = -1
                    if f == 0:
                        c = d[b + 7] << 8 | d[b + 8]
                        if c:
                            r.nak = c
                        r.info = f'BVLC-Result: refused (code 0x{c:x})' if c else 'BVLC-Result: success'
                    elif f == 1:
                        r.dk = 'VMAC ' + mh(d, b + 7, 3)
                        if tree is not None:
                            tree.append([1, 'Destination virtual address (VMAC): ' + mh(d, b + 7, 3)])
                        q = b + 10
                    elif f in (2, 12):
                        q = b + 7
                    elif f == 8:
                        q = b + 25
                    elif f in (3, 5):
                        r.info += ': ' + mh(d, b + 7, 3)
                    if q >= 0:
                        r.info = npdu(d, L, q, r, tree)
    except (IndexError, ValueError, struct.error):
        r.info = 'Malformed packet'
    r.dk = r.dk or (('' if r.dst == 'Broadcast' else 'MS/TP ' + r.dst) if r.proto == 'MS/TP' else r.dst)
    if r.o:
        r.key = f'network {r.sn}, {r.sa}' if r.sn is not None else r.o
    if want_tree:
        r.tree = tree
    return r


def detail_tree(r: Pk):
    """The decoded detail lines for one packet (built on demand, like the original)."""
    return dis(r.t, r.lt, r.d, r.no, r.ifc, True).tree or []


def hx(d) -> str:
    out = []
    for i in range(0, len(d), 16):
        c = d[i:i + 16]
        out.append(f'{i:04x}  ' + ' '.join(f'{x:02x}' for x in c).ljust(48) + ' ' +
                   ''.join(chr(x) if 31 < x < 127 else '.' for x in c))
    return '\n'.join(out) + ('\n' if out else '')


# --------------------------------------------------------- capture files --
class CaptureError(Exception):
    pass


def parse(b: bytes):
    """Read a pcap or pcapng file. Returns a list of (t, linktype, data, interface).
    A file cut off part-way (e.g. still being written) returns the packets before the cut."""
    o = []
    try:
        _parse(b, o)
    except (struct.error, IndexError):
        if not o:
            raise CaptureError('damaged file')
    return o


def _parse(b, o):
    if len(b) < 24:
        raise CaptureError('too short')
    m = struct.unpack_from('<I', b, 0)[0]
    U = len(b)
    if m == 0x0a0d0d0a:
        le = True
        p = 0
        ifs = []
        while p + 12 <= U:
            if struct.unpack_from('<I', b, p)[0] == 0x0a0d0d0a:
                bo = struct.unpack_from('<I', b, p + 8)[0] if p + 12 <= U else 0
                le = True if bo == 0x1a2b3c4d else False if bo == 0x4d3c2b1a else le
                ifs = []
            e = '<' if le else '>'
            T, Lb = struct.unpack_from(e + 'II', b, p)
            if Lb < 12 or p + Lb > U + 3:
                break
            if T == 1:
                ts = 1e6
                q = p + 16
                while q + 4 <= p + Lb - 4:
                    c, l = struct.unpack_from(e + 'HH', b, q)
                    if c == 0:
                        break
                    if c == 9 and l >= 1:
                        x = b[q + 4]
                        ts = 2.0 ** (x & 127) if x & 128 else 10.0 ** x
                    q += 4 + ((l + 3) & ~3)
                ifs.append((struct.unpack_from(e + 'H', b, p + 8)[0], ts))
            elif T == 6:
                iid, hi, lo, c = struct.unpack_from(e + 'IIII', b, p + 8)
                lt, ts = ifs[iid] if iid < len(ifs) else (1, 1e6)
                o.append(((hi * 4294967296 + lo) / ts, lt, b[p + 28:p + 28 + c], iid))
            elif T == 3:
                c = min(Lb - 16, struct.unpack_from(e + 'I', b, p + 8)[0])
                o.append((o[-1][0] if o else 0, ifs[0][0] if ifs else 1, b[p + 12:p + 12 + c], 0))
            p += Lb
    else:
        if m not in (0xa1b2c3d4, 0xa1b23c4d, 0xd4c3b2a1, 0x4d3cb2a1):
            raise CaptureError('not a pcap or pcapng file')
        le = m in (0xa1b2c3d4, 0xa1b23c4d)
        ns = m in (0xa1b23c4d, 0x4d3cb2a1)
        e = '<' if le else '>'
        lt = struct.unpack_from(e + 'I', b, 20)[0] & 0xfffffff
        p = 24
        while p + 16 <= U:
            s, f, c = struct.unpack_from(e + 'III', b, p)
            o.append((s + f / (1e9 if ns else 1e6), lt, b[p + 16:p + 16 + c], 0))
            p += 16 + c


def pcapng(lst) -> bytes:
    """Write packets (Pk) as a pcapng file that Wireshark opens."""
    def blk(t, body):
        body = bytes(body)
        Lb = len(body) + (4 - len(body) % 4) % 4 + 12
        return struct.pack('<II', t, Lb) + body + b'\0' * (Lb - 12 - len(body)) + struct.pack('<I', Lb)
    lts = []
    for r in lst:
        if r.lt not in lts:
            lts.append(r.lt)
    parts = [blk(0x0A0D0D0A, struct.pack('<IHHII', 0x1A2B3C4D, 1, 0, 0xFFFFFFFF, 0xFFFFFFFF))]
    for lt in lts:
        parts.append(blk(1, struct.pack('<HHI', lt, 0, 65535)))
    for r in lst:
        t = int(round(r.t * 1e6))
        parts.append(blk(6, struct.pack('<IIIII', lts.index(r.lt), t // 4294967296, t % 4294967296,
                                        len(r.d), len(r.d)) + bytes(r.d)))
    return b''.join(parts)


# -------------------------------------------------------------- filters --
class FilterError(Exception):
    pass


_IP_RE = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?')
_MAC_RE = re.compile(r'\bMAC (\d+)\b')


def _addrs(r):
    return ' '.join(x for x in (r.src, r.dst, r.key, r.dk, r.o) if x)


def _anyof(field, vals, limit=10):
    """'field == "a" || field == "b"' – the display filter for a finding's packets."""
    return ' || '.join(f'{field} == "{v}"' for v in list(dict.fromkeys(vals))[:limit])


def _fields(T0):
    def gw(r):
        return [r.o if r.sn is not None else None, r.dst if r.dn is not None else None]
    F = {
        'no': lambda r: r.no, 'time': lambda r: r.t - T0, 'src': lambda r: r.src, 'dst': lambda r: r.dst,
        'addr': lambda r: [r.src, r.dst], 'proto': lambda r: r.proto, 'len': lambda r: r.len,
        'info': lambda r: r.info, 'device': lambda r: r.iam['inst'] if r.iam else None, 'net': lambda r: r.sn,
        'bad': lambda r: 1 if r.bad else 0, 'iam': lambda r: 1 if r.iam else 0, 'whois': lambda r: 1 if r.whois else 0,
        'nak': lambda r: 1 if r.nak else 0, 'router': lambda r: 1 if r.adv is not None else 0, 'gateway': gw,
        'host': lambda r: [r.key, r.dk], 'from': lambda r: r.key, 'to': lambda r: r.dk, 'dnet': lambda r: r.dn,
        'reach': lambda r: list(r.adv) if r.adv is not None else [],
        'announcer': lambda r: r.o if r.adv is not None else None, 'write': lambda r: 1 if r.wr else 0,
        'command': lambda r: 1 if r.wr and r.wr['sev'] else 0, 'cov': lambda r: 1 if r.cov else 0,
        'error': lambda r: 1 if r.er else 0, 'bookmark': lambda r: 1 if r.bm else 0, 'note': lambda r: r.note or '',
        'sender': lambda r: r.key or r.src, 'receiver': lambda r: r.dk or r.dst, 'service': lambda r: r.rs,
        'object': lambda r: [r.ob, r.wr['obj'] if r.wr else None, r.cov['obj'] if r.cov else None],
        'mstp.type': lambda r: MT.get(r.mt[0]) if r.mt else None, 'mstp.src': lambda r: r.mt[1] if r.mt else None,
        'mstp.dst': lambda r: r.mt[2] if r.mt else None,
        'ip': lambda r: _IP_RE.findall(_addrs(r)),           # any IP in the packet, also behind a router
        'mac': lambda r: _MAC_RE.findall(_addrs(r))}         # any MS/TP MAC in the packet
    F.update({'ip.addr': F['addr'], 'ip.src': F['src'], 'ip.dst': F['dst'], 'bacnet.device': F['device'],
              'bacnet.net': F['net'], 'frame.len': F['len'], 'frame.number': F['no'], 'mstp.bad': F['bad']})
    return F


_TERM = re.compile(r'^([\w.]+)\s*(==|!=|>=|<=|>|<|contains|~)\s*"?([^"]*?)"?$', re.I)


def _as_list(x):
    return x if isinstance(x, list) else [x]


def _term(t, FLD):
    t = t.strip()
    neg = False
    if t[:1] == '!':
        neg = True
        t = t[1:].strip()
    m = _TERM.match(t)
    if m:
        g = FLD.get(m.group(1).lower())
        if not g:
            raise FilterError('unknown field ' + m.group(1))
        op = m.group(2).lower()
        v = m.group(3).strip().lower()
        y = jstonum(v)
        ynum = not (isinstance(y, float) and y != y)

        def eq(s):
            if s == v or s.startswith(v + ':'):
                return True
            if v != '' and ynum:
                x = jstonum(s)
                return x == y
            return False

        def f(r):
            A = [jsstr(x).lower() for x in _as_list(g(r)) if x is not None]
            if not A:
                return op == '!='
            if op == '!=':
                return all(not eq(s) for s in A)
            for s in A:
                if op == '==':
                    if eq(s):
                        return True
                    continue
                if op in ('contains', '~'):
                    if v in s:
                        return True
                    continue
                x = jstonum(s)
                if op == '>' and x > y or op == '<' and x < y or op == '>=' and x >= y or op == '<=' and x <= y:
                    return True
            return False
    elif t.lower() in FLD:
        g = FLD[t.lower()]

        def f(r):
            return any(a is not None and a != 0 and a != '' for a in _as_list(g(r)))
    else:
        w = t.lower()

        def f(r):
            return w in (r.proto + ' ' + r.src + ' ' + r.dst + ' ' + r.info).lower()
    if neg:
        return lambda r: not f(r)
    return f


_OR = re.compile(r'^(\|\||or\b)', re.I)
_AND = re.compile(r'^(&&|and\b)', re.I)
_NOT = re.compile(r'^not\b', re.I)
_ANDOR = re.compile(r'^\s+(and|or)\b', re.I)


def compile_filter(s, T0=0.0):
    """Compile a Wireshark-style display filter into a function Pk -> bool. Raises FilterError."""
    s = s.strip()
    if not s:
        return lambda r: True
    FLD = _fields(T0)
    st = {'i': 0}

    def ws():
        while st['i'] < len(s) and s[st['i']] == ' ':
            st['i'] += 1

    def kw(w):
        ws()
        m = (_OR if w == 'or' else _AND).match(s[st['i']:])
        if m:
            st['i'] += len(m.group(0))
            return True
        return False

    def orx():
        a = [andx()]
        while kw('or'):
            a.append(andx())
        return a[0] if len(a) == 1 else (lambda r: any(f(r) for f in a))

    def andx():
        a = [un()]
        while kw('and'):
            a.append(un())
        return a[0] if len(a) == 1 else (lambda r: all(f(r) for f in a))

    def un():
        ws()
        i = st['i']
        if i < len(s) and s[i] == '(':
            st['i'] += 1
            f = orx()
            ws()
            if st['i'] >= len(s) or s[st['i']] != ')':
                raise FilterError('missing )')
            st['i'] += 1
            return f
        if i < len(s) and s[i] == '!' and s[i + 1:i + 2] != '=':
            st['i'] += 1
            f = un()
            return lambda r: not f(r)
        if _NOT.match(s[i:]):
            st['i'] += 3
            f = un()
            return lambda r: not f(r)
        j = i
        q = False
        while j < len(s):
            c = s[j]
            if c == '"':
                q = not q
            if q:
                j += 1
                continue
            if c == ')' or s.startswith('&&', j) or s.startswith('||', j):
                break
            if c.isspace() and _ANDOR.match(s[j:]):
                break
            j += 1
        t = s[i:j].strip()
        if not t:
            raise FilterError('empty term')
        st['i'] = j
        return _term(t, FLD)
    f = orx()
    ws()
    if st['i'] < len(s):
        raise FilterError('unexpected text')
    return f


def cell_filter(r, col, T0):
    """Filter text for one cell of the packet list (right-click 'Apply as Filter')."""
    F = ['no', 'time', 'src', 'dst', 'gateway', 'proto', 'len', 'info'][col]
    if F == 'no':
        return f'no == {r.no}'
    if F == 'time':
        return f'time >= {tofixed(r.t - T0, 4)}'
    if F == 'src':
        return f'from == "{r.key}"' if r.key else f'src == "{r.src}"'
    if F == 'dst':
        return f'to == "{r.dk}"' if r.dk else f'dst == "{r.dst}"'
    if F == 'gateway':
        return f'gateway == "{r.o}"' if r.sn is not None else ''
    if F == 'proto':
        return f'proto == "{r.proto}"'
    if F == 'len':
        return f'len == {r.len}'
    return 'info contains "' + re.split(r'[:(#]', r.info)[0].strip().replace('"', '') + '"'


# --------------------------------------------------------------- search --
def sq_hay(r) -> str:
    return (f"{r.src} {r.dst} {'net ' + str(r.sn) + ' ' + str(r.sa) + ' ' + str(r.o) if r.sn is not None else ''} "
            f"{'net ' + str(r.dn) if r.dn is not None else ''} {r.proto} {r.info or ''} "
            f"{'device ' + str(r.iam['inst']) if r.iam else ''} {r.key or ''} {r.dk or ''} {r.note or ''}").lower()


def search_matcher(text):
    T = []
    for t in text.lower().split():
        if re.match(r'^[\d.:]+$', t):
            lb = r'(?<!\d)' if re.match(r'^\d+$', t) else r'(?<![\d.])'
            T.append(re.compile(lb + re.escape(t) + r'(?!\d)'))
        else:
            T.append(t)

    def m(r):
        s = sq_hay(r)
        return all((t in s) if isinstance(t, str) else bool(t.search(s)) for t in T)
    return m


# ------------------------------------------------------- address helpers --
def is_bc(r) -> bool:
    return r.dst == 'Broadcast' or bool(re.search(r'(^|\.)255:\d+$', r.dst)) or bool(re.match(r'^\[ff', r.dst, re.I))


def MACOF(k):
    k = str(k)
    m = re.search(r'MAC (\d+)$', k)
    if m:
        return int(m.group(1))
    m = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)(?::\d+)?$', k)
    return int(m.group(4)) if m else None


def fmt_ms(ms) -> str:
    return f'{jsround(ms)} ms' if ms < 1000 else f'{tofixed(ms / 1000, 2)} s'


def pl(n, w) -> str:
    return f"{n} {w}{'' if n == 1 else 's'}"


def gap(s) -> str:
    if 0 < s < 1:
        return f'{jsround(s * 1000)} ms'          # MS/TP devices talk many times a second ("every 0 s" before)
    return f'{tofixed(s / 3600, 1)} h' if s >= 3600 else f'{tofixed(s / 60, 1)} min' if s >= 60 else f'{jsround(s)} s'


# ------------------------------------------------------------- bus speed --
BAUDS = [9600, 19200, 38400, 57600, 76800, 115200]


def spd(P):
    tr, ip = {}, {}
    t0 = P[0].t if P else 0

    def sec(o, t, b):
        s = max(0, math.floor(t - t0))
        o['s'][s] = o['s'].get(s, 0) + b
    for r in P:
        if r.proto == 'MS/TP' and r.fl:
            k = r.ifc
            o = tr.get(k)
            if o is None:
                o = tr[k] = {'k': k, 'T': [], 'F': [], 'G': [], 'n': 0, 'bad': 0, 'bytes': 0, 's': {}, 't0': r.t, 't1': r.t}
            o['T'].append(r.t)
            o['F'].append(r.fl)
            o['G'].append(0 if r.bad else 1)
            o['n'] += 1
            if r.bad:
                o['bad'] += 1
            o['bytes'] += r.fl
            o['t1'] = r.t
            sec(o, r.t, r.fl)
        elif r.proto in ('BACnet/IP', 'BACnet/IPv6', 'UDP', 'BACnet/Ethernet'):
            m = re.search(r':(\d+)$', r.dst)
            k = 'BACnet/Ethernet' if r.proto == 'BACnet/Ethernet' else ('UDP port ' + m.group(1) if m else 'other')
            o = ip.get(k)
            if o is None:
                o = ip[k] = {'k': k, 'n': 0, 'bytes': 0, 'bc': 0, 's': {}, 't0': r.t, 't1': r.t}
            o['n'] += 1
            o['bytes'] += r.len
            o['t1'] = r.t
            if r.dst == 'Broadcast' or re.search(r'\.255:\d+$', r.dst) or r.dst.startswith('[ff'):
                o['bc'] += 1
            sec(o, r.t, r.len)
    multi = len(tr) > 1
    mt = []
    for o in sorted(tr.values(), key=lambda x: x['k']):
        need = []
        T, F, G = o['T'], o['F'], o['G']
        for i in range(1, len(T)):
            dt = T[i] - T[i - 1]
            if dt > 0 and G[i]:
                need.append(F[i] * 10 / dt)
        o['name'] = f"MS/TP trunk (capture interface {o['k'] + 1})" if multi else 'MS/TP trunk'
        o['usable'] = len(need)
        o['est'] = None
        o['conf'] = False
        if len(need) >= 20:
            for b in BAUDS:
                if sum(1 for x in need if x <= b * 1.05) >= .98 * len(need):
                    o['est'] = b
                    o['conf'] = sum(1 for x in need if b * .6 <= x <= b * 1.05) / len(need) >= .05
                    break
            if o['est'] is None:
                o['est'] = -1
        del o['T'], o['F'], o['G']
        mt.append(o)
    it = sorted(ip.values(), key=lambda x: -x['bytes'])
    return {'m': mt, 'ip': it, 'dur': max(1, P[-1].t - t0) if P else 1}


def util(o, baud, dur):
    pk = max([0] + list(o['s'].values()))
    return {'avg': min(9.99, o['bytes'] * 10 / baud / max(1, o['t1'] - o['t0'])), 'peak': min(9.99, pk * 10 / baud)}


# --------------------------------------------------------------- analysis --
class Analysis(list):
    """The findings list, with every other analysis result as attributes (like the original FD)."""
    er = rb = tf = pairs = covs = wr = trk = tEnd = sp = sl = dv = via = adv = gws = nm = nets = None


def _fix_why(w):
    if re.search('segmentation not supported', w):
        return ('The device cannot send or receive long (segmented) messages. Ask for fewer objects or properties per '
                'request, and avoid reading whole object lists in one request.')
    if re.search('buffer overflow|apdu too long|message too long', w):
        return 'The request or answer is too big for the device. Ask for less data per request.'
    if re.search('unknown object', w):
        return ('The requester asks for an object that does not exist, often a stale point list after the device was '
                'reprogrammed. Re-import or re-map the points.')
    if re.search('unknown property', w):
        return ('The device does not have that (optional) property. Often harmless probing; a problem only if a graphic '
                'or trend relies on it.')
    if re.search('write access denied|read access denied|service request denied|password', w):
        return 'The point is read-only, not commandable, or needs permission. Check the object type, priority and any device password.'
    if re.search('busy|in progress', w):
        return ('The device was busy or still starting up. Reduce simultaneous requests, or wait for the device to finish '
                'its restart or download.')
    if re.search('out of resources|timeout|exceeded reply time', w):
        return ('The device is overloaded: it ran out of memory or transaction slots, or could not answer in time. Reduce '
                'how much is asking it at once.')
    if re.search('unrecognized service', w):
        return ('The device does not support that service. Configure the client to use Read Property instead of Read '
                'Property Multiple (or the other way round).')
    if re.search('invalid tag|missing required|out of range|data type|inconsistent', w):
        return 'The request is malformed for this device: usually a software or firmware version mismatch or a bug in the client.'
    return 'Check the requester and the device settings for this service.'


def _pair_q(e):
    """A repeated request: that poller asking that device about that object."""
    sig = e.get('sig') or ''
    obj = sig.split(': ', 1)[1].split(',')[0].replace(' …', '').strip() if ': ' in sig else ''
    q = f'sender == "{e["from"]}" && receiver == "{e["to"]}"'
    svc = sig.split(': ', 1)[0].strip()
    if svc:
        q += f' && service == "{svc}"'
    return f'({q} && object == "{obj}")' if obj else f'({q})'


def _median_sorted(a):
    return a[len(a) // 2] if a else 0


ER_WORD = {'error': 'failed', 'reject': 'rejected', 'abort': 'cancelled'}


def analyze(P, T0, local_net=None, own_ips=()) -> Analysis:
    """Everything the views need, computed from the decoded packets P.
    own_ips: this computer's addresses (its own Who-Is scans are not reported as a flood)."""
    own_ips = set(own_ips or ())
    dev, act, ids, gws, dv = {}, {}, {}, {}, {}
    via, adv, wi, nmap = {}, {}, {}, {}
    nets = set()
    out = Analysis()
    mt = mb = nk = rbN = 0
    pend, slm = {}, {}
    tEnd = 0
    tf, pairs, covs, wrs, wgrp, erm, mtI = {}, {}, {}, [], {}, {}, {}

    def sle(k):
        e = slm.get(k)
        if e is None:
            e = slm[k] = {'ms': [], 'miss': 0, 'w': None}
        return e

    def gs(m, k):
        s = m.get(k)
        if s is None:
            s = m[k] = {}          # insertion-ordered "set"
        return s

    def ad(k):
        return f"{k} via gateway {', '.join(gws[k])}" if k in gws else k

    def tm(t):
        return tofixed(t - T0, 1) + 's'
    for r in P:
        if r.t > tEnd:
            tEnd = r.t
        if r.rq is not None:
            k = f'{r.key or r.src}>{r.dk or r.dst}#{r.rq}'
            if k not in pend:
                pend[k] = r
        elif r.rp is not None:
            k = f'{r.dk or r.dst}>{r.key or r.src}#{r.rp}'
            q = pend.get(k)
            if q is not None:
                del pend[k]
                if q.wrx is not None:
                    q.wrx['res'] = f"{ER_WORD[r.er['k']]}: {r.er['txt']}" if r.er else 'accepted'
                if r.er:
                    ek = (r.key or r.src) + '|' + r.er['k'] + ': ' + r.er['txt']
                    e = erm.get(ek)
                    if e is None:
                        e = erm[ek] = {'who': r.key or r.src, 'why': ER_WORD[r.er['k']] + ': ' + r.er['txt'], 'k': r.er['k'],
                                       'svc': {}, 'n': 0, 'no': r.no}
                    e['n'] += 1
                    e['svc'][q.rs] = 1
                ms = (r.t - q.t) * 1000
                if 0 <= ms <= 3e4:
                    e = sle(r.key or r.src)
                    e['ms'].append(ms)
                    if not e['w'] or ms > e['w']['ms']:
                        e['w'] = {'ms': ms, 'svc': q.rs}
        w = r.key or ('MS/TP ' + r.src if r.proto == 'MS/TP' else r.src)
        if w:
            e = tf.get(w)
            if e is None:
                e = tf[w] = {'n': 0, 'b': 0, 'bc': 0, 'rq': 0, 'cov': 0, 'f': r.t, 'l': r.t}
            e['n'] += 1
            e['b'] += r.len
            e['l'] = r.t
            if is_bc(r):
                e['bc'] += 1
            if r.rq is not None:
                e['rq'] += 1
            if r.cov:
                e['cov'] += 1
        if r.rq is not None and r.sig:
            k = f'{r.key or r.src}>{r.dk or r.dst}|{r.sig}'
            e = pairs.get(k)
            if e is None:
                e = pairs[k] = {'from': r.key or r.src, 'to': r.dk or r.dst, 'sig': r.sig, 'n': 0, 'f': r.t, 'l': r.t}
            e['n'] += 1
            e['l'] = r.t
        if r.cov:
            k = (r.key or r.src) + '|' + r.cov['obj']
            e = covs.get(k)
            if e is None:
                e = covs[k] = {'from': r.key or r.src, 'dev': r.cov['dev'], 'obj': r.cov['obj'], 'n': 0, 'f': r.t, 'l': r.t}
            e['n'] += 1
            e['l'] = r.t
        if r.wr:
            wx = {'rec': r, 'no': r.no, 't': r.t, 'from': r.key or r.src, 'to': r.dk or r.dst, **r.wr, 'res': ''}
            wrs.append(wx)
            r.wrx = wx
            if r.wr['prop'] and r.wr['obj'] and r.wr['sev'] == 0:
                k = wx['to'] + '|' + wx['obj'] + '|' + wx['prop']
                g = wgrp.get(k)
                if g is None:
                    g = wgrp[k] = {'to': wx['to'], 'obj': wx['obj'], 'prop': wx['prop'], 'seq': [], 'w': {}}
                g['seq'].append(wx)
                x = g['w'].get(wx['from'])
                if x is None:
                    x = g['w'][wx['from']] = {'n': 0, 'v': {}, 'f': wx['t'], 'l': wx['t']}
                x['n'] += 1
                x['v'][wx['val']] = 1
                x['l'] = wx['t']
        if r.mt:
            q = mtI.get(r.ifc)
            if q is None:
                q = mtI[r.ifc] = {'ifc': r.ifc, 'm': {}, 'tin': {}, 'hold': {}, 'rot': {}, 'lastTo': {}, 'tokIn': {},
                                  'pfmMax': 0, 'pfmTo': {}, 'rpl': set(), 't0': r.t, 't1': r.t, 'n': 0}
            ty, sc, ds = r.mt
            e = q['m'].get(sc)
            if e is None:
                e = q['m'][sc] = {'n': 0, 'tok': 0, 'data': 0, 'pfm': 0, 'rep': 0, 'f': r.t, 'l': r.t}
            e['n'] += 1
            e['l'] = r.t
            q['n'] += 1
            q['t1'] = r.t
            if ty == 0:
                e['tok'] += 1
                q['tokIn'][ds] = q['tokIn'].get(ds, 0) + 1
                if q['tin'].get(sc) is not None:
                    q['hold'].setdefault(sc, []).append(r.t - q['tin'][sc])
                    q['tin'][sc] = None
                if q['lastTo'].get(ds) is not None:
                    q['rot'].setdefault(ds, []).append(r.t - q['lastTo'][ds])
                q['lastTo'][ds] = r.t
                q['tin'][ds] = r.t
            elif ty == 1:
                e['pfm'] += 1
                q['pfmTo'][ds] = q['pfmTo'].get(ds, 0) + 1
                if ds != 255:
                    q['pfmMax'] = max(q['pfmMax'], ds)
            elif ty == 2:
                e['rep'] += 1
                q['rpl'].add(sc)
            elif ty in (5, 6):
                e['data'] += 1
        if r.rb:
            rbN += 1
        if r.proto == 'MS/TP':
            mt += 1
            if r.bad:
                mb += 1
        if r.names:
            for x in r.names:
                nmap.setdefault(x['inst'], {})[x['k']] = x['v']
        if r.sn is not None:
            nets.add(r.sn)
        if r.dn is not None:
            nets.add(r.dn)
        if r.nn is not None:
            nets.add(r.nn)
        if r.adv:
            nets.update(r.adv)
        if r.nak:
            nk += 1
            if nk == 1:
                out.append({'s': 'WARNING', 't': 'A BBMD is refusing requests',
                            'w': f'The BBMD at {r.src} answered "no" (code 0x{r.nak:x}) to a request from {r.dst}.',
                            'ev': [f'{r.src} refused {r.dst}'], 'q': 'nak',
                            'y': 'A BBMD links separate IP subnets. When it refuses requests, devices on other subnets cannot register or be discovered, so they look offline.',
                            'f': [f'Open the BBMD settings on the device at {r.src}.',
                                  'Check the Broadcast Distribution Table (BDT): every BBMD must be listed with the correct IP address, port and subnet mask.',
                                  f'If {r.dst} is a foreign device, check the foreign-device table is not full and its time-to-live is not too short.',
                                  'Confirm the BBMD and the devices use the same UDP port (normally 47808).',
                                  'Capture again and confirm the refusals have stopped.']})
        if not r.key:
            continue
        a = act.get(r.key)
        if a is None:
            a = act[r.key] = {'f': r.t, 'l': r.t}
        a['f'] = min(a['f'], r.t)
        a['l'] = max(a['l'], r.t)
        if r.sn is not None:
            gs(gws, r.key)[r.o] = 1
            via.setdefault(r.sn, {}).setdefault(r.o, {})[r.sa] = 1
        if r.iam:
            k = r.iam['inst']
            dk = f'{k}|{r.key}'
            e = dv.get(dk)
            if e is None:
                e = dv[dk] = {'id': k, 'key': r.key, 'sn': r.sn, 'sa': r.sa, 'gw': r.o if r.sn is not None else '',
                              'v': r.iam['vendor'], 'n': 0}
            e['n'] += 1
            gs(dev, k)[r.key] = 1
            gs(ids, r.key)[k] = 1
        if r.adv:
            for n in r.adv:
                adv.setdefault(n, {})[r.o] = 1
        if r.whois and r.src.rsplit(':', 1)[0] not in own_ips:      # this PC's own scans are not a flood
            k = f'{r.o}|{math.floor(r.t)}'
            wi[k] = wi.get(k, 0) + 1
    taken = set(dev.keys())
    for did, ks in dev.items():
        if did > 4194302:
            out.append({'s': 'WARNING', 't': f'Unusable device ID {did}',
                        'w': f'A device announced itself as device ID {did}, which is reserved.', 'q': f'device == {did}',
                        'ev': [f'Announced from {ad(k)}' for k in ks],
                        'y': '4194303 is the wildcard meaning "any device", so no real device can use it. Software cannot address a device that has it, which usually means the device was never configured.',
                        'f': ['Find the device at the address shown (by its IP address or MS/TP MAC).',
                              'Open its setup page or tool and set a unique device ID between 0 and 4194302.',
                              'Write the new ID down so it is not reused.']})
        if len(ks) < 2:
            continue
        l = list(ks)
        cc = False
        for i in range(len(l)):
            for j in range(i + 1, len(l)):
                x, y = act[l[i]], act[l[j]]
                if min(x['l'], y['l']) - max(x['f'], y['f']) > 0:
                    cc = True
        ev = [f"{ad(k)} – announced {dv[f'{did}|{k}']['n']}×, active {tm(act[k]['f'])} to {tm(act[k]['l'])}" for k in l]

        def sug(k, did=did):
            e = dv.get(f'{did}|{k}')
            net = e['sn'] if e and e['sn'] is not None else local_net
            mac = MACOF(e['sa'] if e and e['sn'] is not None else k)

            def ok(n):
                return 0 <= n <= 999999 and n not in taken

            def pick(n, w):
                taken.add(n)
                return {'id': n, 'why': w}
            if net is not None and mac is not None and mac < 100:
                c = net * 100 + mac
                if ok(c):
                    return pick(c, f'network {net} × 100 + MAC {mac}, following the usual numbering scheme')
                for m in range(100):
                    if ok(net * 100 + m):
                        return pick(net * 100 + m, f'the next unused ID on network {net}')
            b = (did // 100) * 100
            for n in range(b, b + 100):
                if ok(n):
                    return pick(n, 'an unused ID close to the old one')
            for n in range(0, 1000000):
                if ok(n):
                    return pick(n, 'an unused ID')
            return None
        sg = []
        if cc:
            for k in sorted(l, key=lambda k: act[k]['f'])[1:]:
                s_ = sug(k)
                if s_:
                    sg.append({'k': k, 's': s_})
        if cc:
            out.append({'s': 'SERIOUS', 't': f'Two devices are using the same device ID ({did})',
                        'w': f'Device ID {did} is being announced by {len(l)} different addresses at the same time, so {len(l)} different physical devices are claiming it.',
                        'ev': ev, 'sg': sg, 'id': did, 'q': f'device == {did}',
                        'y': 'Every device must have its own device ID. When two share one, software cannot tell them apart: reads and writes can reach the wrong controller, point values jump between the two, and one of them may vanish from device lists.',
                        'f': ['Note the addresses under "Where". An address marked "via gateway" is a device on another network, behind that gateway.',
                              'Find each physical device. For an IP address, look it up in your router or switch (ARP or DHCP table) to get its hardware address and switch port. For an MS/TP address, check the address setting on the controllers on that trunk.',
                              f'Confirm they really are two controllers: read the Object_Name, Description or Location of device {did} from each address with any BACnet tool.',
                              'Change the device ID on one of them using its setup tool or web page. Pick a number nothing else uses and write it down.',
                              *[f"Suggested new ID for the device at {ad(x['k'])}: {x['s']['id']} ({x['s']['why']}). It is not used by any device in this capture; check your own records too." for x in sg],
                              'The usual cause is a controller cloned from a backup or copied from another job. Check for spares or replacements that were never renumbered.',
                              'Capture again for a few minutes and confirm this finding is gone.']})
        else:
            out.append({'s': 'WARNING', 't': f'Device {did} changed address during the capture',
                        'w': f'Device ID {did} was first seen at one address and later at another, but never at both at once.',
                        'q': f'device == {did}',
                        'ev': ev,
                        'y': 'This is harmless if the device was replaced or re-addressed on purpose. If not, its address is not fixed, so other devices and your front-end software may lose contact with it each time it changes.',
                        'f': ['Compare the "active" times under Where: the old address should stop when the new one starts.',
                              'If you replaced or re-addressed the device, no action is needed.',
                              'If the device gets its address from DHCP, give it a fixed IP address or a DHCP reservation.',
                              'Make sure the old unit is not still powered on somewhere.']})
    # duplicate network numbers (the original walked via's networks, then adv's, each in ascending order)
    for n in list(dict.fromkeys(sorted(via) + sorted(adv))):
        v = via.get(n, {})
        ad_ = adv.get(n, {})
        rs = list(dict.fromkeys(list(v) + list(ad_)))
        nq = f'net == {n} || dnet == {n} || reach == {n}'
        if len(rs) < 2:
            continue
        ss = list(v.values())
        dj = len(ss) > 1 and all(all(i == j or not any(x in b for x in a) for j, b in enumerate(ss)) for i, a in enumerate(ss))

        def gdesc(x):
            if x in v:
                vs = list(v[x])
                return (f"Gateway {x} passes on {len(vs)} device{'' if len(vs) == 1 else 's'}: {', '.join(vs[:6])}"
                        f"{', …' if len(vs) > 6 else ''}")
            return f'Gateway {x} announced a route to this network, but none of its devices were seen'
        ev = [gdesc(x) for x in rs]
        if n == 0:
            out.append({'s': 'NOTE', 't': 'Several gateways refer to network 0 (the local network)', 'q': nq,
                        'w': f'{len(rs)} gateways mention network 0. Network 0 is not a real network number: devices and routers '
                             'use it to mean "the local network", so many devices can point to it at once.',
                        'ev': ev,
                        'y': 'Usually nothing to fix. It only matters if a router port has actually been configured with network '
                             'number 0, which BACnet does not allow.',
                        'f': ['No action is needed if every router port has its own network number (1 or higher).',
                              'If a router shows network 0 in its port settings, give that port an unused number (see Available networks).']})
            continue
        if dj:
            out.append({'s': 'SERIOUS' if all(len(a) > 1 for a in ss) else 'WARNING',
                        't': f'Two different networks seem to share network number {n}', 'q': nq,
                        'w': f'Several gateways say they lead to network {n}, but each one passes on a completely different set of devices. If it were one network reached by backup routers, they would all pass on the same devices.',
                        'ev': ev,
                        'y': 'A network number works like a street name. When two networks share one, routers cannot tell which one a message is for, so messages go to the wrong place and devices seem to appear and disappear.',
                        'f': ['Open the configuration of every gateway listed under Where.',
                              f'Look at the BACnet network number set on each port. Every separate network must have a different number, so only one of these ports should be {n}.',
                              'Decide which network is wrong (usually the newer or smaller one) and give it an unused number. Devices behind it keep their device IDs.',
                              'If a router "learned" its number from another router, set the number manually (configured) instead.',
                              'Restart the affected routers, or wait for them to refresh, and capture again.']})
        elif len(ss) > 1:
            out.append({'s': 'NOTE', 't': f'Network {n} can be reached through more than one gateway', 'q': nq,
                        'w': f'The same devices on network {n} were passed on by more than one gateway.', 'ev': ev,
                        'y': 'This looks like a deliberate backup path (two routers doing the same job). It is only a problem if you expected a single router, or if it creates a loop.',
                        'f': ['If you installed backup routers, no action is needed.',
                              'If not, find out why two gateways connect to the same network and remove the extra one.']})
        else:
            out.append({'s': 'WARNING', 't': f'Network {n} is announced by several gateways – check it is not a duplicate', 'q': nq,
                        'w': f'{len(rs)} gateways announce a route to network {n}. That is normal for backup routers, but it is also what a duplicated network number looks like. There was not enough device traffic to tell which.',
                        'ev': ev, 'y': 'If it is a duplicate, messages may reach the wrong network.',
                        'f': ['Open each gateway listed under Where and check which network sits behind it.',
                              'If they all lead to the same physical network, this is fine.',
                              'If they lead to different networks, renumber one so every network has its own number.',
                              'Capture for longer (long enough to see devices announcing themselves) for a clearer answer.']})
    for k, s_ in ids.items():
        if len(s_) <= 1:
            continue
        ms = k.startswith('MS/TP')
        nt = k.startswith('network')
        Ls = ', '.join('device ' + str(i) for i in s_)
        out.append({'s': 'WARNING' if ms or nt else 'NOTE', 't': f'One address uses {len(s_)} different device IDs ({k})', 'q': f'iam && sender == "{k}"',
                    'w': f'{ad(k)} announced {Ls}. One address should hold only one device.',
                    'ev': [f"device {i} announced {dv[f'{i}|{k}']['n']}× from {ad(k)}" for i in s_],
                    'y': ('Two devices with the same MS/TP address fight over the token and answer each other’s messages. That causes garbled frames, lost messages and devices that drop in and out.' if ms else
                          'Behind a gateway, every device needs its own MAC address on its network. Two device IDs on one address usually means a duplicate MAC on an MS/TP trunk, or two separate networks sharing one network number.' if nt else
                          'This is normal for gateways, supervisors and simulators that present several virtual devices, but unusual for an ordinary controller.'),
                    'f': (['Go to the MS/TP trunk and list every controller on it with its MAC address.',
                           'Look for two controllers set to the same address (address switches, DIP switches or a setting in its web page). Addresses 0–127 are masters and must be unique on each trunk.',
                           'Change one of the duplicates to an unused address. Most controllers restart when the address changes.',
                           f'Confirm {Ls} each still answer afterwards.'] if ms else
                          ['Identify the gateway shown above and the network behind it.',
                           'On that trunk, check for two controllers with the same MAC address.',
                           'If the MAC addresses differ, look for another gateway that uses the same network number (see the duplicate network number finding).',
                           'Fix it and capture again.'] if nt else
                          ['If this address is a gateway, supervisor or simulator, no action is needed.',
                           'Otherwise treat it like a duplicate device ID: find the device by its IP address and make sure each device has its own device ID.'])})
    if mb >= 3 and mb / mt >= .005:
        out.append({'s': 'SERIOUS' if mb / mt >= .1 else 'WARNING', 't': 'The MS/TP wiring is producing damaged messages', 'q': 'bad',
                    'w': f'{mb} of {mt} MS/TP frames ({tofixed(100 * mb / mt, 1)}%) failed their CRC error check.',
                    'ev': [f'{mb} damaged and {mt - mb} good MS/TP frames'],
                    'y': 'A damaged frame is a lost message. You will see slow updates, retries, and devices that drop offline and come back.',
                    'f': ['Check both ends of the RS-485 trunk: there should be one 120-ohm terminator at each end of the cable and none in the middle.',
                          'Check bias: the whole trunk needs one set of bias resistors, not one per device. With no bias, idle bus noise causes garbled frames.',
                          'Check the cable: twisted pair, shield grounded at one end only, daisy-chained from device to device (no star or T-shaped branches), under about 1200 m (4000 ft).',
                          'Confirm every device uses the same baud rate. One device at a different rate produces constant damaged frames.',
                          'Find the culprit: disconnect devices (or a branch) one at a time while watching the damaged-frame count.',
                          'Check polarity on every device (A to A, B to B) and look for loose terminals or damaged cable.']})
    tk, seen_src, tok_to = {}, set(), {}
    for r in P:
        if r.mt:
            ty, sc, ds = r.mt
            seen_src.add(sc)
            if ty == 0 and ds != 255:
                tok_to.setdefault(sc, {})
                tok_to[sc][ds] = tok_to[sc].get(ds, 0) + 1
                tk[ds] = tk.get(ds, 0) + 1
    dead = [m for m in sorted(tk) if m not in seen_src and tk[m] >= 3]
    for m in dead:
        frm = [f'MAC {s} passed it {tok_to[s][m]}×' for s in sorted(tok_to) if tok_to[s].get(m)]
        out.append({'s': 'WARNING', 't': f'The token is being handed to MAC {m}, but nothing answers', 'q': f'mstp.type == "Token" && mstp.dst == {m}',
                    'w': f'MAC {m} was offered the MS/TP token {tk[m]} times but never sent a single frame itself, so there is probably no working device at that address.',
                    'ev': frm,
                    'y': 'Every time the token goes to an address with nothing behind it, the trunk waits for a timeout before moving on. That wastes bandwidth and makes every device on the trunk slower to talk.',
                    'f': [f'Find out whether a device is supposed to be at MAC {m}. If it is, check its power, its address setting, its baud rate and its wiring.',
                          f'If a device used to be there and was removed, restart the other controllers on the trunk (or wait for them to rebuild their list of masters) so they stop offering the token to MAC {m}.',
                          'Check that nobody has set "maximum master" higher than the highest real MAC on the trunk. A lower maximum master removes pointless polling.',
                          'Capture again and confirm the token no longer goes to that address.']})
    for s in sorted(tok_to):
        e = sorted([(m, c) for m, c in sorted(tok_to[s].items()) if m not in dead], key=lambda x: -x[1])
        tot = sum(c for _, c in e)
        if len(e) > 1 and e[1][1] >= 5 and e[1][1] / tot >= .1:
            out.append({'s': 'WARNING', 't': f'The token route around MAC {s} keeps changing', 'q': f'mstp.type == "Token" && mstp.src == {s}',
                        'w': f"MAC {s} passes the token to {len(e)} different devices ({', '.join(f'MAC {m} {c}×' for m, c in e)}). In a healthy trunk each master always passes the token to the same next master.",
                        'ev': [f'MAC {s} → MAC {m}: {c} times' for m, c in e],
                        'y': 'A changing token route means masters are repeatedly dropping out of and rejoining the ring. Devices that keep losing the token answer slowly or not at all, and values go stale.',
                        'f': ['Look for a device that is resetting, browning out or losing power on the trunk.',
                              f'Check for a duplicate MAC address, especially at MAC {s} and at the addresses listed under Where.',
                              'Check the wiring, termination and bias (see the damaged-messages finding if it is also present).',
                              'If a controller was recently added or replaced, a short burst of changes is normal; capture again for a few minutes to see if it settles.']})
    for q in pend.values():
        if q.t < tEnd - 10:
            sle(q.dk or q.dst)['miss'] += 1
    kid = {}
    for d in dv.values():
        kid.setdefault(d['key'], []).append(d['id'])
    sl = []
    for k, e in slm.items():
        a = sorted(e['ms'])
        n = len(a)

        def q_(p):
            return a[min(n - 1, math.floor(p * n))] if n else 0
        tot = n + e['miss']
        slow = n >= 5 and (q_(.5) >= 1000 or q_(.95) >= 3000)
        silent = tot >= 5 and e['miss'] / tot >= .3
        row = {'key': k, 'ids': sorted(kid.get(k, [])), 'n': n, 'miss': e['miss'], 'avg': sum(a) / n if n else 0,
               'med': q_(.5), 'p95': q_(.95), 'max': a[-1] if n else 0, 'w': e['w'], 'slow': slow, 'silent': silent}
        if row['n'] or row['miss'] >= 3:
            sl.append(row)
    sl.sort(key=lambda x: (-(1 if (x['slow'] or x['silent']) else 0), -x['med']))

    def nmv2(e):
        return 'device ' + ', '.join(map(str, e['ids'])) if e['ids'] else e['key']
    sw_ = [e for e in sl if e['slow']]
    if sw_:
        out.append({'s': 'WARNING', 'q': _anyof('host', [e['key'] for e in sw_]), 't': f'{nmv2(sw_[0])} is slow to answer requests' if len(sw_) == 1 else f'{len(sw_)} devices are slow to answer requests',
                    'w': 'These devices took a long time to answer: ' + '; '.join(f"{nmv2(e)} (typical {fmt_ms(e['med'])}, worst {fmt_ms(e['max'])})" for e in sw_[:5]) + '.',
                    'ev': [f"{e['key']} – typical {fmt_ms(e['med'])}, slowest 5% took {fmt_ms(e['p95'])}, {e['n']} answered" for e in sw_],
                    'y': 'Most controllers answer in well under half a second. A device that takes seconds is overloaded, on a congested or noisy network, or being asked for too much at once. Front-end screens feel sluggish and requests start timing out.',
                    'f': ['Open the Response times tab to see every device ranked by how long it takes to answer.',
                          'Find out what is asking these devices for data. Reduce how often trend logs, graphics or integrations poll them.',
                          'On MS/TP, check the trunk for damaged frames, a duplicate MAC or too many devices on one trunk.',
                          'On a router or gateway, check its load: a slow gateway makes every device behind it look slow.',
                          'Capture again after the change and compare the two captures on the Compare tab.']})
    sm_ = [e for e in sl if e['silent']]
    if sm_:
        out.append({'s': 'WARNING', 'q': _anyof('receiver', [e['key'] for e in sm_]), 't': f'{nmv2(sm_[0])} often does not answer' if len(sm_) == 1 else f'{len(sm_)} devices often do not answer',
                    'w': 'Requests sent to these devices went unanswered: ' + '; '.join(f"{nmv2(e)} ({e['miss']} of {e['n'] + e['miss']} unanswered)" for e in sm_[:5]) + '.',
                    'ev': [f"{e['key']} – {e['miss']} of {e['n'] + e['miss']} requests got no answer" for e in sm_],
                    'y': 'Unanswered requests mean lost messages or a device that is offline, overloaded or unable to reply. Software retries and waits, which makes everything slower.',
                    'f': ['Check that the device is powered and still on the network (ping it, or check its MS/TP address).',
                          'Check the network path to it: gateways, routers and the trunk wiring.',
                          'Check the device is not overloaded by too many simultaneous requests.',
                          'If it was removed on purpose, remove it from the front-end software so it stops asking.']})
    fl = {}
    for k, c in wi.items():
        x = k.split('|')[0]
        fl[x] = max(fl.get(x, 0), c)
    for x, c in fl.items():
        if c >= 20:
            out.append({'s': 'WARNING', 't': 'A device is flooding the network with Who-Is requests', 'q': f'whois && (sender == "{x}" || src == "{x}")',
                        'w': f'{x} sent up to {c} "who is out there?" broadcasts in one second.',
                        'ev': [f'{x} – peak {c} per second'],
                        'y': 'Every device must answer each unrestricted Who-Is, so a flood can clog the network (especially slow MS/TP trunks) and make everything sluggish.',
                        'f': [f'Find what is at {x} – usually a supervisor, a BACnet tool or a scanner.',
                              'Turn off repeated or automatic device discovery in that software.',
                              'If discovery is needed, limit it to a range of device IDs instead of asking for all devices.',
                              'Capture again and check the flood has stopped.']})

    def name_of(k):
        i = kid.get(k)
        return 'device ' + ', '.join(map(str, i)) + ' (' + k + ')' if i else k

    def fT(t):
        return tofixed(t - T0, 1) + 's'
    nf = 0
    for g in wgrp.values():
        if nf >= 5 or len(g['w']) < 2 or len(g['seq']) < 4:
            continue
        trn = 0
        for i in range(1, len(g['seq'])):
            if g['seq'][i]['from'] != g['seq'][i - 1]['from'] and g['seq'][i]['val'] != g['seq'][i - 1]['val']:
                trn += 1
        if trn < 2:
            continue
        nf += 1
        out.append({'s': 'SERIOUS' if trn >= 6 else 'WARNING', 't': f"Two sources keep writing the same point ({g['obj']}, {g['prop']})",
                    'q': f'write && receiver == "{g["to"]}" && object == "{g["obj"]}"',
                    'w': f"{' and '.join(name_of(x) for x in g['w'])} are both writing {g['obj']} {g['prop']} on {name_of(g['to'])}, and the value flips between them {trn} times.",
                    'ev': [f"{name_of(f)} wrote it {x['n']}× (values: {', '.join(list(x['v'])[:4])})" for f, x in g['w'].items()],
                    'y': 'When two controllers or front-end systems command the same point, they undo each other: the equipment hunts, runs when it should not, or the point never settles where you set it. It is one of the most common causes of "it keeps changing back".',
                    'f': ['Find out which of the two sources should own this point (usually the controller running the sequence, not a front-end overriding it).',
                          'Open the Changes tab to see every write in time order, with priority and result.',
                          'Remove the extra command: a graphic or schedule that also writes it, a duplicate program or a second front-end.',
                          'If both are needed, give them different priorities on purpose so the higher one wins cleanly.',
                          'Capture again and check the flipping has stopped.']})
    fq = []
    for g in wgrp.values():
        for f, x in g['w'].items():
            if x['n'] >= 20 and (x['l'] - x['f']) / (x['n'] - 1) <= 5:
                fq.append({'g': g, 'f': f, 'x': x, 'iv': (x['l'] - x['f']) / (x['n'] - 1)})
    fq.sort(key=lambda e: e['iv'])
    if fq:
        e0 = fq[0]
        out.append({'s': 'WARNING', 't': 'A point is being written very often' if len(fq) == 1 else f'{len(fq)} points are being written very often',
                    'q': ' || '.join(f'(write && sender == "{e["f"]}" && object == "{e["g"]["obj"]}")' for e in fq[:6]),
                    'w': f"{name_of(e0['f'])} wrote {e0['g']['obj']} {e0['g']['prop']} on {name_of(e0['g']['to'])} {e0['x']['n']} times, about every {tofixed(e0['iv'], 1)} seconds.",
                    'ev': [f"{name_of(e['f'])} → {e['g']['obj']} {e['g']['prop']} on {name_of(e['g']['to'])}: {e['x']['n']}×, every {tofixed(e['iv'], 1)} s" for e in fq[:8]],
                    'y': 'Writing the same value over and over wastes network time, and if the property is stored in flash memory (setpoints, configuration, schedules) it can wear the memory out. It usually means a program loops or a front-end "keeps the value pushed".',
                    'f': ['Check what is at the address that sends the writes: a front-end graphic, a supervisor program or a script.',
                          'Change it to write only when the value changes.',
                          'Make sure it is not writing to a stored (non-volatile) setting.',
                          'Capture again afterwards.']})
    cm = [w for w in wrs if w['sev'] >= 1]
    if cm:
        bad = any('DISABLE' in w['val'] for w in cm)
        out.append({'s': 'SERIOUS' if bad else 'NOTE', 't': f"{len(cm)} restart, communication or object command{'' if len(cm) == 1 else 's'} seen", 'q': 'command',
                    'w': 'These commands change how a device behaves: ' + '; '.join(f"{w['svc']} ({w['val']}) sent to {name_of(w['to'])}" for w in cm[:3]) + ('; …' if len(cm) > 3 else '') + '.',
                    'ev': [f"{fT(w['t'])}: {name_of(w['from'])} → {name_of(w['to'])}: {w['svc']}{' ' + w['obj'] if w['obj'] and w['obj'] != 'device' else ''} – {w['val']}{' (' + w['res'] + ')' if w['res'] else ''}" for w in cm[:12]],
                    'y': 'Restarting a controller drops its control for a while, and "disable communication" makes a device go silent so it looks offline. These are normal during commissioning and updates, but unexpected ones are a common reason equipment seems to misbehave.',
                    'f': ['Check the time of each command against what was happening on site: a download, a firmware update, someone commissioning?',
                          'If nobody should be doing this, find the source address and who uses that computer or controller.',
                          'If a device was left with communication disabled, send "enable communication" or restart it (the time-out may also end it).',
                          'Use the Changes tab to see everything around that time.']})
    bw = [w for w in wrs if re.match(r'^(failed|rejected|cancelled)', w['res'])]
    if bw:
        g = {}
        for w in bw:
            k = w['to'] + '|' + w['res']
            g[k] = g.get(k, 0) + 1
        top3 = sorted(g.items(), key=lambda x: -x[1])[:3]
        out.append({'s': 'WARNING', 't': f"{len(bw)} write{' was' if len(bw) == 1 else 's were'} refused", 'q': 'error && info contains "Write"',
                    'w': f"Devices answered \"no\" to {len(bw)} write request{'' if len(bw) == 1 else 's'}. Most common: " + '; '.join(f"{name_of(k.split('|')[0])} – {k.split('|')[1]} ({n}×)" for k, n in top3) + '.',
                    'ev': [f"{fT(w['t'])}: {name_of(w['from'])} tried {w['obj']} {w['prop']} = {w['val']} on {name_of(w['to'])} → {w['res']}" for w in bw[:10]],
                    'y': 'The change did not happen. A front-end shows the new value as sent, but the device keeps the old one, so the screen and the equipment disagree.',
                    'f': ['"write access denied" means the point is read-only (for example an input, or a value that the program owns) or a password is needed.',
                          'Write to the right object: output and value objects accept commands; inputs do not.',
                          'Check the priority used: some points only accept certain priorities.',
                          '"unknown object / property" means the front-end has a stale point list: re-import the points from the device.']})
    tot = len(P)
    tops = sorted(tf.items(), key=lambda x: -x[1]['n'])
    if tot >= 500 and len(tops) >= 3 and tops[0][1]['n'] / tot >= .5:
        allb = max(1, sum(r.len for r in P))
        out.append({'s': 'NOTE', 't': f"{name_of(tops[0][0])} sends {jsround(100 * tops[0][1]['n'] / tot)}% of all traffic", 'q': f'sender == "{tops[0][0]}"',
                    'w': f"{name_of(tops[0][0])} sent {locale_int(tops[0][1]['n'])} of {locale_int(tot)} packets ({jsround(100 * tops[0][1]['b'] / allb)}% of the bytes).",
                    'ev': [f"{name_of(k)}: {locale_int(e['n'])} packets, {locale_int(e['rq'])} requests, {locale_int(e['bc'])} broadcasts" for k, e in tops[:5]],
                    'y': 'One busy address is normal for a front-end or supervisor that polls many devices. If it is a controller or a gateway, it may be misbehaving or overloaded.',
                    'f': ['Open the Traffic tab to see what it is sending and to whom.', 'If it is a front-end, check its polling rates.',
                          'If it is a controller, check for a runaway program, a flood of COV notifications or repeated Who-Is.']})
    prs = []
    for e in pairs.values():
        iv = (e['l'] - e['f']) / (e['n'] - 1) if e['n'] > 1 else 1e9
        if e['n'] >= 30 and iv <= 2:
            prs.append({**e, 'iv': iv})
    prs.sort(key=lambda e: e['iv'])
    if prs:
        p0 = prs[0]
        out.append({'s': 'WARNING' if p0['iv'] <= .2 else 'NOTE', 't': 'A request is repeated very often' if len(prs) == 1 else f'{len(prs)} requests are repeated very often',
                    'q': ' || '.join(_pair_q(e) for e in prs[:6]),
                    'w': f"{name_of(p0['from'])} asks {name_of(p0['to'])} for the same thing ({p0['sig']}) about every {tofixed(p0['iv'], 2)} seconds, {locale_int(p0['n'])} times.",
                    'ev': [f"{name_of(e['from'])} → {name_of(e['to'])}: {e['sig']}, every {tofixed(e['iv'], 2)} s ({locale_int(e['n'])}×)" for e in prs[:8]],
                    'y': 'Fast polling of the same point keeps the network and the controller busy. On MS/TP, a few fast pollers are enough to make the whole trunk slow.',
                    'f': ['Find what is polling: a front-end screen that is open, a trend log, a graphic or an integration.',
                          'Slow the rate to what you really need (for example 10–60 seconds for temperatures), or use COV subscriptions instead.',
                          'Close pages and graphics nobody is looking at.', 'Check the Response times tab for devices that are suffering.']})
    cv = []
    for e in covs.values():
        rate = e['n'] / max(1, e['l'] - e['f'])
        if e['n'] >= 50 and rate >= 2:
            cv.append({**e, 'rate': rate})
    cv.sort(key=lambda e: -e['rate'])
    if cv:
        c0 = cv[0]
        out.append({'s': 'WARNING', 't': 'A point is sending a flood of change notifications' if len(cv) == 1 else f'{len(cv)} points are sending floods of change notifications',
                    'q': ' || '.join(f'(cov && sender == "{e["from"]}" && object == "{e["obj"]}")' for e in cv[:6]),
                    'w': f"{name_of(c0['from'])} sent {locale_int(c0['n'])} change-of-value (COV) notifications for {c0['obj']}, about {tofixed(c0['rate'], 1)} per second.",
                    'ev': [f"{name_of(e['from'])}: {e['obj']} – {locale_int(e['n'])}× ({tofixed(e['rate'], 1)}/s)" for e in cv[:8]],
                    'y': 'COV is meant to send a message only when a value changes by a meaningful amount. A noisy sensor with a tiny COV increment turns into a constant stream that clogs the network and the subscriber.',
                    'f': ['Increase the COV increment on that object (for example 0.5° instead of 0.01°).',
                          'Check the input for noise: loose wiring, a floating input or a bad sensor.',
                          'Check the subscriber: does it really need every update?', 'Capture again to confirm it has settled.']})
    erl = sorted(erm.values(), key=lambda e: -e['n'])
    out.er = [{**e, 'svc': list(e['svc']), 'fix': _fix_why(e['why'])} for e in erl]
    big = [e for e in out.er if e['n'] >= 5]
    if big:
        out.append({'s': 'WARNING', 't': f"{name_of(big[0]['who'])} keeps refusing requests" if len(big) == 1 else f'{len(big)} devices keep refusing or failing requests',
                    'q': 'error && (' + _anyof('sender', [e['who'] for e in big]) + ')',
                    'w': '; '.join(f"{name_of(e['who'])}: {e['why']} ({e['n']}×)" for e in big[:3]) + ('; …' if len(big) > 3 else '') + '.',
                    'ev': [f"{name_of(e['who'])} – {e['why']}, {e['n']}× (while handling {', '.join(map(str, e['svc']))})" for e in big[:10]],
                    'y': 'Every refused request is a wasted round trip, and the software on the other side often retries or shows missing data. Repeated refusals point to a setup problem rather than bad luck.',
                    'f': ['Open the Response times tab: the "Errors and refusals" table explains each reason and what to do.',
                          *[f"{name_of(e['who'])}: {_fix_why(e['why'])}" for e in big[:3]],
                          'Fix the cause on the requesting side where you can, then capture again.']})
    trk = []
    for q in sorted(mtI.values(), key=lambda x: x['ifc']):
        def med(a):
            if not a:
                return 0
            s = sorted(a)
            return s[len(s) // 2]
        st, masters = {}, []
        for m, e in q['m'].items():
            if e['tok'] > 0 or e['pfm'] > 0:
                hd = q['hold'].get(m) or []
                masters.append({'mac': m, 'tok': e['tok'], 'data': e['data'], 'pfm': e['pfm'],
                                'hold': sum(hd) / len(hd) if hd else 0, 'holdMax': max(hd) if hd else 0,
                                'rot': med(q['rot'].get(m)), 'n': e['n']})
                st[m] = 'master'
            elif e['n']:
                st[m] = 'slave'
        for m in q['rpl']:
            if not st.get(m):
                st[m] = 'joining'
        for m, c in q['tokIn'].items():
            if m not in q['m'] and c >= 3:
                st[m] = 'dead'
            elif m not in q['m'] and not st.get(m) and c:
                st[m] = 'dead'
        for m in q['pfmTo']:
            if not st.get(m) and m <= 127:
                st[m] = 'polled'
        masters.sort(key=lambda x: x['mac'])
        hi = max((x['mac'] for x in masters), default=0)
        rots = sorted(x['rot'] for x in masters if x['rot'])
        pf = list(q['pfmTo'].items())
        waste = sum(c for m, c in pf if m > hi)
        pt = sum(c for _, c in pf)
        trk.append({'ifc': q['ifc'], 'n': q['n'], 'st': st, 'masters': masters, 'hi': hi, 'pfmMax': q['pfmMax'],
                    'waste': waste, 'pfmTotal': pt, 'rot': rots[len(rots) // 2] if rots else 0,
                    'dead': sorted(m for m in st if st[m] == 'dead'), 't0': q['t0'], 't1': q['t1']})
    multi = len(trk) > 1
    for t in trk:
        nm = f"MS/TP trunk (capture interface {t['ifc'] + 1})" if multi else 'MS/TP trunk'
        if t['pfmMax'] > t['hi'] and t['waste'] >= 10 and t['pfmTotal'] and t['waste'] / t['pfmTotal'] >= .2 and t['n'] >= 300:
            out.append({'s': 'NOTE', 't': f'Max Master on the {nm} looks higher than needed', 'q': f'mstp.type == "Poll-For-Master" && mstp.dst > {t["hi"]}',
                        'w': f"The highest working master on this trunk is MAC {t['hi']}, but masters keep polling addresses up to MAC {t['pfmMax']} ({t['waste']} wasted polls, {jsround(100 * t['waste'] / t['pfmTotal'])}% of all polling).",
                        'ev': [f"Highest master seen: MAC {t['hi']}", f"Highest address polled: MAC {t['pfmMax']}"],
                        'y': 'Each master has a "Max Master" setting that tells it how far up the address range to look for new masters. Set higher than necessary, every cycle wastes time polling addresses where nothing exists.',
                        'f': [f"Set Max Master to {t['hi']} (or the highest MAC you plan to install) on every master on this trunk.",
                              'Do this on all masters: they only poll as far as their own setting.',
                              'Leave a little headroom only if you will add devices soon.']})
        if t['rot'] >= 1 and len(t['masters']) >= 2:
            out.append({'s': 'WARNING', 't': f'The token on the {nm} is slow to go round', 'q': 'mstp.type == "Token"',
                        'w': f"The token takes about {tofixed(t['rot'], 2)} seconds to complete a lap between {len(t['masters'])} masters.",
                        'ev': [f"MAC {m['mac']} holds the token {jsround(m['hold'] * 1000)} ms on average (longest {jsround(m['holdMax'] * 1000)} ms)"
                               for m in sorted(t['masters'], key=lambda m: -m['hold'])[:4]],
                        'y': 'A device can only speak when it has the token, so a slow lap delays every message on the trunk. Values go stale and requests time out.',
                        'f': ['Look at the devices that hold the token longest (listed under Where): they send or wait for the most.',
                              'Reduce traffic from front-ends and trend logs on this trunk.', 'Raise the baud rate if every device supports it.',
                              'Reduce the number of masters, or split the trunk.']})
    out.rb, out.tf, out.pairs, out.covs, out.wr, out.trk, out.tEnd = rbN, tf, list(pairs.values()), list(covs.values()), wrs, trk, tEnd
    sp = spd(P)
    for o in sp['m']:
        if o['est'] and o['est'] > 0 and o['conf']:
            u = util(o, o['est'], sp['dur'])
            if u['avg'] >= .5:
                out.append({'s': 'WARNING', 't': f"The {o['name']} is about {jsround(u['avg'] * 100)}% full", 'q': 'proto == "MS/TP"',
                            'w': f"At the estimated {o['est']} baud, the trunk was busy about {jsround(u['avg'] * 100)}% of the time on average (peak {jsround(min(1, u['peak']) * 100)}% in one second).",
                            'ev': [f"{locale_int(o['n'])} frames; {o['est']} baud estimated from the timing between frames"],
                            'y': 'MS/TP shares one wire between all devices, and only the device holding the token can talk. When the trunk is this busy, replies are delayed, tokens take longer to go round, and devices start to time out.',
                            'f': ['Raise the baud rate on every device on the trunk (for example 38400 to 76800 or 115200) if every device supports it. All devices must use the same rate.',
                                  'Reduce traffic: slow down trend logs, graphics and supervisor polling, and avoid unrestricted Who-Is.',
                                  'Split the trunk: move some controllers to a second trunk behind another router or gateway.',
                                  'Check the Response times tab to see which devices are slow to answer.',
                                  'Capture again after the change and compare on the Compare tab.']})
    order = {'SERIOUS': 0, 'WARNING': 1, 'NOTE': 2}
    out.sort(key=lambda f: order[f['s']])
    out.sp, out.sl, out.dv, out.via, out.adv, out.gws, out.nm, out.nets = sp, sl, list(dv.values()), via, adv, gws, nmap, nets
    return out


def kid_map(F):
    m = {}
    for d in F.dv or []:
        m.setdefault(d['key'], []).append(d['id'])
    return m


# ------------------------------------------------------- online board --
def online_rows(F, live_now=False):
    tf = F.tf or {}
    km = kid_map(F)
    now = time.time() if live_now else (F.tEnd or 0)
    rows = []
    for k, e in tf.items():
        gp = (e['l'] - e['f']) / (e['n'] - 1) if e['n'] > 1 else 0
        si = max(0, now - e['l'])
        th = max(60, gp * 6)
        st = 'few' if e['n'] < 3 else 'sil' if si > th else 'on'
        rows.append({'k': k, 'ids': sorted(km.get(k, [])), 'n': e['n'], 'f': e['f'], 'l': e['l'], 'gp': gp, 'si': si, 'st': st})
    keys = {r['k'] for r in rows}
    for d in F.dv or []:
        if d['key'] not in tf and d['key'] not in keys:
            rows.append({'k': d['key'], 'ids': [d['id']], 'n': 0, 'f': 0, 'l': 0, 'gp': 0, 'si': 0, 'st': 'quiet'})
            keys.add(d['key'])
    o = {'sil': 0, 'quiet': 1, 'few': 2, 'on': 3}
    rows.sort(key=lambda r: (o[r['st']], r['ids'][0] if r['ids'] else 1e9, r['k']))
    return rows


# --------------------------------------------------- available IDs / nets --
def parse_res(t):
    s = set()
    for p in re.split(r'[,\s]+', t or ''):
        m = re.match(r'^(\d+)(?:-(\d+))?$', p)
        if m:
            a = int(m.group(1))
            b = int(m.group(2) or m.group(1))
            s.update(range(a, min(b, a + 100000) + 1))
    return s


def ranges(a):
    o = []
    i = 0
    while i < len(a):
        j = i
        while j + 1 < len(a) and a[j + 1] == a[j] + 1:
            j += 1
        o.append(f'{a[i]}–{a[j]}' if j > i else f'{a[i]}')
        i = j + 1
    return o


def rg(l):
    o = []
    i = 0
    while i < len(l):
        j = i
        while j + 1 < len(l) and l[j + 1] == l[j] + 1:
            j += 1
        o.append((l[i], l[j]))
        i = j + 1
    return o


def dev_plan(devs, ids, rd, ln, pn, ds, id_lo=0, id_hi=999999):
    mult = 100 if ds == 2 else 1000
    mx = 99 if ds == 2 else 127
    by, off, un = {}, [], []
    for d in devs:
        net = d['sn'] if d['sn'] is not None else ln
        mac = MACOF(d['sa'] if d['sn'] is not None else d['key'])
        if net is None or mac is None:
            un.append(d)
            continue
        e = by.setdefault(net, {'macs': set(), 'devs': []})
        e['macs'].add(mac)
        e['devs'].append(d)
        exp = net * mult + mac
        if d['id'] != exp:
            off.append({'d': d, 'net': net, 'mac': mac, 'exp': exp,
                        'clash': (exp in ids and exp != d['id']) or exp in rd,
                        'big': exp > id_hi or exp < id_lo or mac >= mult})
    if pn and pn not in by:
        by[pn] = {'macs': set(), 'devs': []}
    rows = []
    for net in sorted(by):
        e = by[net]

        def ok(m, net=net, e=e):
            i = net * mult + m
            return id_lo <= i <= id_hi and i not in ids and i not in rd and m not in e['macs']
        hi = max(e['macs']) if e['macs'] else 0
        m = None
        for k in range(hi + 1, mx + 1):
            if ok(k):
                m = k
                break
        if m is None:
            for k in range(0, mx + 1):
                if ok(k):
                    m = k
                    break
        gaps = [k for k in range(1, hi) if k not in e['macs']]
        free = [net * mult + k for k in range(0, mx + 1) if ok(k)]
        rows.append({'net': net, 'dv': e['devs'], 'used': sorted(e['macs']), 'hi': hi, 'gaps': gaps, 'mac': m,
                     'id': None if m is None else net * mult + m, 'free': free, 'fit': net * mult + mx <= id_hi})
    return {'rows': rows, 'off': off, 'un': un, 'mult': mult, 'mx': mx}


def net_plan(seen, lo, hi, rs, pick):
    used = sorted(n for n in seen if lo <= n <= hi)
    res = [n for n in rs if lo <= n <= hi and n not in seen]
    taken = set(used) | set(res)
    free = [n for n in range(lo, hi + 1) if n not in taken]
    cls = []
    for n in used:
        c = cls[-1] if cls else None
        if c and n - c['hi'] <= 200:
            c['hi'] = n
            c['n'] += 1
        else:
            cls.append({'lo': n, 'hi': n, 'n': 1})
    main = next((c for c in cls if c['lo'] == pick), None)
    if not main:
        for c in cls:
            if not main or c['n'] > main['n'] or (c['n'] == main['n'] and c['hi'] > main['hi']):
                main = c
    top = main['hi'] if main else None
    nx = next((n for n in free if top is None or n > top), None)
    return {'cls': cls, 'main': main, 'free': free, 'used': used, 'res': len(res),
            'outside': sorted(n for n in seen if n < lo or n > hi),
            'nx': nx if nx is not None else (free[0] if free else None), 'lo': lo, 'hi': hi}


def all_free(ids, rd, rows, mult, lo, hi):
    hi = min(hi, 4194302)
    if hi < lo:
        return {'r': [], 'n': 0}
    mask = bytearray(hi - lo + 1)

    def mk(n):
        if lo <= n <= hi:
            mask[n - lo] = 1
    for n in ids:
        mk(n)
    for n in rd:
        mk(n)
    for r in rows:
        for m in r['used']:
            mk(r['net'] * mult + m)
    out = []
    n0 = 0
    n = lo
    while n <= hi:
        if mask[n - lo]:
            n += 1
            continue
        j = n
        while j + 1 <= hi and not mask[j + 1 - lo]:
            j += 1
        out.append((n, j))
        n0 += j - n + 1
        n = j + 1
    return {'r': out, 'n': n0}


# ---------------------------------------------------------------- compare --
def _map_ids(F):
    a, b = {}, {}
    for d in F.dv or []:
        a.setdefault(d['id'], {})[d['key']] = 1
        b.setdefault(d['key'], {})[d['id']] = 1
    return a, b


def compare(FA, FB):
    a_id, a_key = _map_ids(FA)
    b_id, b_key = _map_ids(FB)
    R = {'newD': [], 'gone': [], 'moved': [], 'renum': [], 'newN': [], 'goneN': [], 'gwN': [], 'newF': [], 'fixedF': []}

    def sd(x, y):
        return [k for k in x if k not in y]
    re_, rn = set(), set()
    for k, ia in a_key.items():
        ib = b_key.get(k)
        if not ib:
            continue
        o, n = sd(ia, ib), sd(ib, ia)
        if o and n:
            R['renum'].append({'key': k, 'was': o, 'now': n})
            re_.update(o)
            rn.update(n)
    for did, ka in a_id.items():
        kb = b_id.get(did)
        if not kb:
            if did not in re_:
                R['gone'].append({'id': did, 'keys': list(ka)})
            continue
        o, n = sd(ka, kb), sd(kb, ka)
        if o and n:
            R['moved'].append({'id': did, 'from': o, 'to': n})
    for did, kb in b_id.items():
        if did not in a_id and did not in rn:
            R['newD'].append({'id': did, 'keys': list(kb)})
    na, nb = FA.nets or set(), FB.nets or set()
    R['newN'] = sorted(n for n in nb if n not in na)
    R['goneN'] = sorted(n for n in na if n not in nb)
    for n in [n for n in nb if n in na]:
        ga = list((FA.via or {}).get(n, {}))
        gb = list((FB.via or {}).get(n, {}))
        o, m = sd(ga, gb), sd(gb, ga)
        if ga and gb and (o or m):
            R['gwN'].append({'n': n, 'from': o, 'to': m})
    ta = {f['t'] for f in FA}
    tb = {f['t'] for f in FB}
    R['newF'] = [f for f in FB if f['t'] not in ta]
    R['fixedF'] = [f for f in FA if f['t'] not in tb]
    R['na'], R['nb'], R['fa'], R['fb'] = len(FA.dv or []), len(FB.dv or []), len(FA), len(FB)
    return R


# ----------------------------------------------------------- map model --
def map_model(F):
    D = F.dv or []
    via, adv, gws = F.via or {}, F.adv or {}, F.gws or {}
    T = {}

    def add(g, n):
        return T.setdefault(g, {}).setdefault(n, {})
    for d in D:
        if d['sn'] is not None:
            for g in (gws.get(d['key']) or [d['gw']]):
                add(g, d['sn'])[f"{d['id']}|{d['key']}"] = d
        else:
            add('', 'local')[f"{d['id']}|{d['key']}"] = d
    for n in via:
        for g in via[n]:
            add(g, n)
    for n in adv:
        for g in adv[n]:
            add(g, n)
    return T

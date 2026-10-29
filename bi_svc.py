"""
bi_svc.py - the full contents of a BACnet APDU for the packet details pane, like Wireshark shows them: the header
(invoke ID, max response size, segmentation) and every service parameter, with property values decoded and
named (units, states, flags), nested as deep as the message goes.

apdu_rows(d, L, i) returns [[level, text], ...] with level 1 directly under "BACnet APDU".
"""
from __future__ import annotations

import struct

import bi_core as C

MAX_APDU = [50, 128, 206, 480, 1024, 1476]
MAX_SEGS = ['unspecified', '2', '4', '8', '16', '32', '64', 'more than 64']
MAX_ROWS = 600

SEG = {0: 'segmented both ways', 1: 'can send segmented', 2: 'can receive segmented', 3: 'no segmentation'}
EVENT_STATE = {0: 'normal', 1: 'fault', 2: 'off-normal', 3: 'high-limit', 4: 'low-limit', 5: 'life-safety-alarm'}
NOTIFY_TYPE = {0: 'alarm', 1: 'event', 2: 'ack-notification'}
EVENT_TYPE = {0: 'change-of-bitstring', 1: 'change-of-state', 2: 'change-of-value', 3: 'command-failure',
              4: 'floating-limit', 5: 'out-of-range', 6: 'complex-event-type', 8: 'change-of-life-safety',
              9: 'extended', 10: 'buffer-ready', 11: 'unsigned-range', 13: 'access-event', 14: 'double-out-of-range',
              15: 'signed-out-of-range', 16: 'unsigned-out-of-range', 17: 'change-of-characterstring',
              18: 'change-of-status-flags', 19: 'change-of-reliability', 20: 'none', 21: 'change-of-discrete-value',
              22: 'change-of-timer'}
RELIABILITY = {0: 'no-fault-detected', 1: 'no-sensor', 2: 'over-range', 3: 'under-range', 4: 'open-loop',
               5: 'shorted-loop', 6: 'no-output', 7: 'unreliable-other', 8: 'process-error', 9: 'multi-state-fault',
               10: 'configuration-error', 12: 'communication-failure', 13: 'member-fault', 14: 'monitored-object-fault',
               15: 'tripped', 16: 'lamp-failure', 17: 'activation-failure', 18: 'renew-dhcp-failure', 19: 'renew-fd-registration-failure',
               20: 'restart-auto-negotiation-failure', 21: 'restart-failure', 22: 'proprietary-command-failure',
               23: 'faults-listed', 24: 'referenced-object-fault'}
SYSTEM_STATUS = {0: 'operational', 1: 'operational-read-only', 2: 'download-required', 3: 'download-in-progress',
                 4: 'non-operational', 5: 'backup-in-progress'}
POLARITY = {0: 'normal', 1: 'reverse'}
BINARY_PV = {0: 'inactive', 1: 'active'}
ENABLE_DISABLE = {0: 'enable', 1: 'disable', 2: 'disable-initiation'}
REINIT = {0: 'coldstart', 1: 'warmstart', 2: 'start-backup', 3: 'end-backup', 4: 'start-restore', 5: 'end-restore',
          6: 'abort-restore', 7: 'activate-changes'}
TRANSITIONS = ['to-offnormal', 'to-fault', 'to-normal']
STATUS_FLAGS = ['in-alarm', 'fault', 'overridden', 'out-of-service']
LIMIT_ENABLE = ['low-limit', 'high-limit']
RESULT_FLAGS = ['first-item', 'last-item', 'more-items']
DAYS = ['', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

# property -> names for its enumerated / bit-string values
PROP_ENUM = {36: EVENT_STATE, 103: RELIABILITY, 84: POLARITY, 112: SYSTEM_STATUS, 107: SEG, 72: NOTIFY_TYPE,
             79: None, 117: None}                     # 79 object type and 117 units are looked up separately
PROP_BITS = {111: STATUS_FLAGS, 0: TRANSITIONS, 35: TRANSITIONS, 1: TRANSITIONS, 52: LIMIT_ENABLE}
BINARY_VALUE_PROPS = (85, 104, 6, 40, 46)            # present / relinquish-default / alarm / feedback value…
BINARY_TYPES = (3, 4, 5)

# ------------------------------------------------------------------ services --
# A field is (context tag or None for an application tag, label, kind[, table or sub-fields]).
TS = [(0, 'Time', 'time'), (1, 'Sequence number', 'u'), (2, 'Date and time', 'value')]
PV_ITEM = [(0, 'Property', 'prop'), (1, 'Array index', 'u'), (2, 'Value', 'value'), (3, 'Priority', 'u')]
PROP_REF = [(0, 'Property', 'prop'), (1, 'Array index', 'u')]
ERROR = [(None, 'Error class', 'enum', C.EC), (None, 'Error code', 'enum', C.ECD)]
COV_NOTIFY = [(0, 'Subscriber process ID', 'u'), (1, 'Initiating device', 'oid'), (2, 'Monitored object', 'obj'),
              (3, 'Time remaining', 'secs'), (4, 'List of values', 'seq', PV_ITEM)]
EVENT_NOTIFY = [(0, 'Process ID', 'u'), (1, 'Initiating device', 'oid'), (2, 'Event object', 'obj'),
                (3, 'Time stamp', 'seq', TS), (4, 'Notification class', 'u'), (5, 'Priority', 'u'),
                (6, 'Event type', 'enum', EVENT_TYPE), (7, 'Message text', 'str'), (8, 'Notify type', 'enum', NOTIFY_TYPE),
                (9, 'Acknowledgement required', 'bool'), (10, 'From state', 'enum', EVENT_STATE),
                (11, 'To state', 'enum', EVENT_STATE), (12, 'Event values', 'value')]
PRIVATE = [(0, 'Vendor ID', 'vendor'), (1, 'Service number', 'u'), (2, 'Parameters', 'value')]
STREAM = [(None, 'Start position', 'i'), (None, 'Data', 'hex')]
RECORDS = [(None, 'Start record', 'i'), (None, 'Record count', 'u'), (None, 'Data', 'hex')]

REQUEST = {
    0: [(0, 'Acknowledging process ID', 'u'), (1, 'Event object', 'obj'), (2, 'Event state acknowledged', 'enum', EVENT_STATE),
        (3, 'Time stamp', 'seq', TS), (4, 'Acknowledgement source', 'str'), (5, 'Time of acknowledgement', 'seq', TS)],
    1: COV_NOTIFY,
    2: EVENT_NOTIFY,
    5: [(0, 'Subscriber process ID', 'u'), (1, 'Monitored object', 'obj'), (2, 'Issue confirmed notifications', 'bool'),
        (3, 'Lifetime', 'secs')],
    6: [(None, 'File', 'obj'), (0, 'Stream access', 'seq', [(None, 'Start position', 'i'), (None, 'Octet count', 'u')]),
        (1, 'Record access', 'seq', [(None, 'Start record', 'i'), (None, 'Record count', 'u')])],
    7: [(None, 'File', 'obj'), (0, 'Stream access', 'seq', STREAM), (1, 'Record access', 'seq', RECORDS)],
    8: [(0, 'Object', 'obj'), (1, 'Property', 'prop'), (2, 'Array index', 'u'), (3, 'Elements', 'value')],
    9: [(0, 'Object', 'obj'), (1, 'Property', 'prop'), (2, 'Array index', 'u'), (3, 'Elements', 'value')],
    10: [(0, 'Object specifier', 'seq', [(0, 'Object type', 'otype'), (1, 'Object', 'obj')]),
         (1, 'Initial values', 'seq', PV_ITEM)],
    11: [(None, 'Object', 'obj')],
    12: [(0, 'Object', 'obj'), (1, 'Property', 'prop'), (2, 'Array index', 'u')],
    14: [(0, 'Object', 'obj'), (1, 'Properties', 'seq', PROP_REF)],
    15: [(0, 'Object', 'obj'), (1, 'Property', 'prop'), (2, 'Array index', 'u'), (3, 'Value', 'value'), (4, 'Priority', 'u')],
    16: [(0, 'Object', 'obj'), (1, 'Values', 'seq', PV_ITEM)],
    17: [(0, 'Duration', 'mins'), (1, 'Enable / disable', 'enum', ENABLE_DISABLE), (2, 'Password', 'str')],
    18: PRIVATE,
    20: [(0, 'Reinitialized state', 'enum', REINIT), (1, 'Password', 'str')],
    26: [(0, 'Object', 'obj'), (1, 'Property', 'prop'), (2, 'Array index', 'u'),
         (3, 'By position', 'seq', [(None, 'Reference index', 'u'), (None, 'Count', 'i')]),
         (6, 'By sequence number', 'seq', [(None, 'Reference sequence number', 'u'), (None, 'Count', 'i')]),
         (7, 'By time', 'seq', [(None, 'Date', 'date'), (None, 'Time', 'time'), (None, 'Count', 'i')])],
    28: [(0, 'Subscriber process ID', 'u'), (1, 'Monitored object', 'obj'), (2, 'Issue confirmed notifications', 'bool'),
         (3, 'Lifetime', 'secs'), (4, 'Monitored property', 'seq', PROP_REF), (5, 'COV increment', 'real')],
    29: [(0, 'Last received object', 'obj')],
}
ACK = {
    6: [(None, 'End of file', 'bool'), (0, 'Stream access', 'seq', STREAM), (1, 'Record access', 'seq', RECORDS)],
    7: [(0, 'Start position', 'i'), (1, 'Start record', 'i')],
    12: [(0, 'Object', 'obj'), (1, 'Property', 'prop'), (2, 'Array index', 'u'), (3, 'Value', 'value')],
    14: [(0, 'Object', 'obj'), (1, 'Results', 'seq', [(2, 'Property', 'prop'), (3, 'Array index', 'u'), (4, 'Value', 'value'),
                                                       (5, 'Error', 'seq', ERROR)])],
    18: PRIVATE,
    26: [(0, 'Object', 'obj'), (1, 'Property', 'prop'), (2, 'Array index', 'u'), (3, 'Result flags', 'bits', RESULT_FLAGS),
         (4, 'Item count', 'u'), (5, 'Items', 'value'), (6, 'First sequence number', 'u')],
    29: [(0, 'Event summaries', 'seq', [(0, 'Object', 'obj'), (1, 'Event state', 'enum', EVENT_STATE),
                                        (2, 'Acknowledged transitions', 'bits', TRANSITIONS), (3, 'Event time stamps', 'seq', TS),
                                        (4, 'Notify type', 'enum', NOTIFY_TYPE), (5, 'Event enable', 'bits', TRANSITIONS),
                                        (6, 'Event priorities', 'value')]),
         (1, 'More events', 'bool')],
}
UNCONFIRMED = {
    0: [(None, 'Device', 'obj'), (None, 'Max APDU accepted', 'bytes'), (None, 'Segmentation', 'enum', SEG), (None, 'Vendor', 'vendor')],
    1: [(None, 'Device', 'oid'), (None, 'Object', 'obj'), (None, 'Object name', 'str')],
    2: COV_NOTIFY,
    3: EVENT_NOTIFY,
    4: PRIVATE,
    5: [(0, 'Source device', 'oid'), (1, 'Message class', 'value'), (2, 'Priority', 'enum', {0: 'normal', 1: 'urgent'}),
        (3, 'Message', 'str')],
    6: [(None, 'Date', 'date'), (None, 'Time', 'time')],
    7: [(0, 'Device ID from', 'u'), (1, 'Device ID to', 'u'), (2, 'Object', 'obj'), (3, 'Object name', 'str')],
    8: [(0, 'Device ID from', 'u'), (1, 'Device ID to', 'u')],
    9: [(None, 'Date (UTC)', 'date'), (None, 'Time (UTC)', 'time')],
}
ERROR_PDU = {
    8: [(0, 'Error', 'seq', ERROR), (1, 'First failed element', 'u')],
    9: [(0, 'Error', 'seq', ERROR), (1, 'First failed element', 'u')],
    10: [(0, 'Error', 'seq', ERROR), (1, 'First failed element', 'u')],
    18: [(0, 'Error', 'seq', ERROR), (1, 'Vendor ID', 'vendor'), (2, 'Service number', 'u')],
    16: [(0, 'Error', 'seq', ERROR), (1, 'First failed write', 'seq', [(0, 'Object', 'obj'), (1, 'Property', 'prop'),
                                                                     (2, 'Array index', 'u')])],
}


class _Full(Exception):
    pass


# ---------------------------------------------------------------- formatting --
def _date(b):
    if len(b) != 4:
        return '?'
    y = '*' if b[0] == 255 else str(b[0] + 1900)
    m = '*' if b[1] == 255 else ('even months' if b[1] == 14 else 'odd months' if b[1] == 13 else f'{b[1]:02d}')
    dd = '*' if b[2] == 255 else ('last day' if b[2] == 32 else f'{b[2]:02d}')
    wd = DAYS[b[3]] if 1 <= b[3] <= 7 else ''
    return f'{y}-{m}-{dd}' + (f' ({wd})' if wd else '')


def _time(b):
    if len(b) != 4:
        return '?'
    p = ['*' if x == 255 else f'{x:02d}' for x in b]
    return f'{p[0]}:{p[1]}:{p[2]}' + ('' if b[3] in (0, 255) else f'.{b[3]:02d}')


def _signed(b):
    x = C.num(b)
    if b and b[0] & 128:
        x -= 256 ** len(b)
    return x


def _bits(b, names):
    if not b:
        return ''
    unused = b[0]
    bits = [(b[1 + i // 8] >> (7 - i % 8)) & 1 for i in range((len(b) - 1) * 8 - unused)]
    if names:
        on = [names[i] if i < len(names) else f'bit {i}' for i, v in enumerate(bits) if v]
        return ', '.join(on) if on else 'none set'
    return ''.join(map(str, bits)) or '(empty)'


def _named(table, n):
    nm = table.get(n) if table else None
    return f'{nm} ({n})' if nm else str(n)


def _units(n):
    try:
        import bi_explore as E
        u = E.EXU.get(n)
    except ImportError:
        u = None
    return f'{u} ({n})' if u else f'units {n}'


def _prop(n):
    try:
        import bi_explore as E
        nm = E.PROPS.get(n)
    except ImportError:
        nm = None
    return f'{nm or C.PR.get(n) or "proprietary property"} ({n})'


def _vendor(n):
    nm = C.VN.get(n)
    return f'{nm} ({n})' if nm else str(n)


def _fmt(kind, b, extra=None, t0=0, app=False):
    """A primitive value of a known meaning."""
    if kind == 'u':
        return str(C.num(b))
    if kind == 'i':
        return str(_signed(b))
    if kind == 'bool':
        return 'yes' if (t0 & 1 if app else (b[0] if b else 0)) else 'no'
    if kind == 'real':
        return C.jsnum(float('%.7g' % struct.unpack('>f', bytes(b))[0])) if len(b) == 4 else '?'
    if kind == 'str':
        enc = b[0] if b else 0
        codec = 'utf-16-be' if enc == 4 else 'latin-1' if enc == 5 else 'utf-8'
        return '"' + bytes(b[1:]).decode(codec, errors='replace') + '"'
    if kind in ('oid', 'obj'):
        return C.objname(C.num(b))
    if kind == 'prop':
        return _prop(C.num(b))
    if kind == 'otype':
        return f'{C.tyname(C.num(b))} ({C.num(b)})'
    if kind == 'enum':
        return _named(extra, C.num(b))
    if kind == 'bits':
        return _bits(b, extra)
    if kind == 'secs':
        n = C.num(b)
        return f'{n} s' + (' (no expiry)' if n == 0 else f' ({n // 60} min)' if n >= 120 else '')
    if kind == 'mins':
        n = C.num(b)
        return 'indefinitely' if n == 0 else f'{n} min'
    if kind == 'bytes':
        return f'{C.num(b)} bytes'
    if kind == 'vendor':
        return _vendor(C.num(b))
    if kind == 'date':
        return _date(b)
    if kind == 'time':
        return _time(b)
    if kind == 'hex':
        return ' '.join(f'{x:02x}' for x in b[:32]) + (' …' if len(b) > 32 else '') + f' ({len(b)} bytes)'
    return '0x' + bytes(b).hex()


def _app_value(d, a, t0, ctx):
    """An application-tagged value, named with what we know about the property it belongs to."""
    b = d[a.v:a.v + a.len]
    n = a.n
    prop, ot = ctx.get('prop'), ctx.get('ot')
    if n == 9:
        x = C.num(b)
        if prop in BINARY_VALUE_PROPS and ot in BINARY_TYPES:
            return _named(BINARY_PV, x)
        if prop == 117:
            return _units(x)
        if prop == 79:
            return f'{C.tyname(x)} ({x})'
        return _named(PROP_ENUM.get(prop) or {}, x)
    if n == 8:
        return _bits(b, PROP_BITS.get(prop))
    if n == 10:
        return _date(b)
    if n == 11:
        return _time(b)
    if n == 2 and prop == 120:
        return _vendor(C.num(b))
    if n == 6:
        return _fmt('hex', b)
    return C.pv(d, a, t0)


# a trend log record's value: [1] is a choice of these
LOG_DATUM = {0: ('log status', 'bits', ['log-disabled', 'buffer-purged', 'log-interrupted']), 1: ('', 'bool', None),
             2: ('', 'real', None), 3: ('', 'u', None), 4: ('', 'u', None), 5: ('', 'i', None), 6: ('', 'bits', None),
             7: ('', 'null', None), 9: ('time change', 'real', None)}


def _merge_dt(rows):
    """A date followed by a time is shown as one value."""
    out = []
    for r in rows:
        if out and out[-1][2] == 10 and r[2] == 11 and not out[-1][1] and not r[1]:
            p = out.pop()
            out.append(([p[0][0], f'{p[0][1]} {r[0][1]}'], [], 'dt'))
        else:
            out.append(r)
    return out


# ------------------------------------------------------------------- walkers --
def _add(out, lvl, text, ctx):
    if len(out) >= MAX_ROWS:
        out.append([lvl, '… (more – the message is too long to show in full)'])
        raise _Full
    out.append([lvl, text])


def _values(d, k, L, lvl, ctx, parent=None):
    """Application-tagged values up to the closing tag.
    Returns (index after the closing tag, [((level, text), sub-rows, tag type)])."""
    rows = []
    log = ctx.get('prop') == 131                      # log-buffer: trend log records
    while k < L:
        t0 = d[k]
        a = C.tg(d, k)
        if a.cx and a.o == 2:
            k = a.v
            break
        if a.cx and a.o == 1:                         # a constructed part inside the value, e.g. [2] date-time
            k, inner = _values(d, a.v, L, lvl + 1, ctx, a.n)
            if len(inner) == 1 and not inner[0][1]:
                rows.append(([lvl, f'[{a.n}] {inner[0][0][1]}'], [], ('cx', a.n)))
            else:
                rows.append(([lvl, f'[{a.n}]'], inner, ('cx', a.n)))
            continue
        if a.cx:
            b = d[a.v:a.v + a.len]
            if log and parent == 1 and a.n in LOG_DATUM:
                what, kind, names = LOG_DATUM[a.n]
                text = 'null' if kind == 'null' else _fmt(kind, b, names)
                text = f'{what}: {text}' if what else text
            elif log and parent is None and a.n == 2:
                text = 'flags: ' + _bits(b, STATUS_FLAGS)
            else:
                text = f'[{a.n}] ' + (str(C.num(b)) if a.len <= 4 else _fmt('hex', b))
            rows.append(([lvl, text], [], ('cx', a.n)))
            k = a.v + a.len
            continue
        rows.append(([lvl, _app_value(d, a, t0, ctx)], [], a.n))
        k = a.v + a.len
    rows = _merge_dt(rows)
    if log and parent is None:
        rows = _log_records(rows)
    return k, rows


def _log_records(rows):
    """[0] time, [1] value, [2] flags  ->  '2026-10-06 10:26:54 = 61.3'."""
    out = []
    i = 0
    while i < len(rows):
        r = rows[i]
        if r[2] == ('cx', 0) and not r[1] and i + 1 < len(rows) and rows[i + 1][2] == ('cx', 1):
            when = r[0][1][4:]
            nxt = rows[i + 1]
            val = nxt[0][1][4:] if not nxt[1] else '…'
            i += 2
            if i < len(rows) and rows[i][2] == ('cx', 2):
                fl = rows[i][0][1]
                val += '' if fl.endswith('none set') else f' ({fl})'
                i += 1
            out.append(([r[0][0], f'{when} = {val}'], [], 'rec'))
        else:
            out.append(r)
            i += 1
    return out


def _emit_value(label, d, k, L, lvl, out, ctx):
    """A property value: one line when it is a single value, otherwise a numbered list."""
    k, rows = _values(d, k, L, lvl + 1, ctx)
    if ctx.get('prop') == 131 and len(rows) > 1:
        label += ' – log records'
    if len(rows) == 1 and not rows[0][1]:
        _add(out, lvl, f'{label}: {rows[0][0][1]}', ctx)
        ctx.setdefault('pairs', []).append((ctx.get('prop'), rows[0][0][1]))
    else:
        _add(out, lvl, f'{label} ({len(rows)} items)' if len(rows) > 1 else f'{label}: (empty)' if not rows else label, ctx)
        _flush(rows, out, ctx, number=len(rows) > 1)
    return k


def _flush(rows, out, ctx, number=False):
    for i, (row, sub, _t) in enumerate(rows):
        lvl, text = row
        _add(out, lvl, f'{i + 1}: {text}' if number and not text.startswith('[') else text, ctx)
        _flush(sub, out, ctx)


def _walk(d, k, L, spec, lvl, out, ctx):
    """Context / application tags of one service (or one constructed field) up to a closing tag or the end."""
    by_tag = {f[0]: f for f in spec if f[0] is not None}
    app = [f for f in spec if f[0] is None]
    ai = 0
    while k < L:
        t0 = d[k]
        a = C.tg(d, k)
        if a.cx and a.o == 2:
            return a.v
        if a.cx:
            f = by_tag.get(a.n)
        else:
            f = app[ai] if ai < len(app) else None
            ai += 1
        label = f[1] if f else (f'[{a.n}]' if a.cx else 'Value')
        kind = f[2] if f else None
        if a.cx and a.o == 1:                          # opening tag: a structure, a list or a property value
            if kind == 'seq':
                _add(out, lvl, label, ctx)
                k = _walk(d, a.v, L, f[3], lvl + 1, out, ctx)
            else:
                k = _emit_value(label, d, a.v, L, lvl, out, ctx)
            continue
        b = d[a.v:a.v + a.len]
        if kind and kind not in ('seq', 'value'):
            text = _fmt(kind, b, f[3] if len(f) > 3 else None, t0, app=not a.cx)
        elif not a.cx:
            text = _app_value(d, a, t0, ctx)
        else:
            text = str(C.num(b)) if a.len <= 4 else _fmt('hex', b)
        if kind == 'prop':
            ctx['prop'] = C.num(b)
        elif kind == 'obj':
            ctx['ot'] = C.num(b) // 4194304
            ctx['obj'] = text
        _add(out, lvl, f'{label}: {text}', ctx)
        k = a.v + a.len
    return k


# --------------------------------------------------------------------- APDU --
def _service(t, sv):
    names = C.UNC if t == 1 else C.CSV
    nm = (names.get(sv) or [None])[0]
    return f'{nm} ({sv})' if nm else f'service {sv}'


def _decode(d, L, i):
    """(rows, ctx) for the APDU starting at d[i]."""
    t = d[i] >> 4
    seg = bool(d[i] & 8)
    out = []
    ctx = {}
    spec = k = None
    if t == 0:
        b = d[i + 1]
        out.append([1, 'Segmented response accepted: ' + ('yes' if d[i] & 2 else 'no')])
        ma = b & 15
        out.append([1, f"Max response size: {MAX_APDU[ma] if ma < len(MAX_APDU) else '?'} bytes, max segments: "
                       f'{MAX_SEGS[b >> 4 & 7]}'])
        out.append([1, f'Invoke ID: {d[i + 2]}'])
        if seg:
            out.append([1, f"Segment: #{d[i + 3]}, window {d[i + 4]}{', more follow' if d[i] & 4 else ', last'}"])
        sv = d[i + 5] if seg else d[i + 3]
        out.append([1, 'Service: ' + _service(0, sv)])
        spec, k = REQUEST.get(sv), (i + 6 if seg else i + 4)
        if seg and d[i + 3]:
            spec = None                                # only the first segment starts at the beginning
    elif t == 1:
        sv = d[i + 1]
        out.append([1, 'Service: ' + _service(1, sv)])
        spec, k = UNCONFIRMED.get(sv), i + 2
    elif t == 2:
        out += [[1, f'Invoke ID: {d[i + 1]}'], [1, 'Service: ' + _service(0, d[i + 2])]]
    elif t == 3:
        out.append([1, f'Invoke ID: {d[i + 1]}'])
        if seg:
            out.append([1, f"Segment: #{d[i + 2]}, window {d[i + 3]}{', more follow' if d[i] & 4 else ', last'}"])
        sv = d[i + 4] if seg else d[i + 2]
        out.append([1, 'Service: ' + _service(0, sv)])
        spec, k = ACK.get(sv), (i + 5 if seg else i + 3)
        if seg and d[i + 2]:
            spec = None
    elif t == 4:
        out += [[1, f'Invoke ID: {d[i + 1]}'], [1, f'Segment acknowledged: #{d[i + 2]}, window {d[i + 3]}'],
                [1, 'Sent by: ' + ('the server' if d[i] & 1 else 'the client') + (' – asks for a resend' if d[i] & 2 else '')]]
    elif t == 5:
        sv = d[i + 2]
        out += [[1, f'Invoke ID: {d[i + 1]}'], [1, 'Service: ' + _service(0, sv)]]
        spec, k = ERROR_PDU.get(sv, ERROR), i + 3
    elif t == 6:
        out += [[1, f'Invoke ID: {d[i + 1]}'], [1, f"Reject reason: {_named(C.RR, d[i + 2])}"]]
    elif t == 7:
        out += [[1, f'Invoke ID: {d[i + 1]}'], [1, f"Abort reason: {_named(C.AR, d[i + 2])}"],
                [1, 'Sent by: ' + ('the server' if d[i] & 1 else 'the client')]]
    if k is not None and k < L:
        try:
            _walk(d, k, L, spec or [], 1, out, ctx)
        except _Full:
            pass
        except (IndexError, ValueError, struct.error):
            out.append([1, '(the rest of the message could not be decoded)'])
    return out, ctx


def apdu_rows(d, L, i):
    try:
        return _decode(d, L, i)[0]
    except (IndexError, ValueError, struct.error):
        return [[1, '(the message could not be decoded)']]


def cov_summary(d, L, i):
    """'analog-input 1: present-value = 72.5, status-flags = none set' for a COV notification (Info column)."""
    try:
        _, ctx = _decode(d, L, i)
    except (IndexError, ValueError, struct.error):
        return ''
    pairs = ctx.get('pairs') or []
    vals = ', '.join(f'{(_prop(p).rsplit(" (", 1)[0]) if p is not None else "value"} = {v}' for p, v in pairs[:3])
    return (ctx.get('obj') or '') + (': ' + vals if vals else '') + (' …' if len(pairs) > 3 else '')

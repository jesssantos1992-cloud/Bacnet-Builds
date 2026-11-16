"""
bi_site.py - reading a site from its devices, with no user interface: trend log history (Read Range), schedules
(weekly and exception schedules), device clocks, and the site health audit (points out of service, in fault, in
alarm or overridden, switched-off trend logs, wrong clocks), and every active command for the site-wide override list.
It runs on the Discover engine (bi_explore.Explorer) and its guarded send path: reading needs nothing, while setting a
clock and writing a schedule or calendar only work while write access is switched on, and are recorded in the write log.
"""
from __future__ import annotations

import re
import struct
import time

import bi_core as C
import bi_explore as E

LOG_BUFFER, RECORD_COUNT = 131, 141
REL = {0: 'no fault detected', 1: 'no sensor', 2: 'over range', 3: 'under range', 4: 'open loop', 5: 'shorted loop',
       6: 'no output', 7: 'unreliable (other)', 8: 'process error', 9: 'multi-state fault', 10: 'configuration error',
       12: 'communication failure', 13: 'member fault', 14: 'monitored object fault', 15: 'tripped'}
SYSTEM_STATUS = {0: 'operational', 1: 'operational, read-only', 2: 'download required', 3: 'download in progress',
                 4: 'non-operational', 5: 'backup in progress'}
DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
SKIP_TYPES = {6, 8, 10, 11, 15}           # calendars, devices, files, groups, notification classes: no status to check
SEV = {'fault': 'SERIOUS', 'noanswer': 'SERIOUS', 'status': 'SERIOUS', 'alarm': 'WARNING', 'oos': 'WARNING',
       'override': 'WARNING', 'clock': 'WARNING', 'trend': 'NOTE'}
KIND = {'fault': 'In fault', 'alarm': 'In alarm', 'oos': 'Out of service', 'override': 'Overridden', 'trend': 'Trend log off',
        'clock': 'Clock wrong', 'status': 'Device not operational', 'noanswer': 'Did not answer'}


# ---------------------------------------------------------------- encoding --
def app_unsigned(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), 'big')
    return [0x20 | len(b), *b]


def app_signed(v):
    n = 1
    while not -(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1)):
        n += 1
    return [0x30 | n, *v.to_bytes(n, 'big', signed=True)]


def read_range(o, start, count, prop=LOG_BUFFER):
    """Read Range by position: `count` records from position `start` (1 = the oldest)."""
    return [0, 5, 0, 26, 0x0C, *E.be4(o), 0x19, prop, 0x3E, *app_unsigned(start), *app_signed(count), 0x3F]


# ---------------------------------------------------------------- decoding --
def when(date, tm):
    """BACnet date and time bytes to a timestamp, or None when a field is a wildcard."""
    y, mo, d = date[0], date[1], date[2]
    h, mi, s, hs = tm
    if 255 in (y, mo, d, h, mi) or not 1 <= mo <= 12 or not 1 <= d <= 31:
        return None
    try:
        return time.mktime((1900 + y, mo, d, h, mi, s if s != 255 else 0, 0, 0, -1)) + (hs / 100 if hs != 255 else 0)
    except (OverflowError, ValueError):
        return None


def hhmm(tm):
    h, mi = tm[0], tm[1]
    if h == 255:
        return 'any time'
    return f'{h:02d}:{mi:02d}' if mi != 255 else f'{h:02d}:**'


def day_text(b):
    y, mo, d, dw = b[0], b[1], b[2], b[3]
    if 255 in (y, mo, d):
        parts = [DAYS[dw - 1] if 1 <= dw <= 7 else '', f'{d}' if d != 255 else '', '' if mo == 255 else
                 ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][mo] if mo <= 12 else '',
                 'every year' if y == 255 else str(1900 + y)]
        return ' '.join(p for p in parts if p) or 'any day'
    return f'{1900 + y}-{mo:02d}-{d:02d}'


def _value(d, pos, binary=False):
    """(text, number) of the primitive application-tagged value whose tag starts at d[pos]."""
    a = C.tg(d, pos)
    s = C.pv(d, a, d[pos])
    n = a.n
    if n == 0:
        return 'relinquish', None
    if n == 1:
        return s, 1.0 if s == 'true' else 0.0
    if n in (2, 3, 4, 5, 9):
        try:
            v = float(s)
        except ValueError:
            return s, None
        if n == 9 and binary:
            return ('active' if v == 1 else 'inactive'), v
        return s, v
    if n == 7:
        return E.unq(s), None
    return s, None


def parse_range_ack(d, k, L, binary=False):
    """ReadRange-ACK: (records, more). A record is (time, text, number or None, status) and status is '' or what the
    log noted instead of a value (for example 'log disabled')."""
    recs, more = [], False
    end = L
    while k < end:
        a = C.tg(d, k)
        if a.cx and a.n == 3 and a.o == 0:                       # result flags: first, last, more
            bits = d[a.v + 1] if a.len >= 2 else 0
            more = bool(bits & 0x20)
            k = a.v + a.len
        elif a.cx and a.n == 5 and a.o == 1:
            k = a.v
            while k < end:
                b = C.tg(d, k)
                if b.cx and b.n == 5 and b.o == 2:
                    k = b.v
                    break
                k = _record(d, k, end, recs, binary)
                if k is None:
                    return recs, more
        elif a.o == 1:
            k = C.skip(d, k + 1, end)
        else:
            k = a.v + a.len
    return recs, more


def _record(d, k, end, out, binary):
    a = C.tg(d, k)                                            # [0] timestamp
    if not (a.cx and a.n == 0 and a.o == 1):
        return None
    da = C.tg(d, a.v)
    ti = C.tg(d, da.v + da.len)
    t = when(d[da.v:da.v + 4], d[ti.v:ti.v + 4]) if da.n == 10 and ti.n == 11 else None
    k = ti.v + ti.len
    c = C.tg(d, k)                                            # closing [0]
    k = c.v
    a = C.tg(d, k)                                            # [1] log datum
    if not (a.cx and a.n == 1 and a.o == 1):
        return None
    v = C.tg(d, a.v)
    txt, num, status = '', None, ''
    if v.o == 1:                                              # failure or "any": skip it
        status = 'error' if v.n == 8 else ''
        k = C.skip(d, a.v + 1, end)
        txt = 'device reported an error' if v.n == 8 else '(value)'
        c = C.tg(d, k)
        k = c.v
    else:
        raw = d[v.v:v.v + v.len]
        if v.n == 0:                                          # log status
            bits = raw[1] if len(raw) > 1 else 0
            status = ', '.join(x for x, m in (('log disabled', 0x80), ('buffer purged', 0x40), ('log interrupted', 0x20))
                               if bits & m) or 'log status'
            txt = status
        elif v.n == 1:
            num = 1.0 if raw and raw[0] else 0.0
            txt = 'true' if num else 'false'
        elif v.n == 2:
            num = struct.unpack('>f', bytes(raw))[0] if len(raw) == 4 else None
            txt = f'{num:.6g}' if num is not None else '?'
        elif v.n in (3, 4):
            num = float(C.num(raw))
            txt = (('active' if num == 1 else 'inactive') if binary and v.n == 3 else str(int(num)))
        elif v.n == 5:
            x = C.num(raw)
            if raw and raw[0] & 128:
                x -= 256 ** len(raw)
            num, txt = float(x), str(x)
        elif v.n == 7:
            txt, status = 'null', 'null'
        elif v.n == 9:
            txt, status = 'clock changed', 'time change'
        else:
            txt = '(value)'
        k = v.v + v.len
        c = C.tg(d, k)                                        # closing [1]
        k = c.v
    if k < end:
        a = C.tg(d, k)
        if a.cx and a.n == 2 and a.o == 0:                    # [2] status flags
            k = a.v + a.len
    if t is not None:
        out.append((t, txt, num, status))
    return k


def time_values(d, k, end, close_tag, binary):
    """App-tagged (time, value) pairs until the closing context tag `close_tag`: [(HH:MM, text)], next index."""
    out = []
    while k < end:
        a = C.tg(d, k)
        if a.cx and a.n == close_tag and a.o == 2:
            return out, a.v
        if a.n == 11 and not a.cx:
            tm = d[a.v:a.v + 4]
            pos = a.v + a.len
            b = C.tg(d, pos)
            if b.cx or b.o:
                return out, None
            out.append((hhmm(tm), _value(d, pos, binary)[0]))
            k = b.v + b.len
        else:
            return out, None
    return out, None


def parse_weekly(items_d, k, end, binary):
    """weekly-schedule (inside the property value): seven lists of (time, value), Monday first."""
    week = []
    while k < end and len(week) < 7:
        a = C.tg(items_d, k)
        if not (a.cx and a.n == 0 and a.o == 1):
            break
        tv, k = time_values(items_d, a.v, end, 0, binary)
        if k is None:
            break
        week.append(tv)
    return week


def parse_exceptions(d, k, end, binary):
    """exception-schedule: [{'when': text, 'tv': [(time, value)], 'pri': n, 'raw': the special event's bytes}]."""
    out = []
    while k < end:
        a = C.tg(d, k)
        if a.cx and a.n == 3 and a.o == 2:                    # end of the property value
            break
        start = k
        ev = {'when': '?', 'tv': [], 'pri': ''}
        if a.cx and a.n == 0 and a.o == 1:                    # a calendar entry
            b = C.tg(d, a.v)
            if b.cx and b.n == 0 and b.o == 0:
                ev['when'] = day_text(d[b.v:b.v + 4])
                k = b.v + b.len
            elif b.cx and b.n == 1 and b.o == 1:
                x = C.tg(d, b.v)
                y = C.tg(d, x.v + x.len)
                ev['when'] = f"{day_text(d[x.v:x.v + 4])} to {day_text(d[y.v:y.v + 4])}"
                k = C.tg(d, y.v + y.len).v
            elif b.cx and b.n == 2 and b.o == 0:
                mo, wk, dw = d[b.v], d[b.v + 1], d[b.v + 2]
                ev['when'] = ' '.join(p for p in [
                    {1: '1st', 2: '2nd', 3: '3rd', 4: '4th', 5: '5th', 6: 'last'}.get(wk, ''), DAYS[dw - 1] if 1 <= dw <= 7 else 'day',
                    'of ' + ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][mo] if 1 <= mo <= 12
                    else 'of every month'] if p)
                k = b.v + b.len
            else:
                return out
            c = C.tg(d, k)                                    # closing [0]
            k = c.v
        elif a.cx and a.n == 1 and a.o == 0:                  # a calendar object
            ev['when'] = 'calendar ' + str(E.o_i(C.num(d[a.v:a.v + 4])))
            k = a.v + a.len
        else:
            return out
        b = C.tg(d, k)
        if b.cx and b.n == 2 and b.o == 1:
            ev['tv'], k = time_values(d, b.v, end, 2, binary)
            if k is None:
                return out
        b = C.tg(d, k)
        if b.cx and b.n == 3 and b.o == 0:
            ev['pri'] = C.num(d[b.v:b.v + b.len])
            k = b.v + b.len
        ev['raw'] = bytes(d[start:k])
        out.append(ev)
    return out


def parse_date_list(d, k, end):
    """A calendar's date-list: [{'when': text, 'raw': the entry's bytes}]."""
    out = []
    while k < end:
        a = C.tg(d, k)
        if a.cx and a.n == 3 and a.o == 2:
            break
        start = k
        if a.cx and a.n == 0 and a.o == 0:                    # [0] date
            when = day_text(d[a.v:a.v + 4])
            k = a.v + a.len
        elif a.cx and a.n == 1 and a.o == 1:                  # [1] date range
            x = C.tg(d, a.v)
            y = C.tg(d, x.v + x.len)
            when = f"{day_text(d[x.v:x.v + 4])} to {day_text(d[y.v:y.v + 4])}"
            k = C.tg(d, y.v + y.len).v
        elif a.cx and a.n == 2 and a.o == 0:                  # [2] week and day
            mo, wk, dw = d[a.v], d[a.v + 1], d[a.v + 2]
            when = ' '.join(p for p in [
                {1: '1st', 2: '2nd', 3: '3rd', 4: '4th', 5: '5th', 6: 'last'}.get(wk, 'every'), DAYS[dw - 1] if 1 <= dw <= 7 else 'day',
                'of ' + ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][mo] if 1 <= mo <= 12
                else 'of every month'] if p)
            k = a.v + a.len
        else:
            return out
        out.append({'when': when, 'raw': bytes(d[start:k])})
    return out


# ---------------------------------------------------------- schedule edits --
def _date_bytes(y, m, d):
    """BACnet date (year - 1900, month, day, day of week)."""
    import datetime
    return [y - 1900, m, d, datetime.date(y, m, d).isoweekday()]


def enc_value(txt, vt, binary=False):
    """A schedule value typed by the user -> application-tagged bytes for the schedule's value type `vt`
    (the BACnet application tag number: 1 boolean, 2 unsigned, 3 signed, 4 real, 5 double, 9 enumerated).
    'relinquish' or 'null' writes NULL. None when the text does not fit the type."""
    s = str(txt).strip().lower()
    if s in ('relinquish', 'null', 'release'):
        return [0x00]
    if binary or vt == 9:
        n = {'active': 1, 'on': 1, 'inactive': 0, 'off': 0}.get(s)
        if n is None:
            try:
                n = int(s)
            except ValueError:
                return None
        if not 0 <= n <= 65535:
            return None
        return [0x91, n] if n < 256 else [0x92, n >> 8, n & 255]
    try:
        if vt == 1:
            return [0x11] if s in ('true', '1', 'on', 'active') else [0x10] if s in ('false', '0', 'off', 'inactive') else None
        if vt == 2:
            n = int(s)
            return app_unsigned(n) if n >= 0 else None
        if vt == 3:
            return app_signed(int(s))
        if vt == 5:
            return [0x55, 8, *struct.pack('>d', float(s))]
        f = float(s)
        if f != f or f in (float('inf'), float('-inf')):
            return None
        return [0x44, *struct.pack('>f', f)]
    except ValueError:
        return None


def parse_changes(text, vt, binary=False):
    """'07:00 active, 18:00 inactive' -> [(h, m, value bytes)] sorted by time, or raises ValueError with a reason."""
    out = []
    for part in re.split(r'[,;\n]+', text or ''):
        part = part.strip()
        if not part:
            continue
        m = re.match(r'^(\d{1,2}):(\d{2})(?::(\d{2}))?\s+(.+)$', part)
        if not m:
            raise ValueError(f'“{part}” – write a time and a value, for example 07:00 active')
        h, mi, s = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
        if h > 23 or mi > 59 or s > 59:
            raise ValueError(f'“{part}” – the time is not valid')
        v = enc_value(m.group(4), vt, binary)
        if v is None:
            raise ValueError(f'“{m.group(4).strip()}” is not a valid value for this schedule')
        out.append((h, mi, s, v))
    out.sort(key=lambda x: x[:3])
    return out


def _tv_bytes(changes):
    return [b for h, mi, s, v in changes for b in [0xB4, h, mi, s, 0, *v]]


def enc_week(days):
    """weekly-schedule value: seven parsed day lists (Monday first)."""
    return [b for ch in days for b in [0x0E, *_tv_bytes(ch), 0x0F]]


def enc_special_event(start, end, changes, pri):
    """An exception: one date (end None) or a date range, its changes, and its priority (1-16)."""
    if end is None or end == start:
        period = [0x0E, 0x0C, *_date_bytes(*start), 0x0F]
    else:
        period = [0x0E, 0x1E, 0xA4, *_date_bytes(*start), 0xA4, *_date_bytes(*end), 0x1F, 0x0F]
    return bytes(period + [0x2E, *_tv_bytes(changes), 0x2F, 0x39, pri])


def enc_date_entry(start, end=None):
    """A calendar date-list entry: one date or a date range."""
    if end is None or end == start:
        return bytes([0x0C, *_date_bytes(*start)])
    return bytes([0x1E, 0xA4, *_date_bytes(*start), 0xA4, *_date_bytes(*end), 0x1F])


def fits(dev, apdu):
    """Does a request fit in one message to this device (no segmenting)? Leaves room for the network header."""
    return len(apdu) + 24 <= (dev.get('mx') or 480)


def write_schedule(ex, dev, o, week=None, exc=None):
    """Write a schedule's weekly-schedule (seven parsed days) and/or exception-schedule (a list of special-event bytes).
    Returns (ok, message)."""
    msgs = []
    for prop, val, what in ((123, enc_week(week) if week is not None else None, 'weekly schedule'),
                            (38, [b for ev in exc for b in ev] if exc is not None else None, 'exceptions')):
        if val is None:
            continue
        apdu = E.ex_wp(o, val, None, prop)
        if not fits(dev, apdu):
            return False, f'The {what} are too long to send to this device in one message ({len(apdu)} bytes). Remove some entries.'
        ok, msg = ex.write_prop(dev, o, prop, val, f"schedule {E.o_i(o)} · {what}",
                                f'{what} written' + (f" ({sum(len(d) for d in week)} changes)" if prop == 123 else
                                                     f' ({len(exc)} entries)'))
        if not ok:
            return False, f'The {what}: {msg}'
        msgs.append(f'{what.capitalize()} saved.')
    return True, ' '.join(msgs) or 'Nothing to save.'


def calendar(ex, dev, o):
    """{'name', 'pv': true/false (today is in the calendar), 'dates': [{'when','raw'}], 'err'}."""
    out = {'name': '', 'pv': '', 'dates': [], 'err': ''}
    r = ex.req(dev, E.ex_rpm([[o, [77, 85]]]), 5.0)
    if r.get('d'):
        L = E.ex_dec_rpm(r['d'], r['k'], r['L'])
        pr = L[0]['pr'] if L else {}
        nm, pv = _first(pr, 77), _first(pr, 85)
        out['name'] = E.unq(nm['s']) if nm else ''
        out['pv'] = pv['s'] if pv else ''
    else:
        out['err'] = _why(r)
        return out
    x = _prop_value(ex.rpc(dev, o, 23))
    if x:
        out['dates'] = parse_date_list(x[0], x[1], x[2])
    else:
        out['err'] = 'Could not read the date list.'
    return out


def write_calendar(ex, dev, o, entries):
    """Write a calendar's date-list (a list of entry bytes). Returns (ok, message)."""
    val = [b for e in entries for b in e]
    apdu = E.ex_wp(o, val, None, 23)
    if not fits(dev, apdu):
        return False, f'The date list is too long to send to this device in one message ({len(apdu)} bytes).'
    return ex.write_prop(dev, o, 23, val, f'calendar {E.o_i(o)} · date list', f'{len(entries)} dates written')


def _prop_value(r):
    """Where the value of a Read Property answer starts and ends: (d, start, end) or None."""
    if not r.get('d'):
        return None
    d, k, L = r['d'], r['k'], r['L']
    if d[k] != 0x0C:
        return None
    k += 5
    a = C.tg(d, k)
    k = a.v + a.len
    a = C.tg(d, k)
    if a.cx and a.n == 2 and not a.o:
        k = a.v + a.len
        a = C.tg(d, k)
    if not (a.cx and a.n == 3 and a.o == 1):
        return None
    return d, a.v, L


def _why(r):
    return 'No answer from the device.' if r.get('to') else (r.get('err') or 'The device could not answer.')


def _first(pr, p):
    v = pr.get(p)
    return v[0] if v else None


def _binary_ref(ex, dev, o):
    """What a trend log records: (binary point?, 'analog input 1 present-value', unit code or None).
    Binary points read 1 / 0 as active / inactive; the unit lets temperatures show in the unit chosen."""
    r = ex.rpc(dev, o, 132)
    x = _prop_value(r)
    if not x:
        return False, '', None
    d, k, L = x
    a = C.tg(d, k)
    if a.cx and a.n == 0 and a.len == 4:
        ob = C.num(d[a.v:a.v + 4])
        b = C.tg(d, a.v + 4)
        prop = C.num(d[b.v:b.v + b.len]) if b.cx and b.n == 1 else 85
        b2 = C.tg(d, b.v + b.len) if b.cx and b.n == 1 else None
        uc = None
        local = not (b2 and b2.cx and b2.n == 3 and b2.len == 4 and C.num(d[b2.v:b2.v + 4]) != E.oid(8, dev['id']))
        if E.o_t(ob) in (0, 1, 2) and prop == 85 and local:
            u = _prop_value(ex.rpc(dev, ob, 117))
            if u:
                t = C.tg(u[0], u[1])
                uc = C.num(u[0][t.v:t.v + t.len]) if t.n == 9 else None
        return 3 <= E.o_t(ob) <= 5, f"{E.sd_ty(E.o_t(ob))} {E.o_i(ob)} {E.prop_name(prop)}", uc
    return False, '', None


# ------------------------------------------------------------------- trend --
def trend(ex, dev, o, limit=2000, progress=None):
    """The newest `limit` records of a trend log: {'name','what','n','total','recs','enabled','interval','err'}."""
    out = {'name': '', 'what': '', 'recs': [], 'total': 0, 'enabled': None, 'interval': None, 'err': '', 'uc': None}
    r = ex.req(dev, E.ex_rpm([[o, [77, RECORD_COUNT, 133, 134, 126]]]), 5.0)
    if not r.get('d'):
        out['err'] = _why(r)
        return out
    L = E.ex_dec_rpm(r['d'], r['k'], r['L'])
    pr = L[0]['pr'] if L else {}
    nm, rc, en, iv = _first(pr, 77), _first(pr, RECORD_COUNT), _first(pr, 133), _first(pr, 134)
    out['name'] = E.unq(nm['s']) if nm else ''
    total = rc['raw'] if rc and rc['raw'] is not None else 0
    out['total'] = total
    out['enabled'] = (en['s'] == 'true') if en else None
    out['interval'] = iv['raw'] if iv else None
    binary, out['what'], out['uc'] = _binary_ref(ex, dev, o)
    if not total:
        return out
    per = max(4, min(60, ((dev.get('mx') or 480) - 40) // 26))
    pos = max(1, total - limit + 1)
    recs = []
    while pos <= total and not ex.stop:
        n = min(per, total - pos + 1)
        q = ex.req(dev, read_range(o, pos, n), 6.0)
        if (q.get('seg') or q.get('abort') or q.get('rej')) and per > 4:
            per = max(4, per // 2)
            continue
        if not q.get('d'):
            out['err'] = _why(q)
            break
        got, _more = parse_range_ack(q['d'], q['k'], q['L'], binary)
        if not got:
            break
        recs += got
        pos += max(1, n)
        if progress:
            progress(len(recs), min(limit, total))
    recs.sort(key=lambda x: x[0])
    out['recs'] = recs
    return out


# ---------------------------------------------------------------- schedule --
def schedule(ex, dev, o):
    """{'name','pv','default','period','week': [7 lists of (time, value)], 'exc': [...], 'refs', 'err',
    'vt': the application tag of its values (for writing), 'binary'}."""
    out = {'name': '', 'pv': '', 'default': '', 'period': '', 'week': [], 'exc': [], 'refs': 0, 'err': '', 'vt': 4,
           'binary': False}
    r = ex.req(dev, E.ex_rpm([[o, [77, 85, 174, 32]]]), 5.0)
    if r.get('d'):
        L = E.ex_dec_rpm(r['d'], r['k'], r['L'])
        pr = L[0]['pr'] if L else {}
        nm, pv, df, ep = _first(pr, 77), _first(pr, 85), _first(pr, 174), pr.get(32)
        out['name'] = E.unq(nm['s']) if nm else ''
        out['pv'] = pv['s'] if pv else ''
        out['default'] = df['s'] if df else ''
        if ep and len(ep) >= 2:
            def dt(s):
                return 'any' if s.startswith('2155') else s
            out['period'] = f"{dt(ep[0]['s'])} to {dt(ep[1]['s'])}"
    else:
        out['err'] = _why(r)
        return out
    binary = out['pv'] in ('active', 'inactive') or (pv is not None and pv['n'] == 9 and out['pv'] in ('0', '1'))
    out['binary'] = binary
    out['vt'] = next((x['n'] for x in (df, pv) if x is not None and x['n'] not in (0, None)), 4)
    if binary:
        out['pv'], out['default'] = ({'1': 'active', '0': 'inactive'}.get(x, x) for x in (out['pv'], out['default']))
    w = ex.rpc(dev, o, 123)
    x = _prop_value(w)
    if x:
        out['week'] = parse_weekly(x[0], x[1], x[2], binary)
    if len(out['week']) != 7:                                 # too long for one answer: one day at a time
        week = []
        for i in range(1, 8):
            y = _prop_value(ex.rpc(dev, o, 123, i))
            day = parse_weekly(y[0], y[1], y[2], binary) if y else []
            week.append(day[0] if day else [])
        out['week'] = week if any(week) or x is None else out['week']
    x = _prop_value(ex.rpc(dev, o, 38))
    if x:
        out['exc'] = parse_exceptions(x[0], x[1], x[2], binary)
    return out


# ------------------------------------------------------------------- clock --
def _dt_from_text(ds, ts):
    m = re.match(r'^(\d+)-(\d+)-(\d+)$', ds or '')
    n = re.match(r'^(\d+):(\d+):(\d+)', ts or '')
    if not m or not n or int(m.group(1)) >= 2155 or int(n.group(1)) > 23:
        return None
    try:
        return time.mktime((int(m.group(1)), int(m.group(2)), int(m.group(3)), int(n.group(1)), int(n.group(2)),
                            int(n.group(3)), 0, 0, -1))
    except (OverflowError, ValueError):
        return None


def clock(ex, dev):
    """The device's clock compared with this PC's: {'dev': time or None, 'off': seconds (+ = fast), 'text', 'bad', 'err'}."""
    t0 = time.time()
    r = ex.req(dev, E.ex_rpm([[E.oid(8, dev['id']), [56, 57, 119, 24]]]), 5.0)
    t1 = time.time()
    out = {'dev': None, 'off': None, 'text': '', 'bad': False, 'err': '', 'utc': None, 'dst': None}
    if not r.get('d'):
        out['err'] = _why(r)
        return out
    L = E.ex_dec_rpm(r['d'], r['k'], r['L'])
    pr = L[0]['pr'] if L else {}
    da, ti, uo, ds = _first(pr, 56), _first(pr, 57), _first(pr, 119), _first(pr, 24)
    if uo:
        out['utc'] = uo['s']
    if ds:
        out['dst'] = ds['s'] == 'true'
    t = _dt_from_text(da['s'] if da else '', ti['s'] if ti else '')
    if t is None:
        out['err'] = 'The device does not report its clock.' if not (da and ti) else 'The device clock is not set.'
        out['bad'] = bool(da and ti)
        out['text'] = out['err']
        return out
    out['dev'] = t
    off = t - (t0 + t1) / 2
    out['off'] = off
    out['text'], out['bad'] = clock_verdict(off)
    return out


def clock_verdict(off):
    """Plain words for a clock offset, and whether it is wrong (more than a minute out)."""
    a = abs(off)
    if a <= 60:
        return ('Correct (within a minute of this PC)', False)
    hrs = round(off / 3600)
    if hrs and abs(hrs) <= 14 and abs(off - hrs * 3600) <= 120:          # whole hours: a time zone or daylight saving slip
        return (f"{abs(hrs)} hour{'s' if abs(hrs) != 1 else ''} {'ahead' if hrs > 0 else 'behind'}: probably the time zone or "
                'daylight saving setting', True)
    if a < 3600:
        m = round(a / 60)
        return (f"{m} minute{'s' if m != 1 else ''} {'fast' if off > 0 else 'slow'}", True)
    if a < 86400 * 2:
        return (f"{a / 3600:.1f} hours {'fast' if off > 0 else 'slow'}", True)
    return (f"{round(a / 86400)} days {'fast' if off > 0 else 'slow'}: the clock was probably never set", True)


def sync_clock(ex, dev, utc=False):
    """Set the device clock to this PC's time (Time Synchronization, or UTC Time Synchronization), then read it back.
    Returns the clock() result with 'sent' (True when it went out) and 'err'."""
    try:
        ex.send_unconfirmed(dev, E.ex_time_sync(utc=utc))
    except RuntimeError as e:
        ex.log_cmd(dev, 'device clock', 'set to ' + ('UTC' if utc else 'local') + ' time', str(e))
        return {'sent': False, 'err': str(e), 'off': None, 'bad': True, 'text': str(e)}
    time.sleep(3.0 if E.is_mstp(dev) else 1.0)              # let the device apply it
    r = clock(ex, dev)
    r['sent'] = True
    res = 'no answer when read back' if r['err'] else ('clock correct' if not r['bad'] else 'still wrong: ' + r['text'])
    ex.log_cmd(dev, 'device clock', 'set to this PC’s ' + ('UTC' if utc else 'local') + ' time',
               'accepted' if not r['err'] and not r['bad'] else res, rb=r.get('text') or '')
    return r


# --------------------------------------------------------------- overrides --
def overrides(ex, devs, progress=None):
    """Every active command in every commandable point (priority array), for the site-wide release list.
    Returns {'at', 'items': [{'key','id','dname','o','ty','inst','name','pri','val','ctl','unit'}], 'errs', 'stopped'}."""
    ex.stop = False
    res = {'at': time.time(), 'items': [], 'errs': [], 'stopped': False, 'n': 0}
    for i, dev in enumerate(devs):
        if ex.stop:
            res['stopped'] = True
            break
        name = dev.get('name') or f"Device {dev['id']}"
        if progress:
            progress(i, len(devs), name, 0, 0)
        if not dev.get('objs') and not ex.read_objlist(dev, 1 if E.is_mstp(dev) else 3):
            res['errs'].append(f"{name}: {dev.get('pm') or 'could not read the object list'}")
            continue
        rows = [x for x in dev.get('objs') or [] if x['ty'] in E.CMD_T]
        res['n'] += len(rows)
        done = [0]

        def one(batch, dev=dev, name=name, i=i, rows=rows, done=done):
            r = ex.req(dev, E.ex_rpm([[x['o'], [77, 87, 117]] for x in batch]), 5.0)
            got = {e['o']: e['pr'] for e in E.ex_dec_rpm(r['d'], r['k'], r['L'])} if r.get('d') else {}
            for x in batch:
                pr = got.get(x['o'])
                if pr is None and not r.get('fatal'):
                    q = ex.req(dev, E.ex_rpm([[x['o'], [77, 87, 117]]]), 5.0)
                    L = E.ex_dec_rpm(q['d'], q['k'], q['L']) if q.get('d') else []
                    pr = L[0]['pr'] if L else None
                if not pr or not pr.get(87):
                    continue
                nm, u = _first(pr, 77), _first(pr, 117)
                if nm and not x.get('name'):
                    x['name'] = E.unq(nm['s'])
                if u and u['raw'] is not None:
                    x['uc'], x['u'] = u['raw'], E.EXU.get(u['raw'], '')
                first = True
                for p, v in enumerate(pr[87][:16]):
                    if v['n'] == 0:
                        continue
                    s = ('active' if v['raw'] == 1 else 'inactive') if 3 <= x['ty'] <= 5 and v['n'] == 9 else v['s']
                    res['items'].append({'key': dev['key'], 'id': dev['id'], 'dname': name, 'o': x['o'], 'ty': x['ty'],
                                         'inst': x['inst'], 'name': x.get('name') or f"{E.sd_ty(x['ty'])} {x['inst']}",
                                         'pri': p + 1, 'val': s, 'ctl': first, 'row': x, 'dev': dev})
                    first = False
            done[0] += len(batch)
            if progress:
                progress(i, len(devs), name, done[0], len(rows))
        per = 3 if (dev.get('mx') or 480) >= 1024 else 2
        ex.pool_map([rows[j:j + per] for j in range(0, len(rows), per)], 1 if E.is_mstp(dev) else 3, one)
    res['items'].sort(key=lambda x: (x['id'], x['ty'], x['inst'], x['pri']))
    res['stopped'] = res['stopped'] or ex.stop
    return res


# ------------------------------------------------------------------- audit --
def _bits(s):
    return [c == '1' for c in (s or '')] + [False] * 4


def check_object(row, pr):
    """Problems with one object, from its status flags, reliability, out-of-service, event state, priority array and
    (trend logs) enable: [(kind, detail)]."""
    out = []
    fl = _first(pr, 111)
    b = _bits(fl['s'] if fl else '')
    rel = _first(pr, 103)
    oos = _first(pr, 81)
    es = _first(pr, 36)
    if (rel and rel['raw'] not in (None, 0)) or b[1]:
        out.append(('fault', REL.get(rel['raw'], f"reliability {rel['raw']}") if rel and rel['raw'] not in (None, 0)
                    else 'the status flags say fault'))
    if (oos and oos['s'] == 'true') or b[3]:
        out.append(('oos', 'out of service: the value is not coming from the field' if row['ty'] in (0, 3, 13)
                    else 'out of service'))
    if es and es['raw'] not in (None, 0) and not (rel and rel['raw'] not in (None, 0) and es['raw'] == 1):
        out.append(('alarm', E.EVENT_STATE.get(es['raw'], f"event state {es['raw']}")))
    elif b[0] and not out:
        out.append(('alarm', 'the status flags say in alarm'))
    pa = pr.get(87)
    if pa:
        for i, v in enumerate(pa[:8]):
            if v['n'] != 0:
                s = ('active' if v['raw'] == 1 else 'inactive') if 3 <= row['ty'] <= 5 and v['n'] == 9 else v['s']
                out.append(('override', f"commanded at priority {i + 1} = {s}" + (' (manual operator)' if i == 7 else '')))
                break
    if b[2] and not any(k == 'override' for k, _ in out):
        out.append(('override', 'overridden by a hand switch or local override'))
    en = _first(pr, 133)
    if row['ty'] == 20 and en and en['s'] == 'false':
        out.append(('trend', 'the trend log is switched off, so it is not recording'))
    return out


def audit(ex, devs, clocks_only=False, progress=None):
    """Check every device in `devs` (and, unless clocks_only, every point in it).
    Returns {'at', 'devs': [{'key','id','name','clock','status','n','err'}], 'items': [...], 'stopped', 'clocks_only'}."""
    ex.stop = False
    res = {'at': time.time(), 'devs': [], 'items': [], 'stopped': False, 'clocks_only': clocks_only}
    for i, dev in enumerate(devs):
        if ex.stop:
            res['stopped'] = True
            break
        name = dev.get('name') or f"Device {dev['id']}"
        dr = {'key': dev['key'], 'id': dev['id'], 'name': name, 'clock': None, 'status': '', 'n': 0, 'err': ''}
        res['devs'].append(dr)

        def item(kind, detail, row=None):
            res['items'].append({'key': dev['key'], 'id': dev['id'], 'dname': name, 'o': row['o'] if row else None,
                                 'ty': row['ty'] if row else 8, 'inst': row['inst'] if row else dev['id'],
                                 'name': (row.get('name') or f"{E.sd_ty(row['ty'])} {row['inst']}") if row else name,
                                 'kind': kind, 'sev': SEV[kind], 'detail': detail})
        if progress:
            progress(i, len(devs), name, 0, 0)
        ck = clock(ex, dev)
        dr['clock'] = ck
        if ck['err'] == 'No answer from the device.':
            dr['err'] = ck['err']
            item('noanswer', 'the device did not answer; check it is powered and reachable')
            continue
        if ck['bad']:
            item('clock', ck['text'])
        if clocks_only:
            continue
        r = ex.req(dev, E.ex_rpm([[E.oid(8, dev['id']), [112]]]), 4.0)
        if r.get('d'):
            L = E.ex_dec_rpm(r['d'], r['k'], r['L'])
            st = _first(L[0]['pr'], 112) if L else None
            if st and st['raw'] is not None:
                dr['status'] = SYSTEM_STATUS.get(st['raw'], str(st['raw']))
                if st['raw'] not in (0, 1):
                    item('status', f"system status: {dr['status']}")
        if not dev.get('objs') and not ex.read_objlist(dev, 1 if E.is_mstp(dev) else 3):
            dr['err'] = dev.get('pm') or 'could not read the object list'
            continue
        rows = [x for x in dev.get('objs') or [] if x['ty'] not in SKIP_TYPES]
        dr['n'] = len(rows)
        per = 3 if (dev.get('mx') or 480) >= 1024 else 2

        def props(x):
            return [77, 111, 103, 81, 36] + ([87] if x['ty'] in E.CMD_T else []) + ([133] if x['ty'] == 20 else [])
        done = [0]

        def one(batch):
            r = ex.req(dev, E.ex_rpm([[x['o'], props(x)] for x in batch]), 5.0)
            got = {e['o']: e['pr'] for e in E.ex_dec_rpm(r['d'], r['k'], r['L'])} if r.get('d') else {}
            for x in batch:
                pr = got.get(x['o'])
                if pr is None and not r.get('fatal'):
                    q = ex.req(dev, E.ex_rpm([[x['o'], props(x)]]), 5.0)
                    if q.get('seg') or q.get('rej') or q.get('abort'):
                        q = ex.req(dev, E.ex_rpm([[x['o'], [77, 111, 103, 81, 36]]]), 5.0)
                    L = E.ex_dec_rpm(q['d'], q['k'], q['L']) if q.get('d') else []
                    pr = L[0]['pr'] if L else None
                if pr is None:
                    continue
                nm = _first(pr, 77)
                if nm and not x.get('name'):
                    x['name'] = E.unq(nm['s'])
                for kind, detail in check_object(x, pr):
                    item(kind, detail, x)
            done[0] += len(batch)
            if progress:
                progress(i, len(devs), name, done[0], len(rows))
        ex.pool_map([rows[j:j + per] for j in range(0, len(rows), per)], 1 if E.is_mstp(dev) else 3, one)
        if ex.stop:
            res['stopped'] = True
            break
    order = {'SERIOUS': 0, 'WARNING': 1, 'NOTE': 2}
    res['items'].sort(key=lambda x: (order[x['sev']], x['id'], x['ty'], x['inst']))
    return res


def audit_counts(res):
    """{kind: number of items} for the summary."""
    out = {}
    for x in res['items']:
        out[x['kind']] = out.get(x['kind'], 0) + 1
    return out

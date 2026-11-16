"""
bi_history.py - Discover history, with no user interface: every discover (a scan and the reading that follows it) is
kept as a snapshot of its devices and points, so a later visit can look back, reopen it or compare. Snapshots are
gzip-compressed JSON files in the app's state folder, with a small index; only the newest N are kept (N is a setting,
0 = keep none).
"""
from __future__ import annotations

import gzip
import json
import os
import threading
import time

import bacnet_live as BL

DEV_KEYS = ('key', 'id', 'ip', 'port', 'route', 'sn', 'sa', 'mx', 'sg', 'vn', 'name', 'vendor', 'model', 'fw', 'sw',
            'desc', 'loc', 'via', 'mac', 'st')
OBJ_KEYS = ('o', 'ty', 'inst', 'name', 'val', 'u', 'uc', 'desc', 'states')
DETAILS = (('name', 'Name'), ('vendor', 'Manufacturer'), ('model', 'Model'), ('fw', 'Firmware'), ('sw', 'Software'),
           ('ip', 'Address'), ('loc', 'Location'), ('desc', 'Description'))
DEFAULT_KEEP = 10
_LOCK = threading.Lock()


def folder():
    d = os.path.join(BL.state_dir(), 'discover-history')
    os.makedirs(d, exist_ok=True)
    return d


def _index_path():
    return os.path.join(folder(), 'index.json')


def index():
    """The saved discovers, newest first: [{'id','at','mode','where','n','pts'}]."""
    try:
        with open(_index_path(), encoding='utf-8') as f:
            L = json.load(f)
        return sorted((x for x in L if isinstance(x, dict) and 'id' in x), key=lambda x: -x.get('at', 0))
    except (OSError, ValueError):
        return []


def _write_index(L):
    tmp = _index_path() + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(L, f)
    os.replace(tmp, _index_path())


def slim(devs):
    """The parts of the discovered devices worth keeping (no live state, alarms or point details)."""
    out = []
    for d in devs:
        x = {k: d.get(k) for k in DEV_KEYS if d.get(k) not in (None, '')}
        if isinstance(x.get('route'), dict):
            x['route'] = {'dnet': x['route'].get('dnet'), 'dadr': list(x['route'].get('dadr') or [])}
        if d.get('objs') is not None:
            x['objs'] = [{k: o.get(k) for k in OBJ_KEYS if o.get(k) not in (None, '')} for o in d['objs']]
        out.append(x)
    return out


def save(sid, devs, mode, where='', keep=DEFAULT_KEEP):
    """Save (or replace) snapshot `sid` with these devices, then drop all but the newest `keep`. Returns the id, or
    None when nothing was saved (history off, or no device answered)."""
    devs = [d for d in devs if d.get('name') or d.get('objs')]
    if keep <= 0 or not devs:
        return None
    with _LOCK:
        L = index()
        now = time.time()
        sid = sid or time.strftime('%Y%m%d-%H%M%S', time.localtime(now)) + f'-{int(now * 1000) % 1000:03d}'
        old = next((x for x in L if x['id'] == sid), None)
        meta = {'id': sid, 'at': old['at'] if old else now, 'upd': now, 'mode': mode, 'where': where, 'n': len(devs),
                'pts': sum(len(d.get('objs') or []) for d in devs)}
        body = json.dumps({'meta': meta, 'devs': slim(devs)}).encode('utf-8')
        p = os.path.join(folder(), sid + '.json.gz')
        with gzip.open(p + '.tmp', 'wb') as f:
            f.write(body)
        os.replace(p + '.tmp', p)
        L = [x for x in L if x['id'] != sid] + [meta]
        L.sort(key=lambda x: -x['at'])
        for x in L[keep:]:
            _remove_file(x['id'])
        _write_index(L[:keep])
        return sid


def load(sid):
    """{'meta', 'devs'} of one saved discover, or None."""
    try:
        with gzip.open(os.path.join(folder(), sid + '.json.gz'), 'rb') as f:
            return json.loads(f.read().decode('utf-8'))
    except (OSError, ValueError, EOFError):
        return None


def _remove_file(sid):
    try:
        os.remove(os.path.join(folder(), sid + '.json.gz'))
    except OSError:
        pass


def delete(ids):
    with _LOCK:
        ids = set(ids)
        for s in ids:
            _remove_file(s)
        _write_index([x for x in index() if x['id'] not in ids])


def prune(keep):
    """Keep only the newest `keep` (after the setting is lowered)."""
    with _LOCK:
        L = index()
        for x in L[max(0, keep):]:
            _remove_file(x['id'])
        _write_index(L[:max(0, keep)])


def _dev_name(d):
    return f"{d.get('name') or 'Device ' + str(d['id'])} ({d['id']})"


def _pt_name(o):
    import bi_explore as E
    return o.get('name') or f"{E.sd_ty(o['ty'])} {o['inst']}"


def diff(before, now, values=False):
    """What changed between two lists of devices (older first): [(kind, device, what, before, now)].
    kind is 'new', 'gone' or 'changed'. Devices match by device ID and address; points by object identifier.
    Point values are compared only with values=True (they change all the time)."""
    def key(d):
        return (d['id'], d.get('ip'), d.get('sn'), str(d.get('sa') or ''))
    a = {key(d): d for d in before}
    b = {key(d): d for d in now}
    by_id_a = {}
    for d in before:
        by_id_a.setdefault(d['id'], []).append(d)
    out = []
    moved = set()                                         # old keys matched to a device that changed address
    for k, d in sorted(b.items(), key=lambda x: x[0][0]):
        o = a.get(k)
        if o is None and len(by_id_a.get(d['id'], [])) == 1 and not any(kk[0] == d['id'] for kk in b if kk != k):
            o = by_id_a[d['id']][0]                       # same device ID at a new address: one device that moved
            if key(o) in b:
                o = None
            else:
                moved.add(key(o))
        if o is None:
            out.append(('new', _dev_name(d), 'device found', '', f"{d.get('vendor') or ''} {d.get('model') or ''}".strip()))
            continue
        for f, t in DETAILS:
            x, y = o.get(f) or '', d.get(f) or ''
            if x != y and (x and y or f == 'ip'):
                out.append(('changed', _dev_name(d), t, str(x), str(y)))
        if o.get('objs') is None or d.get('objs') is None:
            continue
        pa = {p['o']: p for p in o['objs']}
        pb = {p['o']: p for p in d['objs']}
        for oid in sorted(set(pa) | set(pb)):
            p, q = pa.get(oid), pb.get(oid)
            if p is None:
                out.append(('new', _dev_name(d), 'point added', '', _pt_name(q)))
            elif q is None:
                out.append(('gone', _dev_name(d), 'point removed', _pt_name(p), ''))
            else:
                if (p.get('name') or '') != (q.get('name') or '') and p.get('name') and q.get('name'):
                    out.append(('changed', _dev_name(d), f'point renamed ({_pt_name(q)})', p['name'], q['name']))
                if (p.get('u') or '') != (q.get('u') or '') and p.get('u') and q.get('u'):
                    out.append(('changed', _dev_name(d), f'{_pt_name(q)} units', p['u'], q['u']))
                if values and str(p.get('val') or '') != str(q.get('val') or '') and p.get('val') and q.get('val'):
                    out.append(('changed', _dev_name(d), f'{_pt_name(q)} value', f"{p['val']} {p.get('u') or ''}".strip(),
                                f"{q['val']} {q.get('u') or ''}".strip()))
    for k, d in sorted(a.items(), key=lambda x: x[0][0]):
        if k not in b and k not in moved:
            out.append(('gone', _dev_name(d), 'device did not answer', f"{d.get('vendor') or ''} {d.get('model') or ''}".strip(), ''))
    return out

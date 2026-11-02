"""
bi_points.py - what a capture says about points, alarms and device health, with no user interface:
point value history, value changes, alarms and events, the health score of each device, saved site
profiles, imported point names and the rolling capture files of a long capture.
"""
from __future__ import annotations

import csv
import io
import os
import re
import struct
import time

_NUM = re.compile(r'^[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?')
_ONOFF = {'active': 1.0, 'inactive': 0.0, 'true': 1.0, 'false': 0.0, 'on': 1.0, 'off': 0.0}
_WPM = re.compile(r'([a-z][a-z-]*(?: \d+)?) ([a-z][a-z-]*) = ([^;|]+)')
PV = 'present-value'


def number(v):
    """The value as a number for the graph, or None for text."""
    s = str(v).strip()
    m = _NUM.match(s)
    if m:
        return float(m.group(0))
    return _ONOFF.get(s.lower())


def points(P):
    """Every point the capture shows a value for: {'key', 'dev', 'obj', 'prop', 's': samples, 'w': writes}.
    A sample is (time, value text, number or None, packet number). COV notifications carry the values; a
    write is (time, value text, packet number, who wrote it)."""
    out = {}

    def at(key, dev, obj, prop):
        k = (key, obj, prop)
        e = out.get(k)
        if e is None:
            e = out[k] = {'key': key, 'dev': dev, 'obj': obj, 'prop': prop, 's': [], 'w': []}
        elif dev is not None and e['dev'] is None:
            e['dev'] = dev
        return e
    for r in P:
        if r.cov and r.cv:
            key = r.key or r.src
            for prop, val in r.cv:
                if prop:
                    at(key, r.cov['dev'], r.cov['obj'], prop)['s'].append((r.t, val, number(val), r.no))
        if r.wr and r.wr['val']:
            key, sender = r.dk or r.dst, r.key or r.src
            w = r.wr
            many = list(_WPM.finditer(w['val']))
            if w['svc'] == 'Write Property Multiple' and many:
                for m in many:
                    at(key, None, m.group(1), m.group(2))['w'].append((r.t, m.group(3).replace(' …', '').strip(), r.no, sender))
            elif w['obj'] and w['prop']:
                at(key, None, w['obj'], w['prop'])['w'].append((r.t, w['val'], r.no, sender))
    L = [e for e in out.values() if e['s'] or e['w']]
    for e in L:
        e['chg'] = sum(1 for a, b in zip(e['s'], e['s'][1:]) if a[1] != b[1])
        nums = [x[2] for x in e['s'] if x[2] is not None]
        e['lo'], e['hi'] = (min(nums), max(nums)) if nums else (None, None)
    L.sort(key=lambda e: (e['prop'] != PV, -e['chg'], -len(e['s']), e['key'], e['obj']))
    return L


def value_changes(L):
    """Each time a reported value differed from the one before it, in time order."""
    out = []
    for e in L:
        for a, b in zip(e['s'], e['s'][1:]):
            if a[1] != b[1]:
                out.append({'t': b[0], 'no': b[3], 'key': e['key'], 'dev': e['dev'], 'obj': e['obj'], 'prop': e['prop'],
                            'old': a[1], 'new': b[1]})
    out.sort(key=lambda x: (x['t'], x['no']))
    return out


# ---------------------------------------------------------------- alarms --
def alarms(P):
    """Event notifications in time order, each marked with the acknowledgement that answered it."""
    out = []
    for r in P:
        a = r.al
        if not a:
            continue
        if a['kind'] == 'event':
            out.append({'t': r.t, 'no': r.no, 'from': r.key or r.src, 'to': r.dk or r.dst, 'dev': a.get('Initiating device', ''),
                        'obj': a.get('Event object', ''), 'type': a.get('Event type', ''), 'was': a.get('From state', ''),
                        'now': a.get('To state', ''), 'msg': a.get('Message text', ''), 'pri': a.get('Priority', ''),
                        'notify': a.get('Notify type', ''), 'need': a.get('Acknowledgement required', '') in ('true', 'yes', 'True'),
                        'ack': None})
        else:
            for e in reversed(out):
                if e['need'] and e['ack'] is None and e['obj'] == a.get('Event object') and e['from'] == (r.dk or r.dst):
                    e['ack'] = {'t': r.t, 'no': r.no, 'by': a.get('Acknowledgement source') or r.key or r.src}
                    break
    return out


# ---------------------------------------------------------------- health --
def health(F):
    """A 0-100 score per measured device, with the reasons it lost points. Good is 85 or more, Fair 60 or more."""
    er = {}
    for e in F.er or []:
        x = er.setdefault(e['who'], {'error': 0, 'hard': 0})
        x['hard' if e['k'] != 'error' else 'error'] += e['n']
    out = []
    for e in F.sl or []:
        tot = e['n'] + e['miss']
        score, why = 100, []
        if tot and e['miss']:
            lost = min(50, round(100 * e['miss'] / tot))
            if lost:
                score -= lost
                why.append(f"{e['miss']} of {tot} requests unanswered")
        if e['n'] and e['med'] >= 1000:
            score -= 30
            why.append(f"very slow to answer ({round(e['med'])} ms typical)")
        elif e['n'] and e['med'] >= 300:
            score -= 10
            why.append(f"slow to answer ({round(e['med'])} ms typical)")
        x = er.get(e['key'])
        if x and x['hard']:
            score -= min(25, 5 + x['hard'])
            why.append(f"{x['hard']} rejected or aborted")
        if x and x['error'] and tot:
            lost = min(15, round(100 * x['error'] / tot))
            if lost:
                score -= lost
                why.append(f"{x['error']} error {'reply' if x['error'] == 1 else 'replies'}")
        score = max(0, score)
        out.append({'key': e['key'], 'ids': e['ids'], 'score': score, 'tot': tot,
                    'rate': 'Good' if score >= 85 else 'Fair' if score >= 60 else 'Poor', 'why': why})
    out.sort(key=lambda h: (h['score'], h['key']))
    return out


# ----------------------------------------------------------- site profiles --
def profile(F, name, notes=''):
    nm = F.nm or {}
    devs = [{'id': d['id'], 'key': d['key'], 'v': d['v'], 'name': (nm.get(d['id']) or {}).get('name', ''),
             'model': (nm.get(d['id']) or {}).get('model', ''), 'fw': (nm.get(d['id']) or {}).get('fw', '')} for d in F.dv or []]
    return {'name': name, 'notes': notes, 'when': time.strftime('%Y-%m-%d %H:%M'), 'devs': devs, 'nets': sorted(F.nets or [])}


def profile_diff(p, F):
    """How this capture differs from a saved site. A device that stayed silent in the capture counts as missing."""
    now = profile(F, '')
    A, B = {d['id']: d for d in p['devs']}, {d['id']: d for d in now['devs']}
    R = {'new': [B[i] for i in B if i not in A], 'gone': [A[i] for i in A if i not in B], 'moved': [], 'fw': [],
         'newN': sorted(set(now['nets']) - set(p['nets'])), 'goneN': sorted(set(p['nets']) - set(now['nets']))}
    for i in A:
        if i in B:
            if A[i]['key'] != B[i]['key']:
                R['moved'].append({'id': i, 'was': A[i]['key'], 'now': B[i]['key']})
            if A[i]['fw'] and B[i]['fw'] and A[i]['fw'] != B[i]['fw']:
                R['fw'].append({'id': i, 'was': A[i]['fw'], 'now': B[i]['fw']})
    R['same'] = len(A) - len(R['gone']) - len(R['moved'])
    return R


# ------------------------------------------------------------- point names --
_TYPES = {'ai': 'analog-input', 'ao': 'analog-output', 'av': 'analog-value', 'bi': 'binary-input', 'bo': 'binary-output',
          'bv': 'binary-value', 'msi': 'multi-state-input', 'mso': 'multi-state-output', 'msv': 'multi-state-value'}


def object_name(s):
    """'AI1', 'ai-1', 'analog input 1', 'analog-input:1' -> 'analog-input 1'; '' if it is not an object."""
    m = re.match(r'^\s*([A-Za-z][A-Za-z -]*?)[\s:_-]*(\d+)\s*$', s or '')
    if not m:
        return ''
    t = re.sub(r'[\s_]+', '-', m.group(1).strip().lower()).strip('-')
    return f'{_TYPES.get(t, t)} {int(m.group(2))}'


def parse_point_names(text):
    """A CSV with columns device (may be blank), object and name, in any order if it has a header row.
    Returns ({'device|object': name}, lines that could not be used). Blank device means every device."""
    rows = [r for r in csv.reader(io.StringIO(text.lstrip('﻿'))) if any(c.strip() for c in r)]
    if not rows:
        return {}, 0
    dc, oc, nc = 0, 1, 2
    head = [c.strip().lower() for c in rows[0]]
    obj_col = next((i for i, c in enumerate(head) if c in ('object', 'point', 'object id', 'bacnet object')), None)
    if obj_col is not None:
        oc = obj_col
        dc = next((i for i, c in enumerate(head) if c in ('device', 'device id', 'device instance')), None)
        nc = next((i for i, c in enumerate(head) if c in ('name', 'label', 'description', 'point name')), None)
        rows = rows[1:]
        if nc is None:
            return {}, len(rows)
    elif len(rows[0]) == 2:
        dc, oc, nc = None, 0, 1
    out, bad = {}, 0
    for r in rows:
        try:
            obj = object_name(r[oc])
            name = r[nc].strip()
            dev = r[dc].strip() if dc is not None else ''
        except IndexError:
            obj, name, dev = '', '', ''
        dev = re.sub(r'^\s*device\s*', '', dev, flags=re.I)
        if obj and name and (not dev or dev.isdigit()):
            out[f'{dev or "*"}|{obj}'] = name
        else:
            bad += 1
    return out, bad


# ------------------------------------------------------------ long capture --
class Rolling:
    """Writes a long capture into a folder: a new .pcap every few minutes, the oldest removed once there are
    more than `keep`, and a problems.txt that lists every alert with its time."""

    def __init__(self, folder, minutes=30, keep=48):
        self.folder, self.secs, self.keep = folder, max(1, minutes) * 60, max(1, keep)
        self.f = None
        self.lt = None
        self.t0 = 0
        self.files = []
        self.count = self.num = 0
        os.makedirs(folder, exist_ok=True)

    def _new(self, lt):
        self.close()
        self.num += 1
        name = os.path.join(self.folder, time.strftime('bacnet-%Y%m%d-%H%M%S') + f'-{self.num:04}.pcap')
        self.f = open(name, 'wb', buffering=1 << 16)
        self.f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, lt))
        self.lt, self.t0 = lt, time.time()
        self.files.append(name)
        while len(self.files) > self.keep:
            try:
                os.remove(self.files.pop(0))
            except OSError:
                pass

    def write(self, ts, lt, d):
        if self.f is None or lt != self.lt or time.time() - self.t0 >= self.secs:
            self._new(lt)
        sec = int(ts)
        d = bytes(d)
        self.f.write(struct.pack('<IIII', sec, int((ts - sec) * 1e6), len(d), len(d)) + d)
        self.count += 1

    def log(self, msg):
        with open(os.path.join(self.folder, 'problems.txt'), 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}\n")

    def flush(self):
        if self.f:
            self.f.flush()

    def close(self):
        if self.f:
            self.f.close()
            self.f = None

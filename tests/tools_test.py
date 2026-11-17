"""The field tools on the simulated MS/TP trunk: the guard on the send path, out of service, the 16-level priority array
and Release, the site-wide override list, clock sync, restart and communication control, Find point (Who-Has), COV in
the watch window, schedule and calendar editing, BBMD tables, pressure / flow units, the check-out sheet and the
Max Info Frames finding. Screenshots go to tests/out/tools."""
import os
import socket
import sys
import tempfile
import threading
import time

os.environ['LOCALAPPDATA'] = tempfile.mkdtemp(prefix='bi_tools_test_')
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'out', 'tools')
os.makedirs(OUT, exist_ok=True)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QToolButton  # noqa: E402
import bacnet_live as BL  # noqa: E402
BL.load_session = lambda: {}
BL.save_session = lambda u: None
import mstp_sim as S  # noqa: E402
import bi_mstp as M  # noqa: E402
import bi_store, bi_app, bi_site, bi_sitewin, bi_discover  # noqa: E401,E402
import bi_core as C  # noqa: E402
import bi_explore as E  # noqa: E402

ERR, BAD = [], []


def _hook(t, v, tb):
    import traceback
    ERR.append(f'{t.__name__}: {v}')
    traceback.print_exception(t, v, tb)


sys.excepthook = _hook


def check(ok, msg):
    print(('ok   ' if ok else 'FAIL ') + msg, flush=True)
    if not ok:
        BAD.append(msg)


# ===================================================================== guard --
def ip(apdu, bc=False, armed=True, route=None):
    return BL._read_only_ok(E.ex_wrap(route, apdu, 0 if apdu[0] >> 4 == 1 else 1, bc), armed)


AV7 = E.oid(2, 7)
check(ip(E.ex_wp(AV7, [0x44, 0, 0, 0, 0], 8)) == '', 'present-value write allowed while armed')
check('switched off' in ip(E.ex_wp(AV7, [0x44, 0, 0, 0, 0], 8), armed=False), 'refused while write access is off')
check(ip(E.ex_wp(AV7, [0x11], None, 81)) == '', 'out-of-service write allowed')
check(ip(E.ex_wp(AV7, [0x11], 8, 81)) != '', 'no priority on out-of-service')
check(ip(E.ex_wp(AV7, [0x21, 5], None, 81)) != '', 'out-of-service only takes true / false')
check(ip(E.ex_wp(AV7, [0x44, 0, 0, 0, 0], None, 77)) != '', 'object-name cannot be written')
check(ip(E.ex_wp(E.oid(17, 1), [0x0E, 0x0F] * 7, None, 123)) == '', 'weekly schedule write to a schedule allowed')
check(ip(E.ex_wp(AV7, [0x0E, 0x0F] * 7, None, 123)) != '', 'weekly schedule refused on a non-schedule')
check(ip(E.ex_wp(E.oid(6, 1), [0x0C, 126, 1, 1, 255], None, 23)) == '', 'calendar date-list write allowed')
check(ip(E.ex_reinit(1)) == '' and ip(E.ex_reinit(0, 'secret')) == '', 'warm / cold restart (with a password) allowed')
check(ip([0, 5, 0, 20, 0x09, 3]) != '', 'other reinitialize states (backup, restore…) refused')
check('switched off' in ip(E.ex_reinit(1), armed=False), 'restart refused while write access is off')
check(ip(E.ex_dcc(1, 15, 'pw')) == '' and ip(E.ex_dcc(0)) == '', 'communication control allowed')
check(ip(E.ex_reinit(1), bc=True) != '', 'restart can never be broadcast')
check(ip(E.ex_time_sync()) == '' and ip(E.ex_time_sync(utc=True)) == '', 'time sync to one device allowed')
check(ip(E.ex_time_sync(), bc=True) != '', 'time sync broadcast refused')
check('switched off' in ip(E.ex_time_sync(), armed=False), 'time sync refused while write access is off')
check(ip(E.ex_subscribe_cov(AV7, 300), armed=False) == '', 'COV subscription for 5 minutes allowed without write access')
check(ip(E.ex_subscribe_cov(AV7, cancel=True), armed=False) == '', 'COV cancellation allowed')
check(ip(E.ex_subscribe_cov(AV7, 7200)) != '', 'COV longer than an hour refused')
check(ip([0, 5, 0, 5, 0x09, 87, 0x1C, *E.be4(AV7), 0x29, 0]) != '', 'COV without a lifetime (for ever) refused')
check(ip([0, 5, 0, 5, 0x09, 87, 0x1C, *E.be4(AV7), 0x29, 1, 0x39, 60]) != '', 'confirmed COV notifications refused')
check(ip(E.ex_who_has('AHU-1 SAT'), bc=True, armed=False) == '' and ip(E.ex_who_has(o=AV7, lo=1, hi=9), bc=True) == '',
      'Who-Has by name and by object allowed')
check(ip([0, 5, 0, 10, 0x0C, *E.be4(AV7)]) != '', 'other services (create object) still refused')
pkt = E.ex_wrap(None, E.ex_reinit(1), 1)
check(BL._is_write(pkt) and BL._is_write(E.ex_wrap(None, E.ex_time_sync(), 0)) and not BL._is_write(E.ex_wrap(None, E.ex_rp(AV7, 85), 1)),
      'restarts and clock sets are logged like writes; reads are not')

# ============================================================== pure helpers --
E.PRESS_PREF, E.FLOW_PREF = 'inH2O', 'L/s'
check(E.temp_text('249.0889', 53) == '1' and E.unit_of({'uc': 53, 'u': 'Pa'}) == 'inH₂O', 'Pa shown in inH₂O')
check(abs(E.conv(1.0, 53, back=True) - 249.0889) < 1e-6, 'inH₂O typed in goes back to Pa')
check(E.temp_text('1000', 84) == '471.95' and E.unit_of({'uc': 84, 'u': 'cfm'}) == 'L/s', 'cfm shown in L/s')
check(E.temp_text('0.25', 58) == '0.25', 'inH₂O point stays in inH₂O')
E.PRESS_PREF, E.FLOW_PREF = '', ''
check(E.temp_text('249', 53) == '249', 'as the device sends: no conversion')

ch = bi_site.parse_changes('18:00 inactive, 07:00 active', 9, True)
check([(h, m) for h, m, _s, _v in ch] == [(7, 0), (18, 0)] and ch[0][3] == [0x91, 1], 'changes parsed and sorted')
check(bi_site.parse_changes('06:30 21.5', 4)[0][3][0] == 0x44 and bi_site.parse_changes('08:00 relinquish', 4)[0][3] == [0],
      'real and relinquish values')
for bad in ('7 active', '25:00 active', '07:00 maybe'):
    try:
        bi_site.parse_changes(bad, 9, True)
        check(False, f'refuses {bad!r}')
    except ValueError:
        check(True, f'refuses {bad!r}')
raw = bi_site.enc_special_event((2026, 12, 24), (2026, 12, 26), ch, 10)
ex_ = bi_site.parse_exceptions(raw + b'\x3f', 0, len(raw) + 1, True)
check(len(ex_) == 1 and ex_[0]['when'] == '2026-12-24 to 2026-12-26' and ex_[0]['tv'] == [('07:00', 'active'), ('18:00', 'inactive')]
      and ex_[0]['pri'] == 10 and ex_[0]['raw'] == raw, f'exception encodes and reads back: {ex_}')
de = bi_site.enc_date_entry((2027, 1, 1)) + bi_site.enc_date_entry((2027, 7, 1), (2027, 7, 4))
dl = bi_site.parse_date_list(de + b'\x3f', 0, len(de) + 1)
check([x['when'] for x in dl] == ['2027-01-01', '2027-07-01 to 2027-07-04'], f'date list encodes and reads back: {dl}')

bdt = bytes([0x81, 3, 0, 24, 10, 0, 1, 5, 0xBA, 0xC0, 255, 255, 255, 255, 10, 0, 2, 5, 0xBA, 0xC0, 255, 255, 255, 0])
check(E.parse_bvlc_table(bdt, 3) == [{'ip': '10.0.1.5', 'port': 47808, 'mask': '255.255.255.255'},
                                     {'ip': '10.0.2.5', 'port': 47808, 'mask': '255.255.255.0'}], 'BDT decoded')
probs = bi_sitewin.BbmdDialog.check([
    {'ip': '10.0.1.5', 'bdt': [{'ip': '10.0.1.5', 'mask': '255.255.255.255'}], 'fdt': [], 'err': ''},
    {'ip': '10.0.2.5', 'bdt': [{'ip': '10.0.2.5', 'mask': '255.255.255.255'}, {'ip': '10.0.1.5', 'mask': '255.255.255.255'}],
     'fdt': [], 'err': ''}])
check(len(probs) == 1 and '10.0.1.5 does not list 10.0.2.5' in probs[0], f'BBMD check finds the missing peer: {probs}')

ihave = bytes([0xC4, *E.be4(E.oid(8, 2001)), 0xC4, *E.be4(E.oid(0, 3)), 0x75, 4, 0, *b'OAT'])
check(E.parse_ihave(ihave + C._PAD, 0, len(ihave)) == {'id': 2001, 'o': E.oid(0, 3), 'name': 'OAT'}, 'I-Have decoded')

trunk = {'masters': [{'mac': 1, 'data': 900, 'fph': [2] * 80 + [1] * 20}, {'mac': 5, 'data': 100, 'fph': [1, 0] * 50}]}
m_ = C.mif_limited(trunk)
check(m_ and m_[0]['mac'] == 1 and m_[1] == 2, 'a busy master always stopping at 2 messages is flagged')
trunk['masters'][0]['fph'] = [2, 1, 0, 3] * 25
check(C.mif_limited(trunk) is None, 'a master sending varying numbers is not flagged')

# ============================================================ on the trunk --
bus = S.make_trunk([(1, 2001, 'VAV-1'), (5, 2005, 'VAV-5')], site=True)
S.SIMS[1].password = 'secret'
S.SIMS[0].cov_refuse.add(E.oid(2, 7))
M.open_port = lambda port, baud: bus.port()
app = QApplication(sys.argv)
app.setStyle('windows11')
w = bi_app.MainWindow(bi_store.Store('settings-toolstest.json'))
w.resize(1500, 950)
w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
w.show()
bi_discover.confirm = lambda *a, **k: True                   # every "are you sure?" says yes


def _arm(win):
    win.explorer.arm(15)
    return True


bi_discover.arm_dialog = _arm


def pump(s):
    end = time.time() + s
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)


def until(cond, limit=60):
    end = time.time() + limit
    while time.time() < end and not cond():
        pump(0.1)
    return cond()


def shot(widget, name):
    widget.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    widget.show()
    pump(0.3)
    widget.grab().save(os.path.join(OUT, name + '.png'))


def wait(fut, limit=90):
    """Result of a function run with ex.run (pumping the UI while it works)."""
    until(fut.done, limit)
    return fut.result()


ex = w.explorer
w.goto('x')
dv = w.view('x')
dv.m_ms.setChecked(True)
pump(0.2)
dv.ms_port.insertItem(0, 'SIM – simulated trunk', 'SIM')
dv.ms_port.setCurrentIndex(0)
dv.ms_join_leave()
until(lambda: ex.link is not None and ex.link.joined, 40)
dv.scan()
until(lambda: ex.busy == '' and sum(1 for d in ex.devs.values() if d.get('name')) >= 2, 40)
devs = sorted(ex.devs.values(), key=lambda d: d['id'])
check(len(devs) == 2, f'found the two controllers ({len(devs)})')
d1, d5 = devs
check(dv.b_find.text() == 'Find point…', 'Find point button on the Discover bar')

# ---------------------------------------------------------------- Who-Has --
got = wait(ex.run(ex.who_has, 'OAT', None, None, None, 4.0))
check(sorted(x['id'] for x in got) == [2001, 2005] and all(x['o'] == E.oid(0, 3) for x in got), f'Who-Has by name: {got}')
got = wait(ex.run(ex.who_has, None, E.oid(4, 2), 2003, 2010, 4.0))
check([x['id'] for x in got] == [2005] and got[0]['name'] == 'Fan', 'Who-Has by object, only device IDs 2003–2010')
check(bi_sitewin.WhoHasDialog.parse_obj('AI 3') == E.oid(0, 3) and bi_sitewin.WhoHasDialog.parse_obj('analog-value 12') == E.oid(2, 12)
      and bi_sitewin.WhoHasDialog.parse_obj('AHU-1 SAT') is None, 'Find point understands AI 3 and names')
wh = bi_sitewin.who_has_dialog(w)
wh.q.setText('SAT SP')
wh.go()
until(lambda: wh.res, 20)
check(wh.tbl.rowCount() == 2 and wh.tbl.item(0, 3).text() == 'SAT SP', 'Find point window lists the answers')
shot(wh, 'find-point')
wh.close()

# ---------------------------------------------------------- read the points --
wait(ex.run(ex.browse, d1))
check(len(d1.get('objs') or []) > 5, 'points read')
rat = next(o for o in d1['objs'] if o['ty'] == 0 and o['inst'] == 2)
fan = next(o for o in d1['objs'] if o['ty'] == 4 and o['inst'] == 2)
av = next(o for o in d1['objs'] if o['ty'] == 2 and o['inst'] == 7)

# --------------------------------------------- status flags and out of service --
dv.go_node({'k': d1['key'], 'o': rat['o']})
until(lambda: rat.get('pd') and rat['pd'].get('ok'), 30)
pump(0.8)
texts = [x.text() for x in dv.insp.findChildren(QLabel)]
check('● Out of service' in texts and 'In alarm' in texts and 'Fault' in texts, f'four status badges, out of service lit: {[t for t in texts if "service" in t or "alarm" in t]}')
btns = [b.text() for b in dv.insp.findChildren(QPushButton)]
check('Put back in service' in btns, f'out-of-service switch offered: {btns}')
shot(w, 'point-oos')
check(not ex.armed(), 'write access starts off')
b = next(b for b in dv.insp.findChildren(QPushButton) if b.text() == 'Put back in service')
b.click()
until(lambda: S.SIMS[0].objs[(0, 2)].get(81) == b'\x10' and rat['pd'].get('oos') is False, 30)
check(ex.armed() and S.SIMS[0].objs[(0, 2)][81] == b'\x10' and rat['pd']['oos'] is False, 'put back in service (asked for write access first)')
check(ex.wlog[0]['val'] == 'out of service OFF' and ex.wlog[0]['res'] == 'accepted', f'logged: {ex.wlog[0]}')
ok, msg = wait(ex.run(ex.set_oos, d1, rat, True))
check(ok and S.SIMS[0].objs[(0, 2)][81] == b'\x11' and rat['pd']['oos'] is True and 'out of service' in rat['pd']['flags'],
      f'taken out of service again, read back: {msg}')

# ------------------------------------------------------- the priority array --
dv.go_node({'k': d1['key'], 'o': fan['o']})
until(lambda: fan.get('pd') and fan['pd'].get('pa'), 30)
dv.ptab = 1
dv.refresh(force=True)
pump(0.8)
rel = [b for b in dv.insp.findChildren(QToolButton) if b.text() == 'Release']
labels = [x.text() for x in dv.insp.findChildren(QLabel)]
check(len(rel) == 1 and 'in control' in labels and 'Lowest (schedules, programs)' in labels and '16' in labels,
      f'16 priority levels, the active one marked, one Release button ({len(rel)})')
shot(w, 'priority-array')
rel[0].click()
until(lambda: S.SIMS[0].objs[(4, 2)][87] == b'\x00' * 16 and fan['pd'].get('pa') and not any(v['a'] for v in fan['pd']['pa']), 30)
check(S.SIMS[0].objs[(4, 2)][87] == b'\x00' * 16 and S.SIMS[0].objs[(4, 2)][85] == S.enum(0), 'Release cleared priority 8; the fan follows its default')
check(ex.wlog[0]['res'] == 'accepted' and ex.wlog[0]['pri'] == 8, 'release logged')
dv.ptab = 0

# -------------------------------------------------------------- overrides --
S.SIMS[0].objs[(2, 7)][87] = S.real(19.0) + b'\x00' * 15                      # a life-safety-level command on the setpoint
od = bi_sitewin.overrides_dialog(w)
until(lambda: od.res is not None, 180)
pump(0.3)
items = sorted((x['id'], x['name'], x['pri']) for x in od.res['items'])
check(items == [(2001, 'SAT SP', 1), (2005, 'Fan', 8)], f'override list: {items}')
check(od.tbl.rowCount() == 1, 'filter starts on priority 8')
od.f.setCurrentIndex(2)
pump(0.2)
check(od.tbl.rowCount() == 2, 'every active command')
od.f.setCurrentIndex(0)
pump(0.2)
od.tbl.selectAll()
pump(0.2)
check(od.rel.isEnabled() and od.rel.text() == 'Release 1 selected…', 'Release button counts the selection')
shot(od, 'overrides')
od.release()
until(lambda: any(v.startswith('✓') for v in od.done_res.values()), 60)
check(S.SIMS[1].objs[(4, 2)][87] == b'\x00' * 16, 'the fan in VAV-5 released from the list')
od.close()

# ------------------------------------------------------------ clock sync --
check(abs(S.SIMS[1].clock_off - 300) < 1, 'VAV-5 clock starts 5 minutes fast')
sd = bi_sitewin.sync_clocks_dialog(w, [d5])
sd.run()
until(lambda: sd.close_b.text() == 'Done', 60)
check(abs(S.SIMS[1].clock_off) < 3 and S.SIMS[1].synced and S.SIMS[1].synced[-1][0] == 6, f'clock set (now {S.SIMS[1].clock_off:.1f} s out)')
check('✓ set' in sd.tbl.item(0, 2).text(), f'sync result shown: {sd.tbl.item(0, 2).text()}')
check(ex.wlog[0]['obj'] == 'device clock' and ex.wlog[0]['res'] == 'accepted', 'clock set logged')
shot(sd, 'clock-sync')
sd.close()
S.SIMS[1].clock_off = 7200
r = wait(ex.run(bi_site.sync_clock, ex, d5, True))
check(abs(S.SIMS[1].clock_off) < 3 and S.SIMS[1].synced[-1][0] == 9 and not r['bad'], 'UTC time sync')

# ------------------------------------------------------- device commands --
ok, msg = wait(ex.run(ex.device_command, d5, E.ex_reinit(1, 'wrong'), 'device · restart', 'warm start'))
check(not ok and 'password' in msg and not S.SIMS[1].reinits, f'wrong password refused: {msg}')
ok, msg = wait(ex.run(ex.device_command, d5, E.ex_reinit(1, 'secret'), 'device · restart', 'warm start'))
check(ok and S.SIMS[1].reinits == [1], 'warm start with the password')
ok, _ = wait(ex.run(ex.device_command, d5, E.ex_dcc(1, 5, 'secret'), 'device · disable', 'disable for 5 min'))
check(ok and S.SIMS[1].dcc == 1, 'communication disabled')
r = wait(ex.run(ex.rpc, d5, E.oid(8, 2005), 77))
check(r.get('to'), 'a disabled device does not answer reads')
ok, _ = wait(ex.run(ex.device_command, d5, E.ex_dcc(0, 0, 'secret'), 'device · enable', 'enable'))
r = wait(ex.run(ex.rpc, d5, E.oid(8, 2005), 77))
check(ok and S.SIMS[1].dcc == 0 and r.get('d'), 'enabled again: it answers')
ex.arm(0)
ok, msg = wait(ex.run(ex.device_command, d5, E.ex_reinit(1, 'secret'), 'device · restart', 'warm start'))
check(not ok and 'switched off' in msg and S.SIMS[1].reinits == [1], 'no restart while write access is off')
ex.arm(15)
dv.go_node({'k': d1['key']})
pump(0.8)
bd = next((b for b in dv.right.findChildren(QPushButton) if b.text() == 'Device commands'), None)
check(bd is not None and [a.text() for a in bd.menu().actions() if a.text()] ==
      ['Restart (warm start)…', 'Restart (cold start)…', 'Disable communication…', 'Enable communication…'], 'Device commands menu')
check(any(b.text() == 'Sync clock…' for b in dv.right.findChildren(QPushButton)), 'Sync clock button on the device page')

# -------------------------------------------------------------------- COV --
sat = next(o for o in d1['objs'] if o['ty'] == 0 and o['inst'] == 1)
wv = bi_sitewin.watch(w, d1, sat)
bi_sitewin.watch(w, d1, av)
wv.cov.setChecked(True)
until(lambda: wv.pts[0].get('cov') == 'on' and wv.pts[1].get('cov') and wv.pts[0]['s'], 40)
check(wv.pts[0]['cov'] == 'on' and wv.pts[1]['cov'].startswith('refused'), f"COV on for SAT, refused for the setpoint: {wv.pts[1]['cov']}")
check(E.oid(0, 1) in S.SIMS[0].cov and S.SIMS[0].cov[E.oid(0, 1)][1] == 300, 'subscribed for 5 minutes')
n = len(wv.pts[0]['s'])
S.SIMS[0].objs[(0, 1)][85] = S.real(15.5)
S.SIMS[0].notify_cov(E.oid(0, 1))
until(lambda: len(wv.pts[0]['s']) > n and wv.pts[0]['s'][-1][1].startswith('15.5'), 20)
check(wv.pts[0]['s'][-1][1].startswith('15.5'), 'a change notification updates the value')
pump(0.5)
check(wv.tbl.item(0, 7).text() == 'COV – instant' and 'refused' in wv.tbl.item(1, 7).text(), 'Updates column')
shot(wv, 'watch-cov')
wv.close()
until(lambda: E.oid(0, 1) not in S.SIMS[0].cov, 20)
check(E.oid(0, 1) not in S.SIMS[0].cov and wv.on_cov not in ex.cov_listeners, 'closing the watch cancels the subscription')
w.store.set('bi_watch_cov', False)

# --------------------------------------------------------------- schedule --
sc = next(o for o in d1['objs'] if o['ty'] == 17)
s = bi_sitewin.schedule_dialog(w, d1, sc)
until(lambda: s.res is not None, 60)
check(s.edit_b.isEnabled(), 'schedule can be changed')
s.start_edit()
check(s.day_edits[0].text() == '07:00 active, 18:00 inactive', f'week in the text boxes: {s.day_edits[0].text()!r}')
s.day_edits[0].setText('06:30 active, 17:00 inactive')
s.day_edits[6].setText('09:00 active, 12:00 inactive')
bi_sitewin.add_dates_dialog = lambda *a, **k: ((2027, 1, 1), None, '00:00 inactive', 9)
s.add_exception()
check(len(s.exc_new) == 2 and s.exc.rowCount() == 2, 'exception added')
s.day_edits[2].setText('7 active')
s.save()
check('write a time' in s.emsg.text(), f'a mistake is explained: {s.emsg.text()}')
s.day_edits[2].setText('07:00 active, 18:00 inactive')
s.save()
until(lambda: not s.editing and s.res and s.res['week'][0] == [('06:30', 'active'), ('17:00', 'inactive')], 60)
r = s.res
check(r['week'][0] == [('06:30', 'active'), ('17:00', 'inactive')] and r['week'][6] == [('09:00', 'active'), ('12:00', 'inactive')]
      and r['week'][1] == [('07:00', 'active'), ('18:00', 'inactive')], f"week written and read back: {r['week']}")
check([e['when'] for e in r['exc']] == ['2026-12-25', '2027-01-01'] and r['exc'][1]['pri'] == 9, f"exceptions written: {[e['when'] for e in r['exc']]}")
check(any(x['obj'].endswith('weekly schedule') for x in ex.wlog[:3]), 'schedule write logged')
s.start_edit()
s.exc.selectRow(0)
s.remove_exception()
s.save()
until(lambda: not s.editing and s.res and len(s.res['exc']) == 1, 60)
check([e['when'] for e in s.res['exc']] == ['2027-01-01'], 'exception removed')
shot(s, 'schedule-edit')
s.close()

# --------------------------------------------------------------- calendar --
cal = next(o for o in d1['objs'] if o['ty'] == 6)
cd = bi_sitewin.calendar_dialog(w, d1, cal)
until(lambda: cd.res is not None, 60)
check([x['when'] for x in cd.res['dates']] == ['2026-12-25', '2026-12-31 to 2027-01-01'], f"calendar read: {[x['when'] for x in cd.res['dates']]}")
check(not cd.save_b.isEnabled(), 'nothing to write until something changes')
bi_sitewin.add_dates_dialog = lambda *a, **k: ((2027, 7, 1), (2027, 7, 4), '', 0)
cd.add()
check(cd.save_b.isEnabled(), 'a change can be written')
cd.save()
until(lambda: cd.res and len(cd.res['dates']) == 3, 60)
check(cd.res['dates'][2]['when'] == '2027-07-01 to 2027-07-04', 'calendar date range written and read back')
shot(cd, 'calendar')
cd.close()

# ----------------------------------------------------------- check-out sheet --
html = dv.cx_html([d1])
check('Point check-out sheet' in html and 'Checked by' in html and 'SAT SP' in html and 'Device 2001' in html, 'check-out sheet')
check(any(f[0] == 'checkout' for f in dv.formats()), 'check-out sheet in Save as')

# ------------------------------------------------------------- BBMD tables --
HOST = (ex.relay.iface or {}).get('ip') or '127.0.0.1'      # Discover's socket is bound to its adapter: answer from there
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind((HOST, 47899))
srv.settimeout(0.2)
stop = []


def fake_bbmd():
    while not stop:
        try:
            data, addr = srv.recvfrom(100)
        except OSError:
            continue
        if data == b'\x81\x02\x00\x04':
            srv.sendto(bytes([0x81, 3, 0, 14, *map(int, HOST.split('.')), 0xBA, 0xDB, 255, 255, 255, 255]), addr)
        elif data == b'\x81\x06\x00\x04':
            srv.sendto(bytes([0x81, 7, 0, 14, 10, 9, 9, 9, 0xBA, 0xC0, 1, 44, 0, 200]), addr)


threading.Thread(target=fake_bbmd, daemon=True).start()
r = wait(ex.run(ex.read_bbmd, f'{HOST}:47899'), 20)
check(r['bdt'] == [{'ip': HOST, 'port': 47835, 'mask': '255.255.255.255'}] and r['fdt'] and r['fdt'][0]['ttl'] == 300,
      f'BBMD tables read over UDP: {r}')
check(bi_sitewin.BbmdDialog.check([r]) == [], 'one BBMD that lists itself: no problems')
stop.append(1)

# ---------------------------------------------------------------- the menu --
names = [a.text() for m in w.menuBar().actions() for a in m.menu().actions()]
check(all(n in names for n in ('Review overrides…', 'Find point (Who-Has)…', 'BBMD tables…')), 'Capture menu entries')
um = next(a.menu() for m in w.menuBar().actions() for a in m.menu().actions() if a.text() == 'Units')
check(sum(1 for a in um.actions() if a.text()) == 9, 'Units menu: temperature, pressure and flow')
w.set_unit('press', 'inH2O')
check(E.PRESS_PREF == 'inH2O' and w.store.get('bi_press') == 'inH2O', 'pressure unit remembered')
w.set_unit('press', '')

# ---------------------------------------------------------------- History --
import bi_history as H  # noqa: E402
until(lambda: H.index(), 10)
idx = H.index()
check(len(idx) == 1 and idx[0]['n'] == 2 and idx[0]['pts'] >= len(d1['objs']) and idx[0]['mode'] == 'mstp',
      f'this discover was saved, with the points read: {idx}')
snap = H.load(idx[0]['id'])
check(any(o.get('name') == 'SAT SP' for d in snap['devs'] for o in d.get('objs') or []), 'saved with point names and values')
check(dv.t_hist.text() == 'History' and dv.t_dev.isChecked(), 'Devices / History tabs on the Discover bar')
dv.t_hist.setChecked(True)
pump(0.5)
hp = dv.history
check(dv.stack.currentWidget() is hp and hp.pick.count() == 1 and len(hp.rows) == 2, 'History tab shows the discover and its devices')


def tree_shape(tr):
    """[(depth, text)] of every row, like the Devices tab tree."""
    out = []

    def walk(it, dep):
        out.append((dep, it.text(0)))
        for i in range(it.childCount()):
            walk(it.child(i), dep + 1)
    for i in range(tr.topLevelItemCount()):
        walk(tr.topLevelItem(i), 0)
    return out


dv.show_tab('dev')
dv.open.update({d1['key'], d5['key']} | {f"{d1['key']}|{t}" for t, _ in E.Explorer.cats(d1)})
dv.gopen.add('nmstp')
dv.refresh(force=True)
pump(0.3)
live_shape = tree_shape(dv.tree)
dv.show_tab('hist')
hp.go({'k': d1['key'], 'o': E.oid(2, 7)})                    # opens the same branches as in the Devices tab
hp.open.add(d5['key'])
hp.build_tree()
pump(0.3)
hist_shape = tree_shape(hp.tree)
check(hist_shape[:len(live_shape)] == live_shape[:len(hist_shape)] and len(hist_shape) > 8,
      f'the History tree is built like the Devices tree: {hist_shape[:6]} vs {live_shape[:6]}')
check(hp.tree.currentItem() and hp.tree.currentItem().text(0) == 'SAT SP' and 'SAT SP' in hp.crumb.text(), 'a point opens from the tree')
shot(w, 'history')
it = next(hp.tree.topLevelItem(0).child(i) for i in range(hp.tree.topLevelItem(0).childCount())
          if hp.tree.topLevelItem(0).child(i).data(0, Qt.ItemDataRole.UserRole)[1] == d1['key'])
hp.tree.setCurrentItem(it)
pump(0.2)
check(hp.node == {'k': d1['key']} and any(b.text() == 'Technical details' for b in hp.right.findChildren(QToolButton)),
      'a device page like Discover’s (with Technical details)')
hp.tree.setCurrentItem(it.child(0))
pump(0.2)
check(hp.node.get('t') is not None and len(hp.rows) == sum(1 for o in d1['objs'] if o['ty'] == hp.node['t']), 'a category lists its points')
d5['fw'] = '5.0'                                               # the device was upgraded since that discover
hp.go({'chg': 2})
pump(0.2)
check(['Changed', 'VAV-5 (2005)', 'Firmware', '4.1', '5.0'] in hp.rows, f'compared with the Devices tab now: {hp.rows}')
ex.new_history()                                              # a second discover, in which VAV-1 has a new name
d1['name'] = 'VAV-1 east'
ex.cache()
until(lambda: len(H.index()) == 2, 10)
pump(0.5)
check(hp.pick.count() == 2 and hp.pick.currentIndex() == 0, 'the new discover appears straight away')
hp.go({'chg': 1})
pump(0.2)
check(['Changed', 'VAV-1 east (2001)', 'Name', 'VAV-1', 'VAV-1 east'] in hp.rows, f'changes since the discover before: {hp.rows}')
check(len(H.diff([{'id': 9, 'ip': 'a'}], [{'id': 9, 'ip': 'b'}])) == 1 and H.diff([{'id': 9, 'ip': 'a'}], [{'id': 9, 'ip': 'b'}])[0][2] == 'Address',
      'a device that moved address is one change, not missing + new')
check([x[0] for x in H.diff([{'id': 1, 'ip': 'a'}], [{'id': 2, 'ip': 'a'}])] == ['new', 'gone'], 'a new device and a missing one')
hp.keep.setValue(1)
pump(0.3)
check(len(H.index()) == 1 and hp.pick.count() == 1 and w.store.get('bi_hist_keep') == 1, 'keeping fewer deletes the oldest')
old = ex.clear()
n = ex.open_history(H.load(H.index()[0]['id']))
pump(0.5)
check(n == 2 and all(d.get('hist') and d.get('objs') is not None for d in ex.devs.values()),
      'a saved discover goes back in the list, marked as from History')
hp.open_in_discover()
pump(0.5)
check(dv.stack.currentIndex() == 0 and len(ex.devs) == 2, 'Open in Discover switches to the Devices tab')
ex.unclear(old)
hp.keep.setValue(0)
pump(0.3)
check(not H.index() and 'off' in hp.empty.text(), 'History can be switched off')
ex.cache()
pump(1.5)
check(not H.index(), 'nothing is saved while it is off')

dv.ms_join_leave()
pump(0.3)
w.close()
pump(0.3)
for s_ in S.SIMS:
    s_.on = False
print('exceptions:', ERR + [f'check failed: {b}' for b in BAD], flush=True)

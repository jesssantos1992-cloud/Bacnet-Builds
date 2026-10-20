"""
bi_discover.py - the Discover view: networks > devices > categories > points, read from the live
network, with the guarded write dialog. The network work itself is in bi_explore.Explorer.
"""
from __future__ import annotations

import re
import time

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
                               QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton, QSplitter,
                               QTabWidget, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

import bi_core as C
import bi_explore as E
import bi_ui as U
from bi_common import (Page, Pill, RowDelegate, Table, colors, csv_text, dev_name, doc, esc, heading, html_table, label,
                       semibold, stamp)

K_ROLE = Qt.ItemDataRole.UserRole


def ago(t):
    s = round(time.time() - t)
    return ('just now' if s < 60 else f'{round(s / 60)} min ago' if s < 3600 else f'{round(s / 3600)} h ago' if s < 86400
            else time.strftime('%Y-%m-%d', time.localtime(t)))


class DiscoverView(QWidget):
    key, title = 'x', 'Discover'

    def __init__(self, win):
        super().__init__()
        self.win = win
        self.ex = win.explorer
        self._stale = True
        self.node = None            # {'k': device key, 't': object type, 'o': object id}
        self.open = set()           # expanded devices / categories
        self.gopen = set()          # expanded network groups
        self.vis = set()
        self.live = False
        self.pk = None              # device picker {'src','sel','run','stop'}
        self.tq = ''
        self.ptab = 0
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        bar = QFrame()
        bar.setObjectName('dxbar')
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(24, 14, 24, 10)
        bl.setSpacing(8)
        t = QVBoxLayout()
        t.setSpacing(0)
        t.addWidget(label('Discover', bold=True, size=17, wrap=False))
        t.addWidget(label('Find devices and read their points', muted=True, wrap=False))
        bl.addLayout(t)
        self.armpill = Pill('WRITE ACCESS ON', 'SERIOUS')
        bl.addWidget(self.armpill)
        bl.addStretch(1)
        self.b_new = QPushButton('New discover')
        self.b_scan = QPushButton('Scan network')
        self.b_opts = QPushButton('Options…')
        self.b_arm = QPushButton('Enable write access…')
        self.b_arm.setToolTip('Allow Write Property for a limited time')
        for b in (self.b_new, self.b_scan, self.b_opts, self.b_arm):
            bl.addWidget(b)
        v.addWidget(bar)
        v.addWidget(self._conn_bar())
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        v.addWidget(line)
        self.split = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 10, 6, 8)
        ll.setSpacing(8)
        self.status = label('', muted=True)
        ll.addWidget(self.status)
        self.q = QLineEdit()
        self.q.setPlaceholderText('Search devices and points')
        self.q.setClearButtonEnabled(True)
        ll.addWidget(self.q)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setAnimated(True)
        self.tree.setItemDelegate(RowDelegate(self.tree))
        self.tree.setIconSize(QSize(12, 12))
        self.tree.setFrameShape(QFrame.Shape.NoFrame)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        ll.addWidget(self.tree, 1)
        self.leg = QWidget()
        lg = QHBoxLayout(self.leg)
        lg.setContentsMargins(4, 0, 0, 0)
        lg.setSpacing(4)
        for ic, t_ in ((U.dot(colors()['no']), 'answered scan'), (U.dot('#0a84ff'), 'in capture'), (U.ring(colors()['mu']), 'not seen now')):
            il = QLabel()
            il.setPixmap(ic.pixmap(QSize(12, 12)))
            lg.addWidget(il)
            lg.addWidget(label(t_, muted=True, wrap=False))
            lg.addSpacing(10)
        lg.addStretch(1)
        ll.addWidget(self.leg)
        self.left = left
        self.split.addWidget(left)
        rightw = QWidget()
        rv = QVBoxLayout(rightw)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(0)
        nav = QWidget()                          # Back / Discover home / where you are
        nl = QHBoxLayout(nav)
        nl.setContentsMargins(16, 6, 16, 6)
        nl.setSpacing(6)
        self.b_back = U.tool(QToolButton(), 'back', 'Back', 'Back to what you were looking at before (Alt+←, or the mouse Back button)')
        self.b_home = U.tool(QToolButton(), 'home', 'Home', 'Back to the Discover start page')
        nl.addWidget(self.b_back)
        nl.addWidget(self.b_home)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        nl.addWidget(sep)
        self.crumbw = QWidget()
        self.crumbs = QHBoxLayout(self.crumbw)
        self.crumbs.setContentsMargins(4, 0, 0, 0)
        self.crumbs.setSpacing(2)
        nl.addWidget(self.crumbw, 1)
        rv.addWidget(nav)
        ln = QFrame()
        ln.setFrameShape(QFrame.Shape.HLine)
        rv.addWidget(ln)
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        self.right = Page(1100)
        body.addWidget(self.right, 1)
        # inspector: a point's details slide in on the right, so the list of points stays in view
        self.insp = QFrame()
        self.insp.setObjectName('insp')
        iv = QVBoxLayout(self.insp)
        iv.setContentsMargins(0, 0, 0, 0)
        iv.setSpacing(0)
        ih = QHBoxLayout()
        ih.setContentsMargins(20, 12, 10, 4)
        self.insp_t = label('', bold=True, size=13, wrap=True)
        ih.addWidget(self.insp_t, 1)
        self.insp_x = U.tool(QToolButton(), 'close', tip='Close (Esc)')
        self.insp_x.clicked.connect(self.close_inspector)
        ih.addWidget(self.insp_x, 0, Qt.AlignmentFlag.AlignTop)
        iv.addLayout(ih)
        self.insp_page = Page(10000)
        self.insp_page.inner.layout().setContentsMargins(20, 4, 20, 20)
        self.insp_page.scroll.viewport().setAutoFillBackground(False)
        self.insp_page.inner.setAutoFillBackground(False)
        iv.addWidget(self.insp_page, 1)
        self.insp.setMinimumWidth(0)
        self.insp.setMaximumWidth(0)
        self.insp.hide()
        body.addWidget(self.insp)
        self._insp_anim = None
        esc_ = QShortcut(QKeySequence('Escape'), self.insp, activated=self.close_inspector)
        esc_.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        rv.addLayout(body, 1)
        self.split.addWidget(rightw)
        self.hist = []                           # earlier places in Discover, for Back
        self.b_back.clicked.connect(self.back)
        self.b_home.clicked.connect(self.home)
        self.split.setSizes([320, 900])
        self.split.setStretchFactor(1, 1)
        v.addWidget(self.split, 1)
        self.b_new.clicked.connect(self.new_discover)
        self.b_scan.clicked.connect(lambda: self.scan())
        self.b_opts.clicked.connect(self.options)
        self.b_arm.clicked.connect(lambda: win.disarm() if self.ex.armed() else win.arm_dlg())
        self.q.textChanged.connect(self._search)
        self.tree.currentItemChanged.connect(self._tree_pick)
        self.tree.itemExpanded.connect(lambda it: self._exp(it, True))
        self.tree.itemCollapsed.connect(lambda it: self._exp(it, False))
        self.tree.itemChanged.connect(self._checked)
        self.tree.customContextMenuRequested.connect(self._menu)
        self._building = False

    # ---------------------------------------------------------- connection --
    def _conn_bar(self):
        """BACnet/IP or MS/TP (USB RS-485), and the MS/TP port, baud, MAC and Join controls."""
        w = QFrame()
        v = QVBoxLayout(w)
        v.setContentsMargins(24, 0, 24, 12)
        v.setSpacing(8)
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(label('Connection', bold=True, wrap=False))
        self.m_ip = QToolButton(text='BACnet/IP  (network port)')
        self.m_ms = QToolButton(text='MS/TP  (USB RS-485 adapter)')
        seg = U.Segmented([self.m_ip, self.m_ms])
        (self.m_ms if self.ex.mode == 'mstp' else self.m_ip).setChecked(True)
        row.addWidget(seg)
        row.addStretch(1)
        v.addLayout(row)
        self.ms = QWidget()
        ml = QHBoxLayout(self.ms)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.setSpacing(8)
        st = self.win.store.get('bi_mstp') or {}
        ml.addWidget(QLabel('Port'))
        self.ms_port = QComboBox()
        self.ms_port.setMinimumWidth(260)
        ml.addWidget(self.ms_port)
        rf = U.tool(QToolButton(), 'refresh', tip='Look for serial adapters again')
        self.ms_rf = rf
        ml.addWidget(rf)
        ml.addWidget(QLabel('Baud'))
        self.ms_baud = QComboBox()
        self.ms_baud.addItems(['9600', '19200', '38400', '57600', '76800', '115200'])
        self.ms_baud.setCurrentText(str(st.get('baud') or 38400))
        ml.addWidget(self.ms_baud)
        self.ms_detect = QPushButton('Detect')
        self.ms_detect.setToolTip('Listen on the trunk and find the baud rate')
        ml.addWidget(self.ms_detect)
        ml.addWidget(QLabel('PC’s MAC'))
        from PySide6.QtWidgets import QSpinBox
        self.ms_mac = QSpinBox()
        self.ms_mac.setRange(0, 127)
        self.ms_mac.setValue(int(st.get('mac', 127)))
        self.ms_mac.setToolTip('The MS/TP address the PC uses on the trunk. It must not be used by any other device.')
        ml.addWidget(self.ms_mac)
        self.ms_find = QPushButton('Find a free MAC')
        self.ms_find.setToolTip('Listen to the trunk for a few seconds (without sending) and pick a free address')
        ml.addWidget(self.ms_find)
        self.ms_join = QPushButton('Join trunk')
        self.ms_join.setDefault(True)
        ml.addWidget(self.ms_join)
        ml.addStretch(1)
        v.addWidget(self.ms)
        self.ms_status = label('', muted=True)
        v.addWidget(self.ms_status)
        self.m_ip.toggled.connect(lambda on: on and self.set_mode('ip'))
        self.m_ms.toggled.connect(lambda on: on and self.set_mode('mstp'))
        rf.clicked.connect(self.fill_ports)
        self.ms_detect.clicked.connect(self.ms_detect_baud)
        self.ms_find.clicked.connect(self.ms_find_mac)
        self.ms_join.clicked.connect(self.ms_join_leave)
        self.fill_ports()
        self.ms.setVisible(self.ex.mode == 'mstp')
        self.ms_status.setVisible(self.ex.mode == 'mstp')
        return w

    def fill_ports(self):
        cur = self.ms_port.currentData() or (self.win.store.get('bi_mstp') or {}).get('port')
        self.ms_port.clear()
        try:
            from serial.tools import list_ports
            ports = list(list_ports.comports())
        except ImportError:
            ports = []
        for p in ports:
            self.ms_port.addItem(f'{p.device} – {p.description}', p.device)
        if not ports:
            self.ms_port.addItem('No serial / USB RS-485 adapter found – plug it in, then press Refresh', '')
        i = self.ms_port.findData(cur)
        if i >= 0:
            self.ms_port.setCurrentIndex(i)

    def set_mode(self, m):
        self.ex.mode = m
        self.win.store.set('bi_dmode', m)
        self.ms.setVisible(m == 'mstp')
        self.ms_status.setVisible(m == 'mstp')
        self.node = None
        self.pk = None
        self.refresh()

    def _ms_settings(self):
        port, baud, mac = self.ms_port.currentData(), int(self.ms_baud.currentText()), self.ms_mac.value()
        self.win.store.set('bi_mstp', {'port': port, 'baud': baud, 'mac': mac})
        return port, baud, mac

    def _port_busy(self, port):
        s = self.win.live.cur()
        if self.win.run and s and s.get('backend') == 'serial' and s.get('id') == port:
            return f'{port} is being used by the live capture. Stop the capture first (one program at a time can use a COM port).'
        return ''

    def _ms_msg(self, text, bad=False):
        self.ms_status.setText(text)
        self.ms_status.setStyleSheet(f"color:{colors()['se'] if bad else colors()['mu']}")

    def ms_detect_baud(self):
        port, _b, _m = self._ms_settings()
        if not port:
            return self._ms_msg('Choose the serial port of your USB RS-485 adapter first.', True)
        if self.ex.link and self.ex.link.on:
            return self._ms_msg('Leave the trunk first.', True)
        busy = self._port_busy(port)
        if busy:
            return self._ms_msg(busy, True)
        self.ms_detect.setEnabled(False)
        self._ms_msg('Listening at each common baud rate…')
        import bacnet_live as BL

        def work():
            d = BL.autobaud(port)

            def done():
                self.ms_detect.setEnabled(True)
                if d.get('error'):
                    self._ms_msg(d['error'], True)
                elif d.get('baud'):
                    self.ms_baud.setCurrentText(str(d['baud']))
                    self._ms_settings()
                    self._ms_msg(f"Detected {d['baud']} baud. Now press Find a free MAC.")
                else:
                    self._ms_msg('No MS/TP traffic was heard at any common baud rate. Check the wiring (try swapping A and B) '
                                 'and that devices on the trunk are powered.', True)
            self.win.on_ui(done)
        self.ex.run(work)

    def ms_find_mac(self, then_join=False):
        port, baud, _m = self._ms_settings()
        if not port:
            return self._ms_msg('Choose the serial port of your USB RS-485 adapter first.', True)
        if self.ex.link and self.ex.link.on:
            return self._ms_msg('Leave the trunk first.', True)
        busy = self._port_busy(port)
        if busy:
            return self._ms_msg(busy, True)
        self.ms_find.setEnabled(False)
        self.ms_join.setEnabled(False)
        self._ms_msg(f'Listening to the trunk at {baud} baud for a few seconds (the PC does not send anything)…')
        import bi_mstp as M

        def work():
            try:
                info = M.listen(port, baud, 4.0)
                err = ''
            except Exception as e:
                import bacnet_live as BL
                info, err = None, BL.serial_error(e, port)

            def done():
                self.ms_find.setEnabled(True)
                self.ms_join.setEnabled(True)
                if err:
                    return self._ms_msg(err, True)
                info['_key'] = (port, baud)
                self._listen = info
                mac, why = M.suggest_mac(info)
                used = ', '.join(map(str, info['srcs'][:30])) or 'none'
                if mac is None:
                    return self._ms_msg(f'{why[:1].upper()}{why[1:]}. Addresses in use: {used}.', True)
                self.ms_mac.setValue(mac)
                self._ms_settings()
                self._ms_msg(f'MAC {mac} is free – {why}. Heard {info["frames"]} frames; addresses in use: {used}.'
                             + ('' if then_join else ' Press Join trunk.'))
                if then_join:
                    self._join(info)
            self.win.on_ui(done)
        self.ex.run(work)

    def ms_join_leave(self):
        link = self.ex.link
        if link and link.on:
            link.stop()
            self.ex.link = None
            self.win.mstp_feed(False)
            self._ms_msg('Left the trunk.')
            self.ms_join.setText('Join trunk')
            for w in (self.ms_port, self.ms_baud, self.ms_mac, self.ms_detect, self.ms_find):
                w.setEnabled(True)
            return self.refresh()
        port, baud, mac = self._ms_settings()
        info = getattr(self, '_listen', None)
        if not info or info.get('_key') != (port, baud):
            return self.ms_find_mac(then_join=True)          # always look at the trunk before joining
        self._join(info)

    def _join(self, info):
        import bi_mstp as M
        port, baud, mac = self._ms_settings()
        info['_key'] = (port, baud)
        if mac in info['srcs']:
            return self._ms_msg(f'MAC {mac} is already used by a device on this trunk. Press Find a free MAC.', True)
        if not info['frames'] and info.get('bytes'):
            return self._ms_msg('Data is arriving but none of it is valid MS/TP – the baud rate is probably wrong '
                                '(press Detect), or A and B are swapped. Not joining.', True)
        busy = self._port_busy(port)
        if busy:
            return self._ms_msg(busy, True)
        link = M.MstpLink(port, baud, mac, on_npdu=self.ex.rx_mstp, on_status=self.ex.notify,
                          allow_create=not info['frames'])
        cap = self.win.cap
        link.on_frame = lambda raw: cap.add(time.time(), 165, raw)      # every frame also shows in Live capture
        try:
            link.start()
        except Exception as e:
            import bacnet_live as BL
            return self._ms_msg(BL.serial_error(e, port), True)
        self.ex.link = link
        self.win.mstp_feed(True)
        self.ex.pump()
        self.ms_join.setText('Leave trunk')
        for w in (self.ms_port, self.ms_baud, self.ms_mac, self.ms_detect, self.ms_find):
            w.setEnabled(False)
        self.live = True
        self.ex_changed()

    def ms_update(self):
        link = self.ex.link
        if link is None:
            return
        if not link.on and link.error:
            self._ms_msg(link.error, True)
            self.ex.link = None
            self.win.mstp_feed(False)
            self.ms_join.setText('Join trunk')
            for w in (self.ms_port, self.ms_baud, self.ms_mac, self.ms_detect, self.ms_find):
                w.setEnabled(True)
            return
        self._ms_msg(link.status_text())

    @staticmethod
    def is_ms(d):
        """Does this Discover entry belong to the MS/TP connection?"""
        if d['ex'] and E.is_mstp(d['ex']):
            return True
        c = d['cap']
        return bool(c) and (str(c['key']).startswith('MS/TP MAC') or str(c.get('gw') or '').startswith('MS/TP MAC'))

    def other_mode_hint(self):
        """When the capture's devices all belong to the other connection, say so (instead of 'no devices')."""
        ms = self.ex.mode == 'mstp'
        n = sum(1 for d in self.sd_devs() if d['cap'] and self.is_ms(d) != ms)
        if not n:
            return ''
        return (f"The {n} device{'' if n == 1 else 's'} in this capture {'are' if n > 1 else 'is'} on "
                + ('BACnet/IP – switch Connection to BACnet/IP.' if ms else 'an MS/TP trunk – switch Connection to MS/TP.'))

    def all_devs(self):
        """The devices for the chosen connection (BACnet/IP or MS/TP), sorted by network and ID."""
        ms = self.ex.mode == 'mstp'
        L = [d for d in self.sd_devs() if self.is_ms(d) == ms]
        return sorted(L, key=lambda a: (-1 if a['net'] is None else a['net'], a['id']))

    def grp(self, d):
        if d['net'] is not None:
            return d['net']
        return 'mstp' if self.is_ms(d) else 'local'

    def grp_name(self, k, short=False):
        if k == 'mstp':
            port = self.ex.link.port if self.ex.link else (self.win.store.get('bi_mstp') or {}).get('port') or ''
            return 'MS/TP trunk' + (f' ({port})' if port else '')
        if k == 'local':
            return 'This network' if short else 'Local Network – BACnet/IP'
        return f'Network {k}'

    # ----------------------------------------------------------------- data --
    def sd_devs(self):
        """Devices from the capture and from discovery, in one list (the original's sdDevs)."""
        F = self.win.FD
        out, used = [], set()
        ex = list(self.ex.devs.values())
        nmv = F.nm or {}
        lab = self.win.labels
        for d in F.dv or []:
            ip = E.ip_of(d['key']) or (d['key'] if str(d['key']).startswith('MS/TP MAC') else '')
            e = next((x for x in ex if x['id'] == d['id'] and (x['ip'] == ip or (x.get('sn') is not None and x.get('sn') == d['sn']))), None)
            if e:
                used.add(e['key'])
            m = nmv.get(d['id']) or {}
            out.append({'id': d['id'], 'net': d['sn'], 'ip': ip, 'cap': d, 'ex': e,
                        'name': lab.d(d['id']) or (e and e.get('name')) or m.get('name', ''),
                        'vendor': (e and e.get('vendor')) or m.get('vendor') or C.VN.get(d['v'], ''),
                        'model': (e and e.get('model')) or m.get('model', ''),
                        'key': e['key'] if e else f"c|{d['id']}|{d['key']}", 'filt': f'host == "{d["key"]}"'})
        for e in ex:
            if e['key'] in used:
                continue
            out.append({'id': e['id'], 'net': e.get('sn'), 'ip': e['ip'], 'cap': None, 'ex': e,
                        'name': lab.d(e['id']) or e.get('name') or '', 'vendor': e.get('vendor') or C.VN.get(e.get('vn'), ''),
                        'model': e.get('model') or '', 'key': e['key'],
                        'filt': (f'net == {e["sn"]} && gateway == "{e["ip"]}:{e["port"]}"' if e.get('sn') is not None
                                 else f'host == "{e["ip"]}:{e["port"]}"')})
        return out

    def entry(self, k):
        return next((x for x in self.sd_devs() if x['key'] == k), None)

    def select(self, k, **extra):
        en = self.entry(k)
        if en and not en['ex'] and en['cap']:
            e = self.ex.ensure(en['cap'])
            if e:
                k = e['key']
                en = self.entry(k)
        self.node = {'k': k, **extra}
        return en

    def open_device(self, k):
        self.live = True
        prev = self.node
        en = self.select(k)
        self._push(prev)
        if en:
            self.gopen.add('n' + ('local' if en['net'] is None else str(en['net'])))
        self.win.goto('x')
        self.refresh()

    # --------------------------------------------------------------- redraw --
    def ex_changed(self):
        if self.win.cur_view == 'x':
            self.refresh(soft=True)

    def refresh(self, soft=False):
        self._stale = False
        armed = self.ex.armed()
        self.armpill.setVisible(armed)
        self.b_arm.setText('Write access ON – turn off' if armed else 'Enable write access…')
        self.b_arm.setStyleSheet('QPushButton{background:#c42b1c;color:white}' if armed else '')
        AL = self.all_devs()
        D = [d for d in AL if d['ex'] or d['key'] in self.vis]
        self.b_new.setVisible(bool(D))
        ms = self.ex.mode == 'mstp'
        self.b_scan.setText('Stop scan' if self.ex.busy == 'scan' else 'Scan MS/TP trunk' if ms else 'Scan network')
        self.b_opts.setVisible(not ms)                   # broadcast address / BBMD options are IP-only
        if ms:
            self.ms_update()
        show_left = bool(self.pk) or (self.live and bool(D))
        self.left.setVisible(show_left)
        if self.ex.busy == 'scan':
            self.status.setText(self.ex.msg)
        else:
            self.status.setText(self.status_text(D))
        if show_left:
            self.build_tree(AL, D)
        self.build_right(D, AL)

    def status_text(self, D):
        if self.pk:
            return 'Devices seen in the capture – tick the ones to discover.'
        n = len(D)
        on = sum(1 for d in D if d['ex'] and not d['ex'].get('old'))
        if not n:
            return 'No devices discovered yet.'
        if self.ex.scan_at and on:
            return f"{n} device{'' if n == 1 else 's'} · {on} answered the scan {ago(self.ex.scan_at)}"
        return f"{n} device{'' if n == 1 else 's'} from your capture. Press Scan network to see which are online."

    @staticmethod
    def dev_label(d):
        """Device ID · vendor · model, plus the device's name when it is a real one (not the default "device<ID>")."""
        vn = re.sub(r',?\s+(Corporation|Corp\.?|Inc\.?|Incorporated|LLC|Ltd\.?|Limited|GmbH|AG|Co\.?)$', '', d.get('vendor') or '', flags=re.I)
        nm = dev_name(d.get('name'), d.get('id'))
        return ' · '.join(str(x) for x in (d['id'], vn, d.get('model')) if x) + (f'  “{nm}”' if nm else '')

    def _dot(self, d):
        e = d['ex']
        c = colors()
        if e and not e.get('old'):
            return '●', c['no'], 'Answered discovery'
        if d['cap']:
            return '●', '#0a84ff', 'Seen in the capture'
        return '○', c['mu'], 'From the last scan – did not answer this time'

    def build_tree(self, AL, D):
        self._building = True
        tr = self.tree
        y = tr.verticalScrollBar().value()
        tr.setUpdatesEnabled(False)
        tr.clear()
        q = self.tq.lower()
        bold = semibold(QFont(tr.font()))
        mu = QColor(colors()['mu'])
        cur = None
        if self.pk:
            run = self.pk.get('run')
            L0 = [d for d in AL if d['cap'] and (not q or q in f"{d['id']} {d['name']} {d['vendor']} {d['ip']}".lower())]
            groups = {}
            for d in L0:
                groups.setdefault(self.grp(d), []).append(d)
            for k, L in groups.items():
                gk = 'n' + str(k)
                lab = self.win.labels.n(k) if isinstance(k, int) else ''
                g = QTreeWidgetItem(tr, [self.grp_name(k, True) + (f' “{lab}”' if lab else '')
                                         + f"  · {len(L)} device{'' if len(L) == 1 else 's'}"])
                g.setData(0, K_ROLE, ('g', gk))
                g.setFlags(g.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsAutoTristate)
                for d in L:
                    it = QTreeWidgetItem(g, [self.dev_label(d)])
                    it.setData(0, K_ROLE, ('pk', d['key']))
                    it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    it.setCheckState(0, Qt.CheckState.Checked if d['key'] in self.pk['sel'] else Qt.CheckState.Unchecked)
                    if run:
                        it.setDisabled(True)
                g.setExpanded(gk in self.gopen or bool(q))
            if not groups:
                QTreeWidgetItem(tr, [self.other_mode_hint() or 'No devices in the capture yet.']).setForeground(0, mu)
        else:
            groups = {}
            for d in D:
                groups.setdefault(self.grp(d), []).append(d)

            def pm(o):
                return q in f"{o['name']} {E.sd_ty(o['ty'])} {o['inst']}".lower()
            sel = self.node
            for k, L0 in groups.items():
                L = [d for d in L0 if not q or q in f"{d['id']} {d['name']} {d['vendor']} {d['model']}".lower()
                     or any(pm(o) for o in ((d['ex'] or {}).get('objs') or []))]
                if not L:
                    continue
                gk = 'n' + str(k)
                lab = self.win.labels.n(k) if isinstance(k, int) else ''
                g = QTreeWidgetItem(tr, [self.grp_name(k) + (f' “{lab}”' if lab else '')
                                         + f"  · {len(L)} device{'' if len(L) == 1 else 's'}"])
                g.setData(0, K_ROLE, ('g', gk))
                g.setFont(0, bold)
                for d in L:
                    e = d['ex']
                    dot, col, tip = self._dot(d)
                    it = QTreeWidgetItem(g, [self.dev_label(d) + (f"  – {d['ip']}" if d['ip'] else '')])
                    it.setIcon(0, U.ring(col) if dot == '○' else U.dot(col))
                    it.setToolTip(0, '\n'.join(str(x) for x in (tip, d['name'], d['vendor'], d['ip']) if x))
                    it.setForeground(0, QColor(colors()['fg']))
                    it.setData(0, K_ROLE, ('d', d['key']))
                    if sel and sel['k'] == d['key'] and sel.get('t') is None and sel.get('o') is None:
                        cur = it
                    if e and e.get('objs'):
                        for t, os_ in self.ex.cats(e):
                            os2 = [o for o in os_ if pm(o) or q in f"{d['id']} {d['name']}".lower()] if q else os_
                            if not os2:
                                continue
                            ck = e['key'] + '|' + str(t)
                            ci = QTreeWidgetItem(it, [f"{E.cat_name(t)}  ({len(os2)})"])
                            ci.setData(0, K_ROLE, ('c', e['key'], t))
                            ci.setForeground(0, mu)
                            if sel and sel['k'] == e['key'] and sel.get('t') == t and sel.get('o') is None:
                                cur = ci
                            for o in sorted(os2, key=lambda o: C.natural_key(o['name']))[:800]:
                                pi = QTreeWidgetItem(ci, [o['name'] or f"{E.sd_ty(o['ty'])} {o['inst']}"])
                                pi.setData(0, K_ROLE, ('p', e['key'], o['o']))
                                pi.setToolTip(0, f"{o['val']} {o['u']}".strip())
                                if sel and sel['k'] == e['key'] and sel.get('o') == o['o']:
                                    cur = pi
                            ci.setExpanded(ck in self.open or bool(q))
                        it.setExpanded(e['key'] in self.open or bool(q))
                g.setExpanded(gk in self.gopen or bool(q))
            if not tr.topLevelItemCount():
                QTreeWidgetItem(tr, ['No matches.' if D else 'Nothing here yet. Choose devices on the right to discover them.']).setForeground(0, mu)
        if cur is not None:
            tr.setCurrentItem(cur)
        tr.setUpdatesEnabled(True)
        QTimer.singleShot(0, lambda: tr.verticalScrollBar().setValue(y))
        self._building = False

    def _exp(self, it, on):
        if self._building:
            return
        d = it.data(0, K_ROLE)
        if not d:
            return
        key = d[1] if d[0] in ('g', 'd') else f'{d[1]}|{d[2]}' if d[0] == 'c' else None
        if key is None:
            return
        s = self.gopen if d[0] == 'g' else self.open
        if d[0] == 'd':
            en = self.entry(d[1])
            key = en['ex']['key'] if en and en['ex'] else key
        (s.add if on else s.discard)(key)

    def _tree_pick(self, it, _prev):
        if self._building or not it:
            return
        d = it.data(0, K_ROLE)
        if not d or d[0] in ('g', 'pk'):
            return
        prev = self.node
        if d[0] == 'd':
            self.select(d[1])
        elif d[0] == 'c':
            self.node = {'k': d[1], 't': d[2]}
        elif d[0] == 'p':
            self.node = {'k': d[1], 'o': d[2]}
        self._push(prev)
        self.build_right(None, None)

    def _checked(self, it, _col):
        if self._building or not self.pk or self.pk.get('run'):
            return
        d = it.data(0, K_ROLE)
        if d and d[0] == 'pk':
            (self.pk['sel'].add if it.checkState(0) == Qt.CheckState.Checked else self.pk['sel'].discard)(d[1])
            QTimer.singleShot(0, lambda: self.build_right(None, None))

    def _search(self, t):
        self.tq = t
        self._st = getattr(self, '_st', None) or QTimer(self, singleShot=True, timeout=self.refresh)
        self._st.start(200)

    # ----------------------------------------------------------- right side --
    def build_right(self, D, AL):
        if AL is None:
            AL = self.all_devs()
            D = [d for d in AL if d['ex'] or d['key'] in self.vis]
        p = self.right
        y = p.scroll.verticalScrollBar().value()
        p.setUpdatesEnabled(False)
        p.clear()
        n = self.node
        en = self.entry(n['k']) if n else None
        e = en['ex'] if en else None
        row = next((o for o in (e or {}).get('objs') or [] if o['o'] == n.get('o')), None) if en and n.get('o') is not None else None
        self.nav_bar(n, en, row)
        if not (row and e):
            self.hide_inspector()
        if not n or not en:
            self.start_page(p, D, AL)
        else:
            if row and e:
                self.cat_page(p, en, e, row['ty'], sel=row['o'])
                self.show_inspector(en, e, row)
            elif n.get('t') is not None and e:
                self.cat_page(p, en, e, n['t'])
            else:
                self.device_page(p, en, e)
        p.end()
        p.setUpdatesEnabled(True)
        QTimer.singleShot(0, lambda: p.scroll.verticalScrollBar().setValue(y))

    def go_node(self, n):
        prev = self.node
        self.node = n
        self._push(prev)
        self.refresh()

    # ------------------------------------------------------------ inspector --
    INSP_W = 470

    def show_inspector(self, en, e, row):
        self.insp_t.setText(row['name'] or f"{E.sd_ty(row['ty'])} {row['inst']}")
        ip = self.insp_page
        y = ip.scroll.verticalScrollBar().value()
        ip.setUpdatesEnabled(False)
        ip.clear()
        self.point_page(ip, en, e, row)
        ip.end()
        ip.setUpdatesEnabled(True)
        QTimer.singleShot(0, lambda: ip.scroll.verticalScrollBar().setValue(y))
        if not self.insp.isVisible() or self._insp_anim == 'closing':
            self.insp.setStyleSheet(f"QFrame#insp{{background:{colors()['card']};border-left:1px solid {colors()['hair']}}}")
            self.insp.show()
            self._slide(self.INSP_W)

    def _slide(self, to):
        from PySide6.QtCore import QParallelAnimationGroup, QPropertyAnimation, QEasingCurve
        g = QParallelAnimationGroup(self)
        for prop in (b'minimumWidth', b'maximumWidth'):
            a = QPropertyAnimation(self.insp, prop, g)
            a.setDuration(200)
            a.setStartValue(self.insp.width() if self.insp.isVisible() else 0)
            a.setEndValue(to)
            a.setEasingCurve(QEasingCurve.Type.OutCubic)
            g.addAnimation(a)
        self._insp_anim = 'closing' if to == 0 else 'opening'

        def done():
            if self._insp_anim == 'closing' and to == 0:
                self.insp.hide()
            self._insp_anim = None
        g.finished.connect(done)
        g.start(QParallelAnimationGroup.DeletionPolicy.DeleteWhenStopped)

    def hide_inspector(self):
        if self.insp.isVisible() and self._insp_anim != 'closing':
            self._slide(0)

    def close_inspector(self):
        n = self.node
        if n and n.get('o') is not None:
            self.go_node({'k': n['k'], 't': E.o_t(n['o'])})

    def retheme(self):
        for b, n in ((self.b_back, 'back'), (self.b_home, 'home')):
            b.setIcon(U.icon(n, colors()['ac'], 16))
        for b, n in ((self.insp_x, 'close'), (self.ms_rf, 'refresh')):
            b.setIcon(U.icon(n, colors()['fg'], 16))
        if self.insp.isVisible():
            self.insp.setStyleSheet(f"QFrame#insp{{background:{colors()['card']};border-left:1px solid {colors()['hair']}}}")

    # ----------------------------------------------------------- navigation --
    def _push(self, prev):
        """Remember where we were (for Back) when the shown page changes."""
        if prev != self.node:
            self.hist.append(prev)
            del self.hist[:-60]

    def can_back(self):
        return bool(self.pk and not self.pk.get('run')) or bool(self.hist) or self.node is not None

    def back(self):
        """Back one step inside Discover. Returns False when there is nowhere to go back to."""
        if self.pk and not self.pk.get('run'):
            self.pk = None                       # leave the 'choose devices' step
        elif self.hist:
            self.node = self.hist.pop()
        elif self.node is not None:
            self.node = None
        else:
            return False
        self.refresh()
        return True

    def home(self):
        if self.node is None and not self.pk:
            return
        if self.pk and self.pk.get('run'):
            return self.win.toast('Wait for the discover to finish, or press Stop')
        self.pk = None
        prev = self.node
        self.node = None
        self._push(prev)
        self.refresh()

    def nav_bar(self, n, en, row):
        """Back / home buttons and a clickable path: Discover › Network › Device › Category › Point."""
        self.b_back.setEnabled(self.can_back())
        self.b_home.setEnabled(n is not None or bool(self.pk))
        self.win.update_back()
        while self.crumbs.count():
            w = self.crumbs.takeAt(0).widget()
            if w:
                w.setParent(None)                   # hide it now, not when Qt gets round to deleting it
                w.deleteLater()
        parts = [('Discover', self.home if (n or self.pk) else None)]
        if self.pk:
            parts.append(('Choose devices', None))
        elif n and en:
            parts.append((self.grp_name(self.grp(en), True), None))
            nm_ = dev_name(en['name'], en['id'])
            dev = f"Device {en['id']}" + (f" “{nm_}”" if nm_ else '')
            deeper = n.get('t') is not None or n.get('o') is not None
            parts.append((dev, (lambda k=n['k']: self.go_node({'k': k})) if deeper else None))
            t = n['t'] if n.get('t') is not None else E.o_t(n['o']) if n.get('o') is not None else None
            if t is not None:
                parts.append((E.cat_name(t), (lambda k=n['k'], t=t: self.go_node({'k': k, 't': t})) if n.get('o') is not None else None))
            if n.get('o') is not None:
                parts.append((row['name'] or f"{E.sd_ty(row['ty'])} {row['inst']}" if row else 'Point', None))
        for i, (text, fn) in enumerate(parts):
            if i:
                self.crumbs.addWidget(label('›', muted=True, wrap=False))
            if fn:
                b = QToolButton(text=text)
                b.setAutoRaise(True)
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                b.setStyleSheet(f"QToolButton{{color:{colors()['ac']}}}")
                b.clicked.connect(fn)
                self.crumbs.addWidget(b)
            else:
                self.crumbs.addWidget(label(text, bold=(i == len(parts) - 1), wrap=False))
        self.crumbs.addStretch(1)

    def start_page(self, p, D, AL):
        cap = [d for d in AL if d['cap']]
        pk = self.pk
        run = pk and pk.get('run')
        p.add(label('New discover', bold=True, size=17))
        p.add(label('Choose where the devices come from, pick the ones you want, then press Discover to read their points into a tree.', muted=True))
        cards = QHBoxLayout()
        cards.setSpacing(12)
        c_ = colors()

        def card(title, sub, fn, on=False, enabled=True):
            b = QPushButton(f'{title}\n{sub}')
            b.setMinimumHeight(72)
            b.setCheckable(True)
            b.setChecked(on)
            b.setEnabled(bool(enabled))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setStyleSheet(f"QPushButton{{text-align:left;padding:14px 18px;border-radius:12px;background:{c_['card']};"
                            f"border:1px solid {c_['hair']};color:{c_['fg']}}}"
                            f"QPushButton:hover{{border:1px solid {c_['ac']}}}"
                            f"QPushButton:checked{{border:2px solid {c_['ac']}}}"
                            f"QPushButton:disabled{{color:{c_['mu']}}}")
            b.clicked.connect(fn)
            cards.addWidget(b)
        card('Use devices from the capture',
             f"{len(cap)} device{'' if len(cap) == 1 else 's'} seen in the capture you have open" if cap else
             self.other_mode_hint() or 'No devices in the open capture yet – start or open a capture first',
             self.pick_capture, bool(pk and pk['src'] == 'cap'), not run)
        ms = self.ex.mode == 'mstp'
        card('Stop scan' if self.ex.busy == 'scan' else 'Scan the MS/TP trunk' if ms else 'Scan the network',
             'Send a Who-Is on the RS-485 trunk (join the trunk first)' if ms else 'Send a Who-Is and list who answers',
             lambda: self.scan(), False, not run)
        w = QWidget()
        w.setLayout(cards)
        p.add(w)
        if self.ex.busy == 'scan':
            p.add(U.busy_row(self.ex.msg))
        if pk:
            L = [d for d in AL if d['ex']] if pk['src'] == 'scan' else cap
            sl = [d['id'] for d in L if d['key'] in pk['sel']]
            box = QFrame()
            box.setObjectName('pick')
            box.setStyleSheet(U.surface_css('pick'))
            bv = QVBoxLayout(box)
            bv.setContentsMargins(16, 14, 16, 14)
            bv.setSpacing(8)
            hr = QHBoxLayout()
            hr.addWidget(label('Discovering…' if run else 'Choose devices on the left', bold=True, wrap=False))
            hr.addWidget(label(f'{len(sl)} of {len(L)} selected', muted=True, wrap=False))
            hr.addStretch(1)
            ba = QPushButton('Select all')
            bn = QPushButton('Clear')
            ba.setEnabled(not run)
            bn.setEnabled(not run)
            ba.clicked.connect(lambda: (pk['sel'].update(d['key'] for d in L), self.refresh()))
            bn.clicked.connect(lambda: (pk['sel'].clear(), self.refresh()))
            hr.addWidget(ba)
            hr.addWidget(bn)
            bv.addLayout(hr)
            bv.addWidget(label(('Selected: ' + ', '.join(map(str, sl[:40])) + (' …' if len(sl) > 40 else '')) if sl else
                               'Open a network on the left, then tick the network or the devices you want.', muted=True))
            fr = QHBoxLayout()
            if run:
                st = QPushButton('Stop')
                st.clicked.connect(lambda: (pk.__setitem__('stop', True), setattr(self.ex, 'stop', True)))
                fr.addWidget(st)
                fr.addWidget(U.busy_row(f"Reading {run['i']} of {run['n']}" + (f" – device {run['cur']}" if run['cur'] else '') + '…'))
            else:
                go = U.primary(QPushButton(f"Discover {len(sl)} device{'' if len(sl) == 1 else 's'}" if sl else 'Discover'))
                go.setDefault(True)
                go.setEnabled(bool(sl))
                go.clicked.connect(self.run_picked)
                fr.addWidget(go)
            fr.addStretch(1)
            bv.addLayout(fr)
            p.add(box)
        elif D:
            p.add(label(f"{len(D)} device{'' if len(D) == 1 else 's'} already discovered are on the left. Pick one to see its points, "
                        'or start another discover above.', muted=True))
            r = QHBoxLayout()
            b1 = QPushButton('Export device list (.csv)')
            b1.clicked.connect(lambda: self.save_csv('bacnet-devices.csv', self.csv_devices()))
            b2 = QPushButton('Use names as labels')
            b2.setToolTip('Use these device names as labels in the Packets and Findings tabs')
            b2.clicked.connect(self.names_as_labels)
            r.addWidget(b1)
            r.addWidget(b2)
            r.addStretch(1)
            ww = QWidget()
            ww.setLayout(r)
            p.add(ww)

    def info_grid(self, items, tech=()):
        """A card of 'name  value' rows; technical rows stay hidden until 'Technical details' is opened."""
        f = QFrame()
        f.setObjectName('info')
        f.setStyleSheet(U.surface_css('info'))
        g = QGridLayout(f)
        g.setContentsMargins(18, 14, 18, 14)
        g.setHorizontalSpacing(20)
        g.setVerticalSpacing(8)
        for i, (k, v) in enumerate(items):
            g.addWidget(label(k, muted=True, wrap=False), i, 0, Qt.AlignmentFlag.AlignTop)
            g.addWidget(label(str(v), sel=True), i, 1)
        tech = [(k, v) for k, v in tech if v]
        if tech:
            n = len(items)
            b = U.disclose(QToolButton(), 'Technical details')
            b.setChecked(getattr(self, 'tech', False))
            g.addWidget(b, n, 0, 1, 2, Qt.AlignmentFlag.AlignLeft)
            rows = []
            for j, (k, v) in enumerate(tech):
                a, c = label(k, muted=True, wrap=False), label(str(v), sel=True)
                g.addWidget(a, n + 1 + j, 0, Qt.AlignmentFlag.AlignTop)
                g.addWidget(c, n + 1 + j, 1)
                rows += [a, c]
            for w in rows:
                w.setVisible(b.isChecked())
            b.toggled.connect(lambda on: (setattr(self, 'tech', on), [w.setVisible(on) for w in rows]))
        g.setColumnStretch(1, 1)
        f.setMaximumWidth(760)
        return f

    def device_page(self, p, en, e):
        busy = self.ex.busy
        nm_ = dev_name(en['name'], en['id'])
        p.add(label(nm_ or f"Device {en['id']}", bold=True, size=17))
        p.add(label(' · '.join(str(x) for x in [f"Device {en['id']}" if nm_ else '', en['vendor'], en['model']] if x), muted=True))
        r = QHBoxLayout()
        r.setSpacing(8)
        has = bool(e and e.get('objs'))
        b = QPushButton('Refresh points' if has else 'Read points')
        if not has:
            U.primary(b)
        b.setEnabled(not busy and bool(e or en['cap']))
        b.clicked.connect(lambda: self.read_points(en))
        r.addWidget(b)
        b2 = QPushButton('Show packets')
        b2.clicked.connect(lambda: self.show_packets(en['filt']))
        r.addWidget(b2)
        if e and e.get('objs'):
            b3 = QPushButton('Export points…')
            b3.clicked.connect(lambda: self.save_csv(f"device-{e['id']}-points.csv", self.csv_points(e)))
            r.addWidget(b3)
        ba = QPushButton('Active alarms')
        ba.setToolTip('Ask the device which of its points are in alarm (read-only)')
        ba.setEnabled(bool(e or en['cap']))
        ba.clicked.connect(lambda: self.read_alarms(en))
        r.addWidget(ba)
        r.addWidget(label((e or {}).get('pm') or '', muted=True, wrap=False))
        r.addStretch(1)
        ww = QWidget()
        ww.setLayout(r)
        p.add(ww)
        reading = bool(busy == 'browse' and e and not e.get('objs') and e.get('pm'))
        if not (e and e.get('objs')) and not reading:
            p.add(label('Press Read points to read this device’s objects and build its tree of points.', muted=True))
        info = [('Address', E.Explorer.addr(e) if e else en['ip']), ('Vendor', en['vendor']), ('Model', en['model']),
                ('Location', e and e.get('loc')), ('Description', e and e.get('desc')), ('Status', e and e.get('st'))]
        tech = [('Firmware', e and e.get('fw')), ('Software', e and e.get('sw')), ('Max APDU', e and e.get('mx')),
                ('Device object', f"device {en['id']}"), ('Vendor ID', (en['cap'] or {}).get('v'))]
        p.add(self.info_grid([(k, v) for k, v in info if v], tech))
        if reading:
            p.add(heading('Points', 13))
            p.add(U.Skeleton(6))
        al = (e or {}).get('alarms')
        if al is not None or (e or {}).get('alarms_busy'):
            c = colors()
            p.add(heading('Active alarms', 13))
            if (e or {}).get('alarms_busy'):
                p.add(U.busy_row('Asking the device for its alarms…'))
            elif al.get('err') and not al['items']:
                er = label(f"Could not read the alarms: {al['err']}")
                er.setStyleSheet(f"color:{c['se']}")
                p.add(er)
            elif not al['items']:
                ok = label(f"✓ No active alarms or events (checked {time.strftime('%H:%M:%S', time.localtime(al['at']))}).", bold=True)
                ok.setStyleSheet(f"color:{c['no']}")
                p.add(ok)
            else:
                p.add(label(f"{len(al['items'])} point{'' if len(al['items']) == 1 else 's'} in alarm or fault "
                            f"(checked {time.strftime('%H:%M:%S', time.localtime(al['at']))}). Double-click a row to open the point.",
                            muted=True))
                t = Table(['Point', 'Object', 'State', 'Acknowledged', 'Type'])
                t.fill([[a['name'] or '–', f"{E.sd_ty(E.o_t(a['o']))} {E.o_i(a['o'])}",
                         (a['state'], {'fg': c['wa'] if a['state'] != 'fault' else c['se'], 'bold': True}),
                         (a['acked'], {'fg': c['se'] if a['acked'] == 'no' else c['mu']}), a['notify']] for a in al['items']],
                       [{'k': e['key'], 'o': a['o']} for a in al['items']])
                t.rowActivated.connect(lambda n: n and any(x['o'] == n['o'] for x in e.get('objs') or []) and self.go_node(n))
                t.fit_height()
                p.add(t)
        cats = self.ex.cats(e) if e else []
        if cats:
            p.add(heading('Points', 13))
            t = Table(['Category', 'Points'])
            t.fill([[E.cat_name(ty), len(os_)] for ty, os_ in cats], [{'k': e['key'], 't': ty} for ty, _ in cats])
            t.rowActivated.connect(lambda n: n and (self.open.add(f"{n['k']}|{n['t']}"), self.go_node(n)))
            t.fit_height()
            p.add(t)
        self.wlog(p, en['id'])

    def cat_page(self, p, en, e, ty, sel=None):
        os_ = [o for o in e.get('objs') or [] if o['ty'] == ty]
        p.add(label(E.cat_name(ty), bold=True, size=17))
        nm_ = dev_name(en['name'], en['id'])
        p.add(label(f"{len(os_)} point{'' if len(os_) == 1 else 's'} in device {en['id']}" + (f" “{nm_}”" if nm_ else '')
                    + ' · click a point to see its details', muted=True))
        r = QHBoxLayout()
        b = QPushButton('Refresh values')
        b.setEnabled(not self.ex.busy)
        b.clicked.connect(lambda: self.ex.run(self.ex.values_all, e))
        r.addWidget(b)
        r.addWidget(label(e.get('pm') or '', muted=True, wrap=False))
        r.addStretch(1)
        ww = QWidget()
        ww.setLayout(r)
        p.add(ww)
        t = Table(['#', 'Name', 'Value', 'Description', ''])
        t.fill([[o['inst'], o['name'], (f"{o['val']} {o['u']}".strip(), {'bold': True}), (o['desc'], {'fg': colors()['mu']}),
                 'commandable – double-click to open' if o['ty'] in E.CMD_T else ''] for o in os_],
               [{'k': e['key'], 'o': o['o']} for o in os_])
        t.rowActivated.connect(lambda n: n and self.go_node(n))
        t.cellClicked.connect(lambda r, _c, t=t: QTimer.singleShot(0, lambda n=t._data[r]: n and n != self.node and self.go_node(n)))
        if sel is not None:
            i = next((i for i, o in enumerate(os_) if o['o'] == sel), -1)
            if i >= 0:
                t.selectRow(i)
                QTimer.singleShot(0, lambda t=t, i=i: t.scrollTo(t.model().index(i, 0)))
        t.fit_height(40)
        p.add(t)
        self.wlog(p, en['id'])

    def point_page(self, p, en, e, o):
        if not o.get('pd') and not o.get('pdl'):
            o['pdl'] = 1
            self.ex.run(self._load_point, e, o)
        wr = o['ty'] in E.CMD_T
        nm = o['name'] or f"{E.sd_ty(o['ty'])} {o['inst']}"
        tn = E.cat_name(o['ty']).rstrip('s')
        ab = E.ABBR.get(o['ty']) or f"OBJ{o['ty']}"
        val = f"{o['val']} {o['u']}".strip()
        pd = o.get('pd')
        tabs = QTabWidget()
        tabs.setDocumentMode(False)
        # summary
        s = QWidget()
        sv = QVBoxLayout(s)
        sv.setContentsMargins(4, 12, 4, 4)
        sv.setSpacing(10)
        sv.addWidget(label(f'{tn} · {ab.lower()}{o["inst"]}', muted=True, wrap=False, sel=True))
        big = QLabel(val or '—')
        bf = big.font()
        bf.setPointSizeF(26)
        bf.setWeight(QFont.Weight.DemiBold)
        big.setFont(bf)
        big.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        big.setToolTip('Present value')
        sv.addWidget(big)
        flags = (pd or {}).get('flags')
        if flags and flags != 'normal':
            fl_ = label(f'⚠ {flags}', bold=True)
            fl_.setStyleSheet(f"color:{colors()['se']}")
            sv.addWidget(fl_)
        f = QFormLayout()
        for k, v in (('Display Name:', nm), ('Description:', o['desc'] or '')):
            le = QLineEdit(v)
            le.setReadOnly(True)
            f.addRow(k, le)
        sv.addLayout(f)
        sv.addLayout(self._point_buttons(en, e, o, wr))
        sv.addStretch(1)
        tabs.addTab(s, 'Summary')
        # details
        dw = QWidget()
        dv = QVBoxLayout(dw)
        dv.setContentsMargins(4, 12, 4, 4)
        dv.setSpacing(8)
        if not pd:
            dv.addWidget(U.busy_row('Reading the details from the device…'))
            dv.addWidget(U.Skeleton(5))
        elif pd.get('err'):
            er = label(pd['err'])
            er.setStyleSheet(f"color:{colors()['se']}")
            dv.addWidget(er)
        g = (pd or {})

        def ro(v):
            le = QLineEdit('' if v is None else str(v))
            le.setReadOnly(True)
            return le
        f1 = QFormLayout()
        f1.addRow('Display Name:', ro(nm))
        f1.addRow('Description:', ro(o['desc'] or ''))
        f1.addRow('Present Value =', ro(val))
        dv.addLayout(f1)
        dv.addLayout(self._point_buttons(en, e, o, wr, details=True))

        def section(t, into=None):
            b = label(t.upper(), bold=True, muted=True, wrap=False)
            f_ = b.font()
            f_.setPointSizeF(8)
            f_.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.6)
            b.setFont(f_)
            b.setContentsMargins(0, 10, 0, 0)
            (into or dv).addWidget(b)
        # the everyday fields first; calibration, BACnet configuration and the property list are technical
        tw = QWidget()
        tv_ = QVBoxLayout(tw)
        tv_.setContentsMargins(0, 0, 0, 0)
        tv_.setSpacing(8)
        section('Calibration', tv_)
        f2 = QFormLayout()
        f2.addRow('COV Increment:', ro(g.get('cov', '')))
        f2.addRow('Resolution:', ro(g.get('res') or '?'))
        f2.addRow('Scaling Range – Minimum:', ro(g.get('min', '')))
        f2.addRow('Scaling Range – Maximum:', ro(g.get('max', '')))
        tv_.addLayout(f2)
        section('BACnet Configuration', tv_)
        f3 = QFormLayout()
        f3.addRow('Object Name:', ro(nm))
        f3.addRow('Object Id:', ro(f"{tn} {o['inst']}"))
        f3.addRow('Object Type:', ro(tn))
        addr = f"bacnet://{en['id']}/{ab}:{o['inst']}"
        ar = QHBoxLayout()
        ar.addWidget(ro(addr), 1)
        cb = QPushButton('Copy')
        cb.clicked.connect(lambda: (QApplication.clipboard().setText(addr), self.win.toast('Address copied')))
        ar.addWidget(cb)
        f3.addRow('Address:', ar)
        oos = QCheckBox()
        oos.setEnabled(False)
        oos.setChecked(bool(g.get('oos')))
        f3.addRow('Out of Service:', oos)
        f3.addRow('Reliability:', ro(g.get('rel') or '?'))
        f3.addRow('Profile Name:', ro(g.get('prof') or '?'))
        tv_.addLayout(f3)
        section('Alarm & status')
        f5 = QFormLayout()
        flags = g.get('flags', '')
        fl = ro(flags or '?')
        if flags and flags != 'normal':
            fl.setStyleSheet(f"color:{colors()['se']};font-weight:600")
        f5.addRow('Status Flags:', fl)
        f5.addRow('Event State:', ro(g.get('es') or '?'))
        for k, t in (('hi', 'High Limit:'), ('lo', 'Low Limit:'), ('db', 'Deadband:'), ('nc', 'Notification Class:')):
            if g.get(k):
                f5.addRow(t, ro(g[k]))
        dv.addLayout(f5)
        ra = QPushButton('Read all properties…')
        ra.setToolTip('Read every property of this point from the device, with a copy / export button')
        ra.clicked.connect(lambda: all_props_dialog(self, e, o))
        rr = QHBoxLayout()
        rr.addWidget(ra)
        rr.addStretch(1)
        plb = U.disclose(QToolButton(), 'Property list')
        plb.setChecked(bool(o.get('pl')))
        plb.clicked.connect(lambda: self._toggle_pl(e, o))
        tv_.addWidget(plb)
        if o.get('pl'):
            pl = QLabel('\n'.join(o['pl']))
            pl.setFont(QFont('Cascadia Mono', 9))
            pl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            tv_.addWidget(pl)
        elif o.get('pll'):
            tv_.addWidget(U.busy_row('Reading…'))
        if wr:
            pa = g.get('pa')
            cp = next((i + 1 for i, v in enumerate(pa) if v['a']), 0) if pa else 0
            f4 = QFormLayout()
            f4.addRow('Relinquish Default:', ro(g.get('rd', '')))
            f4.addRow('Current Command Priority:', ro((cp if cp else 'none (at default)') if pa else '?'))
            dv.addLayout(f4)
            section('Priority Array')
            if pa:
                grid = QGridLayout()
                for c in range(4):
                    for i in range(4):
                        k = c * 4 + i + 1
                        v = pa[k - 1] if k - 1 < len(pa) else None
                        grid.addWidget(label(f'{k}:', muted=True, wrap=False), i, c * 2, Qt.AlignmentFlag.AlignRight)
                        grid.addWidget(label(v['s'] if v and v['a'] else '', bold=True, wrap=False), i, c * 2 + 1)
                dv.addLayout(grid)
            else:
                dv.addWidget(label('?', muted=True))
            dv.addWidget(label('To clear a priority level, use Write… and choose Release at that priority.', muted=True))
        tb = U.disclose(QToolButton(), 'Technical details')
        tb.setChecked(getattr(self, 'tech', False) or bool(o.get('pl')))
        tw.setVisible(tb.isChecked())
        tb.toggled.connect(lambda on: (setattr(self, 'tech', on), tw.setVisible(on)))
        dv.addWidget(tb)
        dv.addWidget(tw)
        dv.addLayout(rr)
        dv.addStretch(1)
        tabs.addTab(dw, 'Details')
        tabs.setCurrentIndex(self.ptab)
        tabs.currentChanged.connect(lambda i: setattr(self, 'ptab', i))
        nm_ = dev_name(en['name'], en['id'])
        p.add(label(f"{nm_ or 'Device ' + str(en['id'])}  ·  {tn}", muted=True))
        p.add(tabs)

    def _point_buttons(self, en, e, o, wr, details=False):
        r = QHBoxLayout()
        r.setSpacing(8)
        b = QPushButton('Read now')
        b.setEnabled(not self.ex.busy)
        b.clicked.connect(lambda: self.ex.run(self.ex.read_one, e, o))
        r.addWidget(b)
        if wr:
            w = QPushButton('Write…')
            w.clicked.connect(lambda: write_dialog(self.win, e, o))
            r.addWidget(w)
        if not details:
            s = QPushButton('Show packets')
            s.setToolTip('Show the packets that mention this point')
            s.clicked.connect(lambda: self.show_packets(f"{en['filt']} && info contains \"{C.tyname(o['ty'])} {o['inst']}\""))
            r.addWidget(s)
        r.addStretch(1)
        return r

    def _load_point(self, e, o):
        self.ex.read_detail(e, o)
        o['pdl'] = 0

    def _toggle_pl(self, e, o):
        if o.get('pl'):
            o['pl'] = None
        elif not o.get('pll'):
            o['pll'] = 1
            self.ex.run(self.ex.read_prop_list, e, o)
        self.build_right(None, None)

    def wlog(self, p, dev_id):
        L = [w for w in self.ex.wlog if dev_id is None or w['dev'] == dev_id]
        if not L:
            return
        p.add(heading('Write log' + (' – this device' if dev_id is not None else ''), 13))
        b = QPushButton('Export write log (.csv)')
        b.clicked.connect(lambda: self.save_csv('bacnet-write-log.csv', self.csv_wlog()))
        r = QHBoxLayout()
        r.addWidget(b)
        r.addStretch(1)
        ww = QWidget()
        ww.setLayout(r)
        p.add(ww)
        c = colors()
        t = Table(['Time', 'Device', 'Point', 'Value', 'Priority', 'Result', 'Read back'])
        t.fill([[time.strftime('%H:%M:%S', time.localtime(w['t'] / 1000)), f"{w['dev']}" + (f" · {w['dname']}" if w['dname'] else ''),
                 w['obj'] + (f" · {w['pname']}" if w['pname'] else ''), w['val'], w['pri'],
                 (w['res'], {'fg': c['no'] if w['res'] == 'accepted' else c['se']}),
                 (w.get('rb') or '') + (f" (overridden by priority {w['hi']})" if w.get('ov') else '')] for w in L[:100]])
        t.fit_height()
        p.add(t)

    # -------------------------------------------------------------- actions --
    def new_discover(self):
        self.home()

    def pick_capture(self):
        self.live = True
        self.pk = {'src': 'cap', 'sel': set(), 'run': None, 'stop': False}
        self.refresh()

    def scan(self, quiet=False):
        ex = self.ex
        if ex.busy == 'scan':
            ex.stop = True
            return
        if ex.busy:
            return
        if ex.mode == 'mstp' and not (ex.link and ex.link.on and ex.link.joined):
            if quiet:
                return
            self._ms_msg('Join the MS/TP trunk first (choose the port, press Find a free MAC, then Join trunk).'
                         if not (ex.link and ex.link.on) else
                         'Still waiting to be invited into the token ring – the scan can start once the PC has the token.', True)
            return
        self.live = True
        self.pk = None
        ex.run(ex.scan, lambda n: self.win.on_ui(lambda: n and self.win.labels_changed()))
        self.refresh()

    def run_picked(self):
        pk = self.pk
        if not pk or pk.get('run'):
            return
        keys = list(pk['sel'])
        if not keys:
            return
        pk['run'] = {'i': 0, 'n': len(keys), 'cur': ''}
        self.refresh()

        def work():
            first = None
            for i, k in enumerate(keys):
                if pk.get('stop'):
                    break
                pk['run'].update(i=i + 1)
                a = self.entry(k)
                if not a:
                    continue
                e = a['ex'] or (a['cap'] and self.ex.ensure(a['cap']))
                if not e:
                    continue
                pk['run']['cur'] = e['id']
                first = first or e
                e['stale'] = 1
                self.ex.notify()
                try:
                    if not e.get('name'):
                        self.ex.info(e)
                    self.ex.browse(e)
                except Exception as x:
                    e['pm'] = f'Could not read: {x}'

            def done():
                self.ex.busy = ''
                self.pk = None
                self.gopen.clear()
                self.ex.cache()
                if first:
                    prev = self.node
                    self.node = {'k': first['key']}
                    self._push(prev)
                    self.open.add(first['key'])
                self.refresh()
            self.win.on_ui(done)
        self.ex.run(work)

    def read_alarms(self, en):
        e = en['ex'] or (en['cap'] and self.ex.ensure(en['cap']))
        if not e:
            if self.is_ms(en):
                return self._ms_msg('This device is on an MS/TP trunk: join the trunk first.', True)
            return self.win.toast('This device is not reachable by IP')
        e['alarms_busy'] = 1
        self.node = {'k': e['key']} if not self.node else self.node

        def work():
            try:
                self.ex.alarms(e)
            finally:
                e['alarms_busy'] = 0
                self.ex.notify()
        self.ex.run(work)
        self.refresh()

    def read_points(self, en):
        e = en['ex'] or (en['cap'] and self.ex.ensure(en['cap']))
        if not e:
            if self.is_ms(en):
                return self._ms_msg('This device is on an MS/TP trunk: join the trunk first (Connection: MS/TP, then Join trunk).', True)
            return self.win.toast('This device is not reachable by IP')
        e['stale'] = 1
        self.open.add(e['key'])
        prev = self.node
        self.node = {'k': e['key']}
        self._push(prev)

        def work():
            self.ex.browse(e)
            for t, _ in self.ex.cats(e):
                self.open.add(f"{e['key']}|{t}")
            self.ex.notify()
        self.ex.run(work)
        self.refresh()

    def show_packets(self, f):
        if not self.win.ac:
            return self.win.toast("Open or start a capture to see this device's packets")
        self.win.go_packets(f)

    def names_as_labels(self):
        n = 0
        for d in list(self.ex.devs.values()):
            if d.get('name'):
                self.win.store.labels()['d'][str(d['id'])] = d['name']
                n += 1
        self.win.store.save_labels()
        self.win.labels_changed()
        self.win.toast(f'{n} device names added as labels')

    def _menu(self, pos):
        it = self.tree.itemAt(pos)
        d = it.data(0, K_ROLE) if it else None
        if not d or d[0] not in ('d',):
            return
        en = self.entry(d[1])
        if not en:
            return
        ex = en['ex']
        m = QMenu(self)
        m.addAction('Open in Discover', lambda: self.open_device(d[1]))
        a = m.addAction('Refresh points' if ex and ex.get('objs') else 'Read points', lambda: self.read_points(en))
        a.setEnabled(bool(ex or en['cap']))

        def ref():
            e2 = ex or self.ex.ensure(en['cap'])
            if e2:
                def w():
                    self.ex.info(e2)
                    self.ex.cache()
                    self.ex.labels_from_names()
                self.ex.run(w)
        m.addAction('Refresh name and details', ref).setEnabled(bool(ex or en['cap']))
        m.addSeparator()
        m.addAction('Show this device’s packets', lambda: self.show_packets(en['filt'])).setEnabled(bool(self.win.ac))
        m.addAction('Name this device…', lambda: self.win.edit_label('d', en['id']))
        m.addSeparator()
        m.addAction('Copy device ID', lambda: QApplication.clipboard().setText(str(en['id'])))
        ip = en['ip'] or (ex and ex.get('ip')) or ''
        m.addAction('Copy IP address', lambda: QApplication.clipboard().setText(ip)).setEnabled(bool(ip))
        m.addAction('Export points (.csv)', lambda: self.save_csv(f"device-{en['id']}-points.csv", self.csv_points(ex))).setEnabled(bool(ex and ex.get('objs')))
        m.addSeparator()

        def forget():
            self.ex.devs.pop(ex['key'], None)
            if self.node and self.node['k'] == ex['key']:
                self.node = None
            self.ex.cache()
            self.refresh()
        m.addAction('Forget this discovered device', forget).setEnabled(bool(ex) and not en['cap'])
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def options(self):
        o = self.ex.opt
        d = QDialog(self)
        d.setWindowTitle('Discovery options')
        v = QVBoxLayout(d)
        v.addWidget(label('Discovery only sends Who-Is and read requests – it never changes anything. Writing is a separate switch on the Discover tab.', muted=True))
        f = QFormLayout()
        to = QLineEdit(o.get('to', ''))
        to.setPlaceholderText('leave empty for automatic, or e.g. 10.0.255.255')
        lo = QLineEdit(o.get('lo', ''))
        lo.setPlaceholderText('from')
        hi = QLineEdit(o.get('hi', ''))
        hi.setPlaceholderText('to')
        rr = QHBoxLayout()
        rr.addWidget(lo)
        rr.addWidget(QLabel('–'))
        rr.addWidget(hi)
        bb_ = QLineEdit(o.get('bbmd', ''))
        bb_.setPlaceholderText('BBMD address, e.g. 10.20.0.5')
        f.addRow('Send to', to)
        f.addRow('Only device IDs', rr)
        f.addRow('Also scan other subnets through a BBMD\n(registers this PC as a foreign device for 5 minutes)', bb_)
        v.addLayout(f)
        lab = QCheckBox('Use discovered device names as labels in captures')
        lab.setChecked(bool(o.get('lab')))
        auto = QCheckBox('Discover automatically when a live capture starts')
        auto.setChecked(bool(o.get('auto')))
        v.addWidget(lab)
        v.addWidget(auto)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(d.accept)
        bb.rejected.connect(d.reject)
        v.addWidget(bb)
        d.resize(520, 260)
        if d.exec() == QDialog.DialogCode.Accepted:
            o.update(to=to.text().strip(), lo=lo.text().strip(), hi=hi.text().strip(), bbmd=bb_.text().strip(),
                     lab=1 if lab.isChecked() else 0, auto=1 if auto.isChecked() else 0)
            self.ex.save_opt()
            self.win.toast('Discovery options saved')

    # ---------------------------------------------------------------- export --
    def csv_devices(self):
        rows = [[d['id'], d.get('name') or '', d['ip'] + (' / ' + d['sa'] if d.get('sa') else ''), '' if d.get('sn') is None else d['sn'],
                 d.get('vendor') or C.VN.get(d.get('vn'), ''), d.get('vn'), d.get('model') or '', d.get('fw') or '', d.get('sw') or '',
                 d.get('desc') or '', d.get('loc') or '', d.get('mx')] for d in sorted(self.ex.devs.values(), key=lambda d: d['id'])]
        return csv_text('Device ID,Name,Address,Network,Vendor,Vendor ID,Model,Firmware,Software version,Description,Location,Max APDU', rows)

    @staticmethod
    def csv_points(d):
        return csv_text('Device ID,Device name,Object type,Instance,Object name,Present value,Units,Description',
                        [[d['id'], d.get('name') or '', E.sd_ty(o['ty']), o['inst'], o['name'], o['val'], o['u'], o['desc']] for o in d.get('objs') or []])

    def csv_wlog(self):
        return csv_text('Time,Device,Device name,Point,Value,Priority,Result,Read back,Highest active priority',
                        [[time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(w['t'] / 1000)), w['dev'], w['dname'],
                          w['obj'] + (f" ({w['pname']})" if w['pname'] else ''), w['val'], w['pri'], w['res'], w.get('rb') or '',
                          w.get('hi') or ''] for w in self.ex.wlog])

    def save_csv(self, name, text):
        """Save a table as Excel (.xlsx) or a spreadsheet (.csv) - the user picks in the Save dialog."""
        from bi_common import csv_to_xlsx
        xl, cs = 'Excel workbook (*.xlsx)', 'Spreadsheet (*.csv)'
        base = name.rsplit('.', 1)[0]
        p, chosen = QFileDialog.getSaveFileName(self, 'Save', base + '.xlsx', f'{xl};;{cs}', xl)
        if not p:
            return
        as_xl = chosen == xl or p.lower().endswith('.xlsx')
        if not p.lower().endswith(('.xlsx', '.csv')):
            p += '.xlsx' if as_xl else '.csv'
        try:
            if as_xl:
                with open(p, 'wb') as f:
                    f.write(csv_to_xlsx(text, base[:31]))
            else:
                with open(p, 'w', encoding='utf-8-sig', newline='') as f:
                    f.write(text)
            self.win.toast('Saved ' + p)
        except OSError as e:
            self.win.toast(f'Save failed: {e.strerror}')

    def formats(self):
        def html():
            rows = [[d['id'], esc(d.get('name') or ''), esc(E.Explorer.addr(d)), esc(d.get('vendor') or C.VN.get(d.get('vn'), '')),
                     esc(d.get('model') or ''), esc(d.get('st') or '')] for d in sorted(self.ex.devs.values(), key=lambda d: d['id'])]
            return doc('Discovered devices', f'<h3>Discovered devices</h3><p class="mu">Saved {stamp()}</p>' +
                       html_table(['Device ID', 'Name', 'Address', 'Vendor', 'Model', 'Status'], rows))
        return [('html', 'Web page – the discovered devices (*.html)', 'html', html),
                ('csv', 'Spreadsheet – one row per device (*.csv)', 'csv', lambda: '﻿' + self.csv_devices())]


# ============================================================ dialogs --
def all_props_dialog(view, dev, o):
    """Every property of one point, read live, with Copy and Export."""
    win, ex = view.win, view.ex
    d = QDialog(win)
    name = o['name'] or f"{E.sd_ty(o['ty'])} {o['inst']}"
    d.setWindowTitle(f"All properties – {name}")
    v = QVBoxLayout(d)
    v.addWidget(label(f"Device {dev['id']}" + (f" “{dev_name(dev.get('name'), dev['id'])}”" if dev_name(dev.get('name'), dev['id']) else '') +
                      f" · {E.sd_ty(o['ty'])} {o['inst']} · read just now from the device (read-only)", muted=True))
    msg = label('Reading every property…', muted=True)
    v.addWidget(msg)
    t = Table(['Property', 'Value'])
    t.setWordWrap(True)
    v.addWidget(t, 1)
    bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    cp = bb.addButton('Copy', QDialogButtonBox.ButtonRole.ActionRole)
    xp = bb.addButton('Export…', QDialogButtonBox.ButtonRole.ActionRole)
    cp.setEnabled(False)
    xp.setEnabled(False)
    bb.rejected.connect(d.reject)
    v.addWidget(bb)
    rows = []

    def done(res, err):
        if err:
            msg.setText(err)
            msg.setStyleSheet(f"color:{colors()['se']}")
            return
        rows[:] = sorted(res, key=lambda x: x[0])
        msg.setText(f'{len(rows)} properties')
        t.fill([[a, b] for a, b in rows])
        t.resizeRowsToContents()
        cp.setEnabled(True)
        xp.setEnabled(True)

    def work():
        try:
            res, err = ex.read_all(dev, o['o']), ''
        except RuntimeError as e:
            res, err = [], str(e)
        win.on_ui(lambda: done(res, err))
    cp.clicked.connect(lambda: (QApplication.clipboard().setText('\n'.join(f'{a}\t{b}' for a, b in rows)), win.toast('Copied')))
    xp.clicked.connect(lambda: view.save_csv(f"device-{dev['id']}-{E.ABBR.get(o['ty'], 'obj').lower()}{o['inst']}-properties.csv",
                                             csv_text('Property,Value', rows)))
    ex.run(work)
    d.resize(640, 620)
    d.exec()


def arm_dialog(win):
    d = QDialog(win)
    d.setWindowTitle('Turn on write access?')
    v = QVBoxLayout(d)
    v.addWidget(label('This lets you send Write Property commands (present-value, with a priority) to devices from the Discover '
                      'tab. A wrong value can start or stop real equipment.'))
    v.addWidget(label('• Only one point at a time, to one device, and each write asks you to confirm.\n'
                      '• It switches itself off after the time you choose, and a red bar stays on screen while it is on.\n'
                      '• Every write is recorded in the write log (and in writes.log next to the app’s settings).', muted=True))
    ok = QCheckBox('I understand this changes live equipment')
    v.addWidget(ok)
    row = QHBoxLayout()
    row.addWidget(QLabel('Switch off after'))
    mins = QComboBox()
    for m in (5, 15, 30, 60):
        mins.addItem(f'{m} minutes', m)
    mins.setCurrentIndex(1)
    row.addWidget(mins)
    row.addStretch(1)
    v.addLayout(row)
    bb = QDialogButtonBox()
    go = bb.addButton('Turn on write access', QDialogButtonBox.ButtonRole.AcceptRole)
    go.setStyleSheet('QPushButton{background:#c42b1c;color:white} QPushButton:disabled{background:#d9a9a4}')
    go.setEnabled(False)
    bb.addButton(QDialogButtonBox.StandardButton.Cancel)
    ok.toggled.connect(go.setEnabled)
    bb.accepted.connect(d.accept)
    bb.rejected.connect(d.reject)
    v.addWidget(bb)
    d.resize(520, 240)
    if d.exec() != QDialog.DialogCode.Accepted:
        return False
    try:
        win.explorer.arm(mins.currentData())
    except Exception:
        win.toast('Could not turn on write access')
        return False
    win.explorer.pump()
    return True


PRI = {1: ' – manual life safety', 2: ' – automatic life safety', 5: ' – critical equipment', 6: ' – minimum on/off',
       8: ' – manual operator (usual for technicians)', 16: ' – lowest (schedules)'}


def write_dialog(win, dev, row):
    ex = win.explorer
    if not ex.armed():
        if not arm_dialog(win):
            return
        win.wb_draw()
    binary = row['ty'] in (4, 5)
    ms = row['ty'] in (14, 19)
    tn = f"{E.sd_ty(row['ty'])} {row['inst']}"
    nm = row.get('name') or tn
    dn = dev.get('name') or f"device {dev['id']}"
    d = QDialog(win)
    d.setWindowTitle(f'Write to {nm}')
    v = QVBoxLayout(d)
    v.addWidget(label(f"Device {dev['id']}" + (f" “{dev_name(dev.get('name'), dev['id'])}”" if dev_name(dev.get('name'), dev['id']) else '') + f' · {tn} · present-value', muted=True))
    v.addWidget(label(f"Current value: {(str(row.get('val') or '').strip() or 'unknown')} {row.get('u') or ''}", bold=True))
    f = QFormLayout()
    if binary:
        val = QComboBox()
        val.addItem('active (on)', 'active')
        val.addItem('inactive (off)', 'inactive')
    else:
        val = QLineEdit()
        val.setPlaceholderText('state number, e.g. 2' if ms else 'number, e.g. 21.5')
    f.addRow('New value', val)
    pri = QComboBox()
    for i in range(1, 17):
        pri.addItem(f'{i}{PRI.get(i, "")}', i)
    pri.setCurrentIndex(7)
    f.addRow('Priority', pri)
    v.addLayout(f)
    rel = QCheckBox('Release – remove my command at this priority (writes NULL)')
    rel.toggled.connect(lambda on: val.setEnabled(not on))
    v.addWidget(rel)
    msg = QLabel()
    msg.setWordWrap(True)
    msg.setTextFormat(Qt.TextFormat.RichText)
    v.addWidget(msg)
    bb = QDialogButtonBox()
    go = bb.addButton('Write…', QDialogButtonBox.ButtonRole.ActionRole)
    go.setStyleSheet('QPushButton{background:#c42b1c;color:white;padding:4px 14px}')
    close = bb.addButton(QDialogButtonBox.StandardButton.Close)
    close.clicked.connect(d.reject)
    v.addWidget(bb)
    st = {'step': 0}
    c = colors()

    def text():
        return val.currentData() if binary else val.text().strip()

    def click():
        p = pri.currentData()
        release = rel.isChecked()
        if release:
            enc = [0]
        else:
            enc = E.ex_enc(row['ty'], text())
            if not enc:
                msg.setText(f'<span style="color:{c["se"]}">That is not a valid value for this kind of point.</span>')
                return
        shown = 'RELEASE (null)' if release else (text() if binary else f"{text()} {row.get('u') or ''}")
        if st['step'] == 0:
            st['step'] = 1
            go.setText(f"Confirm: {'release' if release else 'write ' + shown.strip()} at priority {p}")
            msg.setText(f"<b>Check before you confirm:</b> {'release your command on' if release else 'set'} <b>{esc(nm)}</b> in "
                        f"<b>{esc(dn)}</b>{'' if release else ' to <b>' + esc(shown.strip()) + '</b>'} at priority <b>{p}</b>.")
            for w in (val, pri, rel):
                w.setEnabled(False)
            return
        go.setEnabled(False)
        go.setText('Writing…')

        def work():
            _e, m, ok = ex.write(dev, row, enc, p, release, shown)

            def done():
                msg.setText(f'<span style="color:{c["no"] if ok else c["se"]}"><b>{esc(m.split(". ")[0])}.</b></span> ' + esc('. '.join(m.split('. ')[1:])))
                go.hide()
                close.setText('Done')
                if 'x' in win.views:
                    win.views['x'].refresh()
            win.on_ui(done)
        ex.run(work)
    go.clicked.connect(click)
    d.resize(560, 300)
    d.exec()


def read_now(win, d, ob):
    """Right-click a packet: read that point straight from the device (read-only)."""
    ex = win.explorer
    e = ex.ensure(d)
    if not e:
        return win.toast('This device is not reachable by IP')
    dlg = QDialog(win)
    lab = win.labels.d(d['id'])
    dlg.setWindowTitle(f"Device {d['id']}" + (f' “{lab}”' if lab else '') + f" – {E.sd_ty(ob['ty'])} {ob['inst']}")
    v = QVBoxLayout(dlg)
    v.addWidget(label('Read just now from the network (read-only).', muted=True))
    body = QLabel('Reading…')
    body.setTextFormat(Qt.TextFormat.RichText)
    body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    body.setWordWrap(True)
    v.addWidget(body)
    bb = QDialogButtonBox()
    again = bb.addButton('Read again', QDialogButtonBox.ButtonRole.ActionRole)
    wr = bb.addButton('Write…', QDialogButtonBox.ButtonRole.ActionRole)
    wr.setVisible(False)
    bb.addButton(QDialogButtonBox.StandardButton.Close).clicked.connect(dlg.reject)
    v.addWidget(bb)
    row = {'o': ob['o'], 'ty': ob['ty'], 'inst': ob['inst'], 'name': '', 'val': '', 'u': '', 'desc': ''}

    def go():
        body.setText('Reading…')

        def work():
            r = ex.req(e, E.ex_rpm([[ob['o'], [77, 85, 117, 28]]]), 3.0)
            ok = False
            if r.get('d'):
                L = E.ex_dec_rpm(r['d'], r['k'], r['L'])
                if L:
                    ex._fill(row, L[0]['pr'])
                    ok = True

            def done():
                if ok:
                    body.setText(f"<table cellpadding='4'><tr><td>Name</td><td><b>{esc(row['name'])}</b></td></tr>"
                                 f"<tr><td>Present value</td><td><b>{esc(row['val'] or '(no present value)')} {esc(row['u'])}</b></td></tr>"
                                 f"<tr><td>Description</td><td>{esc(row['desc'])}</td></tr></table>")
                    wr.setVisible(ob['ty'] in E.CMD_T)
                else:
                    body.setText(f"<span style='color:{colors()['se']}'>" +
                                 esc('No answer from the device.' if r.get('to') else (r.get('err') or 'Could not read')) + '</span>')
            win.on_ui(done)
        ex.run(work)
    again.clicked.connect(go)
    wr.clicked.connect(lambda: (dlg.accept(), write_dialog(win, e, row)))
    go()
    dlg.resize(460, 220)
    dlg.exec()

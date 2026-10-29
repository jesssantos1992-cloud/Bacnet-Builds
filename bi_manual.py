"""
bi_manual.py - the user manual (Help > User manual, F1): chapters in plain English, shown in a window
with a contents list, a search box and links between chapters. It can also be saved as a web page.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QTextCursor, QTextDocument
from PySide6.QtWidgets import (QDialog, QFileDialog, QFrame, QHBoxLayout, QLineEdit, QListWidget, QListWidgetItem,
                               QPushButton, QSplitter, QTextBrowser, QVBoxLayout, QWidget)

import bi_ui as U
from bi_common import AUTHOR, colors, is_dark, label


def k(keys):
    """Keyboard keys inside the manual text."""
    return ' + '.join(f'<span class="key">{x}</span>' for x in keys.split('+'))


def go(cid, text):
    return f'<a href="#{cid}">{text}</a>'


def note(text):
    return f'<table class="note" width="100%" cellpadding="10"><tr><td>{text}</td></tr></table>'


# ------------------------------------------------------------------ chapters --
# (id, title, part, html). Parts become headings in the contents list.
CH = []


def ch(cid, title, part, body):
    CH.append((cid, title, part, body))


ch('welcome', 'Welcome', 'Start here', f"""
<p>BACnet Inspector helps you see what is happening on a BACnet building-automation network and find problems
quickly. It works in two ways:</p>
<ul>
<li><b>Capture</b> – open a recording of the network traffic (a <i>.pcap</i> or <i>.pcapng</i> file), or record one
live, then look at it in plain English: which devices are there, what they are saying to each other, what is wrong and
how to fix it.</li>
<li><b>Discover</b> – talk to the network directly: find every device, read its points (temperatures, set points,
fan commands…) and their alarms, and – only when you switch it on – change a value.</li>
</ul>
<p>It understands <b>BACnet/IP</b> (BACnet over Ethernet / Wi-Fi, UDP port 47808) and <b>BACnet MS/TP</b> (the
RS-485 twisted-pair trunks that connect field controllers).</p>
<h3>Who it is for</h3>
<p>Technicians, commissioning engineers and anyone supporting a BMS. You do not need to know how BACnet works inside:
every packet has a <i>Meaning</i> line, and every problem comes with the reason it matters and numbered steps to fix it.</p>
<h3>Is it safe to use on a live site?</h3>
<p>Yes. Opening and analysing captures never sends anything. Discover only sends <i>Who-Is</i> and read requests,
which every BACnet device answers routinely. Changing a value is impossible until you deliberately switch on
{go('write', 'write access')}, and even then each change needs a second confirmation. See {go('safety', 'Privacy and safety')}.</p>
<h3>How to use this manual</h3>
<p>Pick a chapter on the left, or type in the search box above the contents to find a word anywhere in the manual.
New to the app? Read {go('quick', 'Quick start')} first. Press {k('F1')} at any time to open this manual at the page
for what you are looking at.</p>
""")

ch('quick', 'Quick start (5 minutes)', 'Start here', f"""
<h3>Look at a capture you already have</h3>
<ol>
<li>Click <b>Open capture</b> (or press {k('Ctrl+O')}) and choose a <i>.pcap</i> or <i>.pcapng</i> file – or simply
drag the file onto the window.</li>
<li>The capture opens in its own tab and the <b>Packets</b> list fills in. A thin blue line under the toolbar shows
progress for big files.</li>
<li>Click <b>Findings</b> in the sidebar. This is the most useful page: each problem found, why it matters and how to
fix it.</li>
<li>Click <b>Devices</b> to see every router, network and device, or <b>Network map</b> for a picture of it.</li>
<li>Back in <b>Packets</b>, click any packet to see it decoded underneath.</li>
</ol>
<h3>Record a live capture</h3>
<ol>
<li>Click the <b>Live capture</b> tab.</li>
<li>Choose your network adapter (for BACnet/IP) or your USB RS-485 adapter (for MS/TP) in the <b>Capture</b> box.</li>
<li>For MS/TP, press <b>Detect</b> to find the baud rate.</li>
<li>Press <b>Start</b>. Packets appear as they arrive; every analysis page updates by itself.</li>
<li>Press <b>Stop</b> when you have enough, and <b>Save capture</b> to keep it as a file.</li>
</ol>
<h3>Find the devices on a network</h3>
<ol>
<li>Click <b>Discover</b> at the top (or press {k('Ctrl+5')}).</li>
<li>Press <b>Scan network</b>. Every device that answers is listed on the left.</li>
<li>Click a device, then <b>Read points</b>. Click a category, then a point, to see its value and details.</li>
</ol>
{note('Tip: press ' + k('Ctrl+K') + ' at any time to search for any view, device, point or command by name.')}
""")

ch('window', 'The window at a glance', 'Start here', f"""
<table cellpadding="6" width="100%">
<tr><td width="28%"><b>Capture | Discover</b></td><td>The switch at the top changes between looking at captures and
working with the live network. {k('Ctrl+5')} opens Discover; {k('Ctrl+1')} goes back to the packets.</td></tr>
<tr><td><b>Back arrow</b></td><td>Top left. Goes back to the page you were on before. {k('Alt+Left')} or the Back
button on your mouse do the same.</td></tr>
<tr><td><b>Search</b></td><td>Top right. Jump to anything by typing ({k('Ctrl+K')}). See {go('palette', 'Search everything')}.</td></tr>
<tr><td><b>Sidebar</b></td><td>The pages that analyse the open capture, grouped under Analyze, Network, MS/TP and
Tools. A number next to Findings or Devices shows how many there are.</td></tr>
<tr><td><b>Tabs</b></td><td>One tab per open capture, plus the <b>Live capture</b> tab. Drag a tab to reorder it;
click its × to close it (a message at the bottom offers <b>Undo</b>). The <b>+</b> button opens another file.</td></tr>
<tr><td><b>Filter box</b></td><td>On the Packets page: type a display filter to show only some packets. See
{go('filter', 'Display filters')}.</td></tr>
<tr><td><b>Progress line</b></td><td>A thin blue line under the toolbar moves while something is working (opening a
file, scanning, sorting).</td></tr>
<tr><td><b>Messages</b></td><td>Short messages appear in a small banner at the bottom of the window and fade away by
themselves.</td></tr>
<tr><td><b>Banners</b></td><td>A <b>red bar</b> means write access is on. A <b>blue bar</b> means an update is
available.</td></tr>
</table>
<p>The app remembers your open captures, their filters, the window size and the page you were on, and brings them back
next time.</p>
""")

ch('open', 'Opening captures', 'Captures', f"""
<p>BACnet Inspector reads <b>.pcap</b> and <b>.pcapng</b> files – the standard format written by Wireshark,
tcpdump, most routers and BACnet tools, and by this app's own live capture.</p>
<h3>Ways to open a file</h3>
<ul>
<li><b>Open capture</b> button, the <b>+</b> next to the tabs, or File &gt; Open capture ({k('Ctrl+O')}). You can
pick several files at once.</li>
<li>Drag files from File Explorer onto the window.</li>
<li>In File Explorer, right-click a capture and choose <b>Open with &gt; BACnet Inspector</b> (offered when the option
was ticked during installation). If the app is already open, the file opens as a new tab in the same window.</li>
</ul>
<h3>Tabs</h3>
<p>Each file gets its own tab, so you can switch between captures without opening them again. Each tab keeps its own
filter, scroll position and selected packet. Close a tab with its × or {k('Ctrl+W')}; the message at the bottom has an
<b>Undo</b> button for a few seconds.</p>
<h3>Large files</h3>
<p>Files with hundreds of thousands of packets open in the background – you can keep working in other tabs while the
progress line fills. Opening a file reads it from your disk only; nothing is uploaded.</p>
<h3>What is decoded</h3>
<ul>
<li>BACnet/IP (including messages that came through a BACnet router or BBMD – these show a <i>Gateway</i>).</li>
<li>BACnet MS/TP frames captured from an RS-485 trunk (token passing, polls and data).</li>
<li>Damaged frames (bad checksums, cut-off packets) are kept and marked so you can see them.</li>
</ul>
""")

ch('live', 'Live capture', 'Captures', f"""
<p>The <b>Live capture</b> tab records traffic as it happens. Its controls appear at the top of the tab.</p>
<h3>Choose where to listen</h3>
<p>The <b>Capture</b> box lists everything you can record from. The best choice is marked “★ picked for you”.</p>
<ul>
<li><b>[Wireshark/Npcap]</b> network adapters – the recommended way for BACnet/IP. Needs Wireshark (which includes
Npcap) installed on the PC. Supports a capture filter under <b>More options</b> (the default records only BACnet ports
47808–47823).</li>
<li><b>[MS/TP serial]</b> – a USB RS-485 adapter wired onto an MS/TP trunk. Choose the <b>Baud</b> rate, or press
<b>Detect</b> to listen at each common rate and pick the one that works. The PC only listens – it never transmits on
the trunk while capturing.</li>
<li><b>[built-in, BACnet/IP only, needs Administrator]</b> – works without installing anything, but Windows only
allows it when the app is started as Administrator.</li>
</ul>
<p>Press the circular arrow to look for adapters again (for example after plugging in a USB adapter).</p>
<h3>Recording</h3>
<ul>
<li><b>Start</b> / <b>Stop</b> – begin and end recording. A green dot on the tab shows it is recording.</li>
<li><b>Follow newest</b> – keeps the newest packet in view. Untick it to read older packets while it records.</li>
<li><b>Clear</b> – throws away what has been recorded so far.</li>
<li><b>Save capture</b> – saves everything recorded as a <i>.pcapng</i> file you can open later or send to someone.</li>
</ul>
<p>The live tab keeps the newest 100,000 packets. Every analysis page (Findings, Devices, Online board…) updates by
itself while recording.</p>
<h3>Ask the network</h3>
<p>Open <b>Ask the network</b> to send a one-off question and see the answers in the list:</p>
<ul>
<li><b>Find all devices (Who-Is)</b> – every device answers with an I-Am.</li>
<li><b>Find routers (Who-Is-Router)</b> – every BACnet router answers with the networks it can reach.</li>
<li><b>Ask network number</b> – routers say which network number this subnet has.</li>
</ul>
<p>Use <b>Send from</b> if the PC has several network addresses, and <b>to</b> for a different broadcast address.
Sending is not possible on an MS/TP serial connection (a listener must stay silent on a trunk).</p>
<h3>MS/TP frames from Discover</h3>
<p>While Discover is joined to an MS/TP trunk (see {go('dmstp', 'Discover over MS/TP')}), every frame it sends and
receives also appears in the Live capture tab, so you can watch the conversation.</p>
""")

ch('packets', 'The packet list', 'Captures', f"""
<p>The <b>Packets</b> page lists every message in the capture, one per row, with the decoded details of the selected
packet underneath.</p>
<h3>Columns</h3>
<table cellpadding="5">
<tr><td><b>No.</b></td><td>Packet number in the capture. A ★ means it is bookmarked.</td></tr>
<tr><td><b>Time</b></td><td>Seconds since the first packet.</td></tr>
<tr><td><b>Source / Destination</b></td><td>Who sent it and who it was for: an IP address and port, an MS/TP MAC, or
<i>net N / address</i> for a device behind a router.</td></tr>
<tr><td><b>Gateway</b></td><td>The BACnet router the message came through, if any.</td></tr>
<tr><td><b>Protocol</b></td><td>BACnet/IP or MS/TP.</td></tr>
<tr><td><b>Len</b></td><td>Size in bytes.</td></tr>
<tr><td><b>Info</b></td><td>What the message is, in words – for example “I-Am: device 2001 announces itself” or
“Read Property request: analog-input 1 present-value”.</td></tr>
</table>
<p>Coloured highlights make the important parts easy to spot: <b>IP addresses</b> in blue, <b>MS/TP MACs</b> in orange,
<b>network numbers</b> in purple and <b>device IDs</b> in green. Rows with damaged frames have a red tint. Names you
have given devices and networks (see {go('names', 'Names and labels')}) appear next to their numbers.</p>
<h3>Details and bytes</h3>
<p>Click a packet to decode it in the lower-left panel, layer by layer, with a <i>Meaning</i> line in plain English.
The BACnet APDU part shows everything the message carries, like Wireshark: invoke ID, max response size,
segmentation, the service, and every parameter – which object and property, the values (with units, states and
flags named), priorities, time stamps, errors – nested as deep as the message goes. For example a COV notification
shows the subscriber, the device, the object, the time remaining and each changed value; a trend log read shows each
record as <i>time = value</i>. Hover over a line that is cut off to read all of it. The lower-right panel shows the
raw bytes. Drag the divider between the list and the details to resize them (View &gt; Reset pane size puts them
back). Right-click the details to copy them.</p>
<h3>Working with the list</h3>
<ul>
<li><b>Sort</b> – click a column title; click again to reverse; a third time to go back to capture order. Big
captures sort in the background.</li>
<li><b>Filter by a value</b> – double-click any cell to show only the packets with that value.</li>
<li><b>Right-click</b> a packet for more: Apply as Filter (selected, not selected, and/or combinations), Prepare as
Filter (puts it in the box without applying), Conversation (traffic between these two addresses), Copy, Open this
device in Discover, Read this point now, Bookmark and Add note.</li>
<li><b>Keyboard</b> – {k('Up')} / {k('Down')} and {k('PgUp')} / {k('PgDn')} move through packets.</li>
</ul>
<h3>Bookmarks and notes</h3>
<p>Bookmark a packet with {k('Ctrl+B')} or the right-click menu. Add a note to explain it (a packet with a note is
also bookmarked). Bookmarks and notes are saved on this computer for that capture and come back when you open it
again. Edit &gt; Show bookmarked packets lists them; they are included in saved packet lists and reports.</p>
""")

ch('search', 'Searching packets', 'Captures', f"""
<p>The search box above the packet list ({k('Ctrl+F')}) finds packets by a device ID, an IP address, a network number
or any word. Several words must all match.</p>
<ul>
<li><b>Highlight</b> – matching packets are highlighted in yellow and the list stays complete. Press {k('Enter')}
for the next match and {k('Shift+Enter')} for the previous one (or use the arrow buttons). The count shows
“3 of 25”.</li>
<li><b>Filter</b> – only matching packets are shown.</li>
</ul>
<p>{k('Esc')} clears the search. Search works on top of the display filter, so you can filter to one network and then
search inside it.</p>
""")

ch('filter', 'Display filters', 'Captures', f"""
<p>The filter box above the list shows only the packets that match a rule. Type the rule and the list updates; a
<b>green dot</b> means the filter is valid, a <b>red dot</b> means it is not. {k('Ctrl+L')} jumps to the box,
{k('Esc')} clears it. The filter is remembered for each tab.</p>
<h3>Quick filter buttons</h3>
<p>The buttons above the list apply common filters with one click: All, I-Am, Who-Is, Routers, Via gateway,
BACnet/IP, MS/TP, Damaged, Refused, Writes, Commands, Errors &amp; aborts, COV and Time sync / DCC.</p>
<p>Type your own filter and press <b>＋ Save current filter</b> to keep it as a button of your own (marked ★).
Right-click a saved button to remove it.</p>
<h3>Writing a filter</h3>
<table cellpadding="5">
<tr><td><code>device == 1001</code></td><td>exact match</td></tr>
<tr><td><code>len &gt; 100</code></td><td>also <code>&lt;</code>, <code>&gt;=</code>, <code>&lt;=</code>, <code>!=</code></td></tr>
<tr><td><code>info contains "Read"</code></td><td>text anywhere in a field</td></tr>
<tr><td><code>a &amp;&amp; b</code>, <code>a || b</code>, <code>!a</code></td><td>and, or, not – use brackets to group:
<code>(a || b) &amp;&amp; c</code></td></tr>
<tr><td><code>bad</code>, <code>iam</code>, <code>whois</code></td><td>yes/no flags on their own</td></tr>
</table>
<h3>Fields you can use</h3>
<table cellpadding="5">
<tr><td><code>no</code>, <code>time</code>, <code>len</code></td><td>packet number, seconds from the start, size</td></tr>
<tr><td><code>src</code>, <code>dst</code>, <code>addr</code></td><td>source, destination, either address (as shown in the list)</td></tr>
<tr><td><code>host</code></td><td>the sender <i>or</i> the receiver</td></tr>
<tr><td><code>ip</code></td><td>an IP address anywhere in the packet – sender, receiver or router, with or without the port:
<code>ip == "10.0.0.5"</code></td></tr>
<tr><td><code>mac</code></td><td>an MS/TP MAC anywhere in the packet: <code>mac == 5</code></td></tr>
<tr><td><code>sender</code>, <code>receiver</code></td><td>the device that sent / should receive the message, even
behind a router: <code>sender == "network 2400, MAC 7"</code></td></tr>
<tr><td><code>service</code></td><td>the request: <code>service == "Read Property"</code></td></tr>
<tr><td><code>object</code></td><td>the object a request, write or COV is about: <code>object == "analog-input 1"</code></td></tr>
<tr><td><code>mstp.type</code>, <code>mstp.src</code>, <code>mstp.dst</code></td><td>MS/TP frame type and MACs:
<code>mstp.type == "Token" &amp;&amp; mstp.dst == 12</code></td></tr>
<tr><td><code>from</code>, <code>to</code></td><td>the logical sender / receiver (the device itself, even behind a router)</td></tr>
<tr><td><code>proto</code></td><td><code>"BACnet/IP"</code> or <code>"MS/TP"</code></td></tr>
<tr><td><code>info</code></td><td>the Info text</td></tr>
<tr><td><code>device</code></td><td>a device ID mentioned in the packet</td></tr>
<tr><td><code>net</code>, <code>dnet</code></td><td>source network, destination network</td></tr>
<tr><td><code>gateway</code></td><td>the router a message came through</td></tr>
<tr><td><code>bad</code>, <code>iam</code>, <code>whois</code>, <code>nak</code>, <code>router</code>, <code>write</code>,
<code>command</code>, <code>cov</code>, <code>error</code>, <code>bookmark</code>, <code>note</code></td><td>flags: damaged,
I-Am, Who-Is, refused, router messages, writes, commands, COV, errors, bookmarked, has a note</td></tr>
</table>
<p>Wireshark names also work: <code>ip.addr</code>, <code>ip.src</code>, <code>ip.dst</code>, <code>bacnet.device</code>,
<code>bacnet.net</code>, <code>frame.len</code>, <code>mstp.bad</code>.</p>
<h3>Examples</h3>
<ul>
<li><code>device == 1001</code> – everything about device 1001</li>
<li><code>host == "10.0.0.5" &amp;&amp; !whois</code> – traffic to or from one address, without Who-Is broadcasts</li>
<li><code>net == 2000 &amp;&amp; gateway == "10.0.0.1:47808"</code> – network 2000 through one router</li>
<li><code>write || command</code> – every change request</li>
<li><code>error &amp;&amp; time &gt; 60</code> – errors after the first minute</li>
</ul>
{note('You rarely need to type a filter: double-click a cell, or right-click a packet and choose Apply as Filter.')}
""")

ch('findings', 'Findings', 'Analyse a capture', f"""
<p><b>Findings</b> ({k('Ctrl+2')}) is the place to start with any capture. It checks the whole capture for common
problems and explains each one:</p>
<ul>
<li><b>What we found</b> – the problem in one or two sentences.</li>
<li><b>Where</b> – the devices, addresses and networks involved (highlighted).</li>
<li><b>Why it matters</b> – what it does to the building.</li>
<li><b>How to troubleshoot</b> – numbered steps to fix it.</li>
</ul>
<p><b>Show the packets behind this finding ›</b> under each title opens the Packets page filtered to exactly the
messages that caused it – for example only the COV notifications that one device sent for the flooding point, the
Who-Is broadcasts from the flooding address, the token passes to a dead MAC, the I-Am announcements of a duplicate
device ID, or the refused writes. The filter appears in the filter box, so you can see what was used and change it;
press {k('Esc')} to see every packet again.</p>
<p><b>Click any highlighted address</b> – an IP address, an MS/TP MAC, a network number or a device ID – to jump to
the Packets page showing only the packets that involve it. This works everywhere addresses are highlighted:
Findings, Devices, Compare and the other tables. The pointer turns into a hand over them. (In the packet list itself
double-click a cell instead.) For a device ID the filter covers every address that device used.</p>
<p>Each finding is marked <span style="color:#d70015"><b>SERIOUS</b></span>,
<span style="color:#b86e00"><b>WARNING</b></span> or <span style="color:#248a3d"><b>NOTE</b></span>. A tab with serious
findings shows a ⚠ and their number. The checks include:</p>
<ul>
<li>two devices using the same device ID, unusable device IDs, and devices that changed address;</li>
<li>two networks sharing a network number, and networks announced by several gateways;</li>
<li>a BBMD refusing requests;</li>
<li>devices that are slow to answer or often do not answer;</li>
<li>Who-Is floods, requests repeated very often and points sending floods of change notifications;</li>
<li>two sources writing the same point, points written very often, refused writes, and restarts or other commands;</li>
<li>on MS/TP: damaged messages from the wiring, the token handed to an address that does not answer, an unstable token
route, a slow token, a Max Master set higher than needed, and a trunk that is nearly full.</li>
</ul>
<p>Who-Is messages sent by this PC (for example by Discover) are not reported as a problem, and network number 0 (the
local network) is only a note.</p>
<p>Save the findings with {k('Ctrl+S')} as a web page, a text file (easy to paste into a ticket or e-mail) or JSON.</p>
""")

ch('devices', 'Devices', 'Analyse a capture', f"""
<p><b>Devices</b> ({k('Ctrl+3')}) shows the layout of the system as a tree: each <b>gateway</b> (BACnet router), the
<b>networks</b> behind it, and the <b>devices</b> on each network, plus the devices directly on your own network.</p>
<p>For each device you see its address, manufacturer, name, model, firmware and how often it announced itself. Duplicate
device IDs are marked in red.</p>
<ul>
<li><b>Double-click</b> a gateway, network or device to see all its packets.</li>
<li><b>Right-click</b> to give a device or network a name (see {go('names', 'Names and labels')}).</li>
<li><b>Expand all / Collapse all</b> open or close the whole tree.</li>
</ul>
<p>Names, models and firmware appear when the capture contains the answers to those questions – for example after a
front-end read them, or after you run Discover.</p>
""")

ch('changes', 'Changes', 'Analyse a capture', f"""
<p><b>Changes</b> ({k('Ctrl+6')}) lists every request in the capture that changes something: point writes (who wrote
which value to which point, at what priority) and <b>commands</b> – restarts, communication on/off and objects created or
deleted. The <b>Result</b> column shows whether the device accepted it.</p>
<p>Use <b>Show</b> to see Everything, only Point writes, only Restarts and commands, or only the Refused ones, and the
search box to find an address, point or value. Double-click a row to see the packet.</p>
{note('Useful when something in the building changed and nobody knows who did it: the From column shows which PC or controller sent the change.')}
""")

ch('traffic', 'Traffic', 'Analyse a capture', f"""
<p><b>Traffic</b> ({k('Ctrl+7')}) shows where the network load comes from:</p>
<ul>
<li><b>Busiest senders</b> – packets, share of all traffic, bytes, requests, broadcasts and COV notifications per
device.</li>
<li><b>Who asks whom, and how often</b> – repeating requests, fastest first. Anything repeating faster than once a
second is shown in red; it is usually a graphic, trend or front-end polling too fast.</li>
<li><b>Change-of-value (COV) notifications</b> – which points send the most COV updates. More than two a second is red:
the COV increment is probably too small.</li>
</ul>
<p>Double-click any row to see its packets.</p>
""")

ch('response', 'Response times & errors', 'Analyse a capture', """
<p>This page matches each request to its answer and measures how long each device takes to reply.</p>
<ul>
<li><b>Typical</b>, <b>Slowest 5%</b> and <b>Worst</b> reply times per device, and how many requests got <b>No
answer</b>.</li>
<li>Devices are marked <b>slow</b> (typically over a second) or <b>often silent</b> (many unanswered requests). Most
controllers answer in well under half a second.</li>
<li><b>Errors, refusals and cancelled requests</b> – every error, reject and abort grouped by device, with what it
means and what to do (for example “unknown object – the point was deleted or renumbered”).</li>
</ul>
<p>This page needs confirmed requests (such as Read Property) in the capture – capture while a front-end or tool is
polling the devices.</p>
""")

ch('online', 'Online board & alerts', 'Analyse a capture', f"""
<p>The <b>Online board</b> ({k('Ctrl+4')}) shows which devices are talking and which have gone quiet. A device counts as
online while it keeps sending within about six times its usual rhythm (at least 60 seconds). A device that was active
and then stopped is <b>silent</b>.</p>
<p>For a saved capture, “silent” means it stopped talking before the end of the capture. During a live capture the board
updates every two seconds.</p>
<h3>Alerts</h3>
<p>While a live capture runs, the app can alert you when <b>a new device appears</b>, <b>a device goes silent</b>,
<b>a new problem is found</b> or <b>a router says it is busy</b>. Tick the alerts you want, and optionally <b>play a
sound</b> or show a <b>desktop notification</b> (useful while you work on something else). The first 15 seconds of a
capture only learn what is on the network, so you are not flooded with alerts at the start. Recent alerts are listed on
the page.</p>
""")

ch('map', 'Network map', 'Analyse a capture', f"""
<p>The <b>Network map</b> ({k('Ctrl+9')}) draws the routers, the networks behind them and the devices on each network.
Each router box shows its address and the device IDs it answers for; devices show their ID, address, name and
manufacturer.</p>
<p>Click a router, network or device on the map to see its packets. Save the map with {k('Ctrl+S')} as a picture
(PNG), a vector drawing (SVG – opens in Visio, Inkscape or a browser and stays sharp at any size) or a web page.</p>
""")

ch('ids', 'Available IDs and networks', 'Analyse a capture', f"""
<p>Every BACnet device needs a unique <b>device ID</b>, and every BACnet network a unique <b>network number</b>. These
two pages show which are already taken in the capture and which are free, so you can pick a safe number for something
new.</p>
<h3>Available IDs</h3>
<ul>
<li>Each network shows its taken IDs, its free IDs and devices that do not follow the numbering scheme.</li>
<li><b>Plan a new device on network</b> – type a network number to get the next free ID on it.</li>
<li><b>Device ID scheme</b> – how IDs are built on this site: network × 100 + MAC, or network × 1000 + MAC.</li>
<li><b>Also treat as taken</b> – IDs you know are used but were not in the capture (for example
<code>240010-240019</code>).</li>
<li><b>Your own network's number</b> – only needed for devices that are not behind a router.</li>
<li><b>Lowest / Highest device ID</b> and <b>List every ID instead of ranges</b> change what is listed.</li>
</ul>
<h3>Available networks</h3>
<p>Shows the network numbers in use and the free ones, in blocks of 100. Set the lowest and highest numbers to consider,
numbers to treat as taken, and whether to list every number. <b>Copy all networks</b> copies the list.</p>
{note('A capture only shows devices that talked while it was recording. Before giving out an ID, run a Discover scan as well, and add any IDs you know about under Also treat as taken.')}
""")

ch('mstp', 'MS/TP trunk and bus speed', 'Analyse a capture', f"""
<h3>MS/TP trunk</h3>
<p>This page ({k('Ctrl+8')}) needs a capture of an RS-485 trunk (made with a USB RS-485 adapter in Live capture). It
shows:</p>
<ul>
<li>A grid of all 128 MAC addresses: <b>masters</b> (pass the token), <b>slaves</b> (only answer), devices
<b>joining</b>, <b>dead</b> addresses (offered the token but never answered) and addresses <b>polled</b> with nothing
there. Hover a square for details.</li>
<li>The <b>token lap</b> – how long the token takes to go round. Over a second is slow.</li>
<li>For each master: token passes, data frames, how long it holds the token and how often the token comes back.</li>
<li>A <b>Max Master</b> recommendation: if masters poll for addresses far above the highest real device, lowering Max
Master on every master stops that wasted polling and speeds the trunk up.</li>
</ul>
<p>If the capture only contains data frames (no token or poll frames – typical for a router's own capture), the page
says so: the masters and Max Master cannot be worked out from it.</p>
<h3>Bus speed</h3>
<p>A capture file does not record the baud rate, so <b>Bus speed</b> estimates it from the timing (a frame cannot
arrive faster than it takes to send). The estimate is reliable when the trunk was busy and only a minimum when it was
quiet; enter the real rate if you know it. The page also shows how busy each trunk is and the throughput of each IP
port.</p>
""")

ch('compare', 'Compare captures', 'Analyse a capture', """
<p><b>Compare captures</b> lines up two open captures – typically <b>Before</b> and <b>After</b> a change – and shows
what is different:</p>
<ul>
<li>new devices and missing devices;</li>
<li>devices that changed address, and addresses that now have a different device ID;</li>
<li>new networks, networks no longer seen, and networks reached through a different gateway;</li>
<li>new problems, and problems that went away.</li>
</ul>
<ol>
<li>Open both captures (each in its own tab).</li>
<li>Click <b>Compare captures</b> in the sidebar.</li>
<li>Choose the <b>Before</b> and <b>After</b> capture. The ⇄ button swaps them.</li>
</ol>
<p>Save the comparison as a web page or spreadsheet to attach to a job report.</p>
""")

ch('discover', 'Discover: finding devices', 'Discover', f"""
<p><b>Discover</b> ({k('Ctrl+5')}) talks to the network directly. It lists the devices from your open capture and the
devices it finds itself, side by side, grouped by network on the left.</p>
<h3>Connection</h3>
<p>Choose <b>BACnet/IP (network port)</b> to work over Ethernet / Wi-Fi, or <b>MS/TP (USB RS-485 adapter)</b> to work
directly on a trunk (see {go('dmstp', 'Discover over MS/TP')}).</p>
<h3>Scan the network</h3>
<ol>
<li>Press <b>Scan network</b> ({k('Ctrl+D')}). The app sends a Who-Is twice and waits for the I-Am answers.</li>
<li>Then it reads each device's name, vendor, model, firmware, location and description.</li>
<li>Devices appear on the left as <b>ID · vendor · model</b>, with their name if it is not just the default
“device1234”.</li>
</ol>
<p>The dot in front of each device means: <span style="color:#248a3d">●</span> answered the last scan,
<span style="color:#0a84ff">●</span> seen in the capture, ○ from an earlier scan but did not answer this time.</p>
<h3>Use devices from the capture</h3>
<p>Instead of scanning, press <b>Use devices from the capture</b>, tick the networks or devices you want on the left, and
press <b>Discover</b>. The app reads the points of each selected device in turn. This works through BACnet routers too,
using the addresses seen in the capture.</p>
<h3>Options</h3>
<p><b>Options…</b> (BACnet/IP only):</p>
<ul>
<li><b>Send to</b> – leave empty for the automatic broadcast address, or enter one (for example
<code>10.0.255.255</code>).</li>
<li><b>Only device IDs</b> – limit the scan to a range of IDs on a big site.</li>
<li><b>Also scan other subnets through a BBMD</b> – registers this PC as a foreign device for 5 minutes so the scan
reaches other IP subnets. Add <code>:port</code> if the BBMD does not use 47808. When the scan finishes, the
status line says whether the BBMD accepted the registration; if it refused or did not answer, only this subnet was
scanned – check that the BBMD's foreign-device table is enabled and that UDP 47808 is not blocked.</li>
<li><b>Use discovered device names as labels in captures</b> and <b>Discover automatically when a live capture
starts</b>.</li>
</ul>
<h3>Moving around</h3>
<p>The path above the right-hand page (Discover › Network › Device › Category › Point) is clickable. <b>Back</b>,
<b>Home</b>, {k('Alt+Left')} and the mouse Back button go back. Type in <b>Search devices and points</b> to filter the
tree. Right-click a device for more: refresh its details, show its packets, name it, copy its ID or IP, export its points,
or forget it.</p>
<p><b>Export device list</b> saves every discovered device as Excel or CSV. <b>Use names as labels</b> copies the device
names into the capture pages.</p>
<h3>Site inventory</h3>
<p>After a scan, press <b>Site inventory…</b> (or Capture &gt; <b>Build site inventory…</b>). The app reads the details
and the object list of every device it found – the status line shows how far it has got – and then offers to save an
Excel workbook (or CSV) with one row per device:</p>
<ul>
<li>device ID, name, vendor, model, firmware and software version;</li>
<li>address: IP (with network and station for devices behind a router) or MS/TP MAC;</li>
<li>location, description, Max APDU and segmentation;</li>
<li>how many objects the device has, and how many of each kind: AI, AO, AV, BI, BO, BV, multi-state, trend logs,
schedules, calendars, notification classes and files;</li>
<li>a note for any device that did not answer.</li>
</ul>
<p>It is the usual hand-over document at the end of a job. Only the object lists are read, not every value, so it is
quick even on a big site. It covers the devices on the side you are on: BACnet/IP, or the MS/TP trunk you joined.</p>
""")

ch('dmstp', 'Discover over MS/TP', 'Discover', f"""
<p>With a USB RS-485 adapter you can join an MS/TP trunk and read devices directly – no BACnet router needed.</p>
<ol>
<li>Wire the adapter onto the trunk (A to A / + , B to B / –) and plug it into the PC.</li>
<li>In Discover, set <b>Connection</b> to <b>MS/TP</b> and choose the adapter's <b>Port</b> (press the circular arrow
if it is not listed).</li>
<li>Choose the <b>Baud</b> rate, or press <b>Detect</b>.</li>
<li>Press <b>Find a free MAC</b>. The PC listens for a few seconds <i>without sending anything</i>, sees which addresses
are in use and picks a free one for itself.</li>
<li>Press <b>Join trunk</b>. The PC waits for a master to invite it into the token ring (this can take up to a minute,
because masters poll free addresses one at a time). The status line shows when it has joined.</li>
<li>Press <b>Scan MS/TP trunk</b>, then read points as usual.</li>
<li>Press <b>Leave trunk</b> when you are done – this also frees the COM port.</li>
</ol>
<ul>
<li>Only one program can use a COM port at a time: stop a live serial capture (or close any terminal program) before joining, and
leave the trunk before capturing.</li>
<li>If the PC's MAC turns out to be in use by a device, the app stops and tells you – press Find a free MAC again.</li>
<li>Every frame the PC sends and receives also appears in the Live capture tab.</li>
</ul>
{note('If nothing is heard: check the baud rate (Detect), swap A and B, and make sure the devices on the trunk are powered. Some USB adapters need their latency timer set to 1 ms in Device Manager for reliable token passing.')}
""")

ch('points', 'Reading points and alarms', 'Discover', f"""
<h3>A device's page</h3>
<p>Click a device on the left. Its page shows the address, vendor, model, location, description and status;
firmware, software version and other technical fields are under <b>Technical details</b>.</p>
<ul>
<li><b>Read points</b> reads the device's object list and the name, value, units and description of every point.
Grey placeholder rows show while it reads. The points are grouped into categories (Analog Inputs, Binary Outputs…) in
the tree and on the page. <b>Refresh points</b> reads them again.</li>
<li><b>Active alarms</b> asks the device which points are in alarm or fault, whether each alarm is acknowledged and
its type. Double-click a row to open the point.</li>
<li><b>Export points…</b> saves every point with its value as Excel or CSV.</li>
<li><b>Show packets</b> shows this device's packets in the open capture.</li>
</ul>
<h3>A category</h3>
<p>Click a category to list its points with their values. <b>Refresh values</b> reads them all again.</p>
<h3>A point</h3>
<p>Click a point (in the tree or in the list) and its details slide in on the right, so the list stays in view. Click
another point to switch; press {k('Esc')} or × to close the panel.</p>
<ul>
<li><b>Summary</b> – the present value in large type, a warning if the point is in alarm, its name and description,
and <b>Read now</b>, <b>Write…</b> (commandable points only) and <b>Show packets</b>.</li>
<li><b>Details</b> – <b>Alarm &amp; status</b> (status flags, event state, high and low limits, deadband, notification
class), the <b>priority array</b> for commandable points (which priority is in control) and the relinquish default.
<b>Technical details</b> holds calibration, the BACnet configuration (object ID, type, a copyable
<code>bacnet://</code> address, out of service, reliability, profile) and the property list.</li>
<li><b>Read all properties…</b> reads every property of the point straight from the device, with <b>Copy</b> and
<b>Export</b>.</li>
</ul>
<h3>Read a point from a packet</h3>
<p>In the packet list, right-click a packet that mentions a point and choose <b>Read this point now</b> to read its
current value from the device (read-only).</p>
""")

ch('write', 'Writing values (write access)', 'Discover', """
<p>Writing changes real equipment, so it is switched off until you turn it on – and it switches itself off again.</p>
<h3>Turning write access on</h3>
<ol>
<li>Press <b>Enable write access…</b> in Discover (or Capture &gt; Enable write access).</li>
<li>Read the warning, tick <b>I understand this changes live equipment</b>, and choose how long it stays on (5, 15, 30
or 60 minutes).</li>
<li>A <b>red bar</b> across the window shows that write access is on and counts down. Press <b>Turn off</b> on the bar
to end it early.</li>
</ol>
<h3>Writing a value</h3>
<ol>
<li>Open a commandable point (an output or value object) and press <b>Write…</b>.</li>
<li>Enter the new value (or choose active / inactive for a binary point) and the <b>priority</b>. Priority 8 – manual
operator – is the usual one for technicians.</li>
<li>Press <b>Write…</b>. The dialog shows exactly what will be sent; press <b>Confirm</b> to send it.</li>
<li>The device's answer is shown, and the value is read back to check it took effect. If a higher priority is in
control, the dialog tells you which one is overriding your write.</li>
</ol>
<p>To remove your command, tick <b>Release</b> and write at the same priority (this writes NULL). Always release
temporary overrides when you have finished.</p>
<h3>Write log</h3>
<p>Every write is recorded: time, device, point, value, priority, result and read-back. The log is shown on the device
and category pages, can be exported as Excel or CSV, and is also saved to <i>writes.log</i> next to the app's settings.</p>
<p>Only the present value can be written. Restarts, configuration changes and other services are never sent.</p>
""")

ch('names', 'Names and labels', 'Everyday tools', """
<p>Give device IDs and network numbers your own names – “AHU-1”, “Roof trunk” – and they appear next to the numbers on
every page and in reports.</p>
<ul>
<li>Right-click a device or network in <b>Devices</b> (or a device in Discover) and choose to name it.</li>
<li>Edit &gt; <b>Names &amp; labels…</b> lists all names: add, change or remove them, or <b>import</b> a spreadsheet
saved as CSV with rows like <code>device,1001,AHU-1</code> (or just <code>1001,AHU-1</code>) and
<code>network,5,Roof trunk</code>.</li>
<li>In Discover, <b>Use names as labels</b> copies the names read from the devices; the Discovery option can do this
automatically after each scan.</li>
</ul>
<p>Names are saved on this computer.</p>
""")

ch('save', 'Saving, exporting and reports', 'Everyday tools', f"""
<p><b>Save</b> ({k('Ctrl+S')}) and <b>Save As</b> ({k('Ctrl+Shift+S')}) save whichever page you are looking at. Save As
asks for a format; Save then reuses it.</p>
<table cellpadding="5">
<tr><td><b>Web page (.html)</b></td><td>Exactly as shown, with highlights – opens in any browser, easy to print or
e-mail.</td></tr>
<tr><td><b>Excel workbook (.xlsx)</b></td><td>Tables with a bold, frozen, filterable header row.</td></tr>
<tr><td><b>Spreadsheet (.csv)</b></td><td>For Excel or other tools.</td></tr>
<tr><td><b>Capture file (.pcapng)</b></td><td>Packets page only: just the packets that match the filter – handy for
sending a short extract.</td></tr>
<tr><td><b>Text / JSON</b></td><td>Findings: plain text for a ticket, or JSON for other tools.</td></tr>
<tr><td><b>Picture / vector</b></td><td>Network map: PNG or SVG.</td></tr>
</table>
<h3>Report</h3>
<p>File &gt; <b>Export report…</b> writes a plain-English report of the whole capture – summary, findings, devices,
networks and more – as a web page or text file. Ideal for a job report or to send to a colleague.</p>
""")

ch('palette', 'Search everything (Ctrl+K)', 'Everyday tools', f"""
<p>Press {k('Ctrl+K')} or click <b>Search</b> at the top right and start typing. Results include:</p>
<ul>
<li><b>Views</b> – Findings, Devices, Network map…</li>
<li><b>Devices</b> – every device from the capture and from Discover, by ID, vendor, model or name.</li>
<li><b>Points</b> – every point read in Discover, by name.</li>
<li><b>Tabs</b> – your open captures.</li>
<li><b>Commands</b> – everything in the menus (Start capture, Export report, Check for updates…).</li>
<li><b>Findings</b> – the problems found in the open capture.</li>
</ul>
<p>Use {k('Up')} / {k('Down')} to choose and {k('Enter')} to open; {k('Esc')} closes it. You do not need to type whole
words: “sat sp” finds “SAT Setpoint”.</p>
""")

ch('settings', 'Appearance, tips and the tour', 'Everyday tools', f"""
<h3>Light and dark</h3>
<p>View &gt; Theme: <b>automatic</b> follows Windows, or choose <b>light</b> or <b>dark</b>.</p>
<h3>Galactic cursor</h3>
<p>Inside the app the mouse pointer is a small galaxy: a nebula-filled arrow with stars and a bright star at the tip
(the tip is exactly where you click). Text boxes still show the normal text cursor and dividers their resize arrows.
View &gt; <b>Galactic cursor</b> switches back to the standard Windows pointer.</p>
<h3>Tips</h3>
<p>As you work, small tips point out shortcuts and quicker ways – for example the keyboard shortcut for something you
just clicked. Each tip appears only once. Press <b>Got it</b> to close one or <b>Turn off tips</b> to stop them. Help
&gt; <b>Show tips</b> turns them on or off, and <b>Show all tips again</b> starts over.</p>
<h3>The tour</h3>
<p>The first time the app opens, a short tour shows you around. Take it again any time with Help &gt; <b>Take the
tour</b>. Use <b>Next</b> / <b>Back</b> or the arrow keys; {k('Esc')} ends it.</p>
<h3>What's new</h3>
<p>After an update, a window lists what changed. Help &gt; <b>What's new</b> shows it again.</p>
""")

ch('updates', 'Updates', 'Everyday tools', """
<p>The app checks for a new version once a day (when Help &gt; Check for updates… has <b>Check automatically</b>
ticked). When one is available, a blue bar appears:</p>
<ul>
<li><b>What's new</b> – read the changes first.</li>
<li><b>Update now</b> – downloads the new version, checks it is genuine, closes the app, installs it and reopens it
(about a minute). Your captures, names, notes and settings are kept.</li>
<li><b>Later</b> – hides the bar until the next version.</li>
</ul>
<p>Help &gt; <b>Check for updates…</b> checks straight away. Help &gt; <b>About</b> shows the version you have.</p>
""")

ch('keys', 'Keyboard shortcuts', 'Reference', f"""
<table cellpadding="5">
<tr><td colspan="2"><b>Anywhere</b></td></tr>
<tr><td width="34%">{k('Ctrl+K')}</td><td>Search everything</td></tr>
<tr><td>{k('Ctrl+O')}</td><td>Open capture</td></tr>
<tr><td>{k('Ctrl+S')} / {k('Ctrl+Shift+S')}</td><td>Save / Save As the current page</td></tr>
<tr><td>{k('Ctrl+W')}</td><td>Close the current capture tab</td></tr>
<tr><td>{k('Ctrl+1')}</td><td>Packets</td></tr>
<tr><td>{k('Ctrl+2')}</td><td>Findings</td></tr>
<tr><td>{k('Ctrl+3')}</td><td>Devices</td></tr>
<tr><td>{k('Ctrl+4')}</td><td>Online board</td></tr>
<tr><td>{k('Ctrl+5')}</td><td>Discover</td></tr>
<tr><td>{k('Ctrl+6')}</td><td>Changes</td></tr>
<tr><td>{k('Ctrl+7')}</td><td>Traffic</td></tr>
<tr><td>{k('Ctrl+8')}</td><td>MS/TP trunk</td></tr>
<tr><td>{k('Ctrl+9')}</td><td>Network map</td></tr>
<tr><td>{k('Ctrl+D')}</td><td>Scan the network for devices</td></tr>
<tr><td>{k('Alt+Left')}</td><td>Back (also the Back button on a mouse)</td></tr>
<tr><td>{k('F1')}</td><td>This manual, at the page for what you are looking at</td></tr>
<tr><td colspan="2"><b>Packets</b></td></tr>
<tr><td>{k('Ctrl+F')}</td><td>Search packets</td></tr>
<tr><td>{k('Enter')} / {k('Shift+Enter')}</td><td>Next / previous search match</td></tr>
<tr><td>{k('Ctrl+L')}</td><td>Go to the display filter</td></tr>
<tr><td>{k('Esc')}</td><td>Clear the search or filter you are typing in</td></tr>
<tr><td>{k('Ctrl+B')}</td><td>Bookmark the selected packet</td></tr>
<tr><td>{k('Up')} {k('Down')} {k('PgUp')} {k('PgDn')}</td><td>Move through packets</td></tr>
<tr><td colspan="2"><b>Discover</b></td></tr>
<tr><td>{k('Esc')}</td><td>Close the point details panel</td></tr>
<tr><td colspan="2"><b>Tour and search window</b></td></tr>
<tr><td>{k('Right')} / {k('Left')}, {k('Enter')}</td><td>Next / previous step, open the chosen result</td></tr>
<tr><td>{k('Esc')}</td><td>Close</td></tr>
</table>
""")

ch('trouble', 'Troubleshooting', 'Reference', """
<h3>“No interfaces found” or no network adapters in Live capture</h3>
<p>Install Wireshark (it includes Npcap and dumpcap), then press the circular arrow. Without it, the built-in raw
capture works only when the app is started as Administrator.</p>
<h3>Live capture runs but no BACnet packets arrive</h3>
<ul>
<li>Check you picked the adapter connected to the BACnet network.</li>
<li>On a switched network you only see broadcasts and your own traffic. Use a mirror (SPAN) port, or capture on the
BACnet router, to see traffic between other devices.</li>
<li>Clear the capture filter under More options, or make sure it includes port 47808.</li>
</ul>
<h3>MS/TP: no frames, or garbage</h3>
<ul>
<li>Press <b>Detect</b> to find the baud rate.</li>
<li>Swap the A and B wires.</li>
<li>Check the trunk devices are powered and the adapter is on the right trunk.</li>
<li>“Port in use” – close any other program using the COM port, stop the live capture, or leave the trunk in
Discover.</li>
</ul>
<h3>Scan finds no devices (BACnet/IP)</h3>
<ul>
<li>Windows Firewall may block the answers: allow BACnet Inspector on private / domain networks when Windows asks, or
allow UDP port 47808.</li>
<li>The PC must be on the same IP subnet as the devices, or use a <b>BBMD</b> in Discovery Options.</li>
<li>If the PC has several network adapters, set <b>Send to</b> to the BACnet subnet's broadcast address.</li>
<li>Another BACnet program on the PC (a front-end or tool) may be using port 47808 – close it and try again.</li>
</ul>
<h3>A device is listed but its points cannot be read</h3>
<ul>
<li>Devices behind a router are reached through that router – the router must be reachable from this PC.</li>
<li>MS/TP devices need the PC to be joined to that trunk, or a BACnet router in front of it.</li>
<li>“No answer” usually means the device is offline, overloaded or behind a router that is not passing the request.</li>
</ul>
<h3>Joining an MS/TP trunk takes a long time</h3>
<p>Masters poll one free address per token lap, so on a slow or large trunk it can take up to a minute before the PC is
invited in. If it never joins, lower the PC's MAC (masters only poll up to their Max Master setting).</p>
<h3>Where are my settings?</h3>
<p>Names, notes, saved filters and settings are stored in <i>%LOCALAPPDATA%\\BACnetInspector</i>. They are kept when
the app is updated.</p>
<h3>“Something went wrong”</h3>
<p>If the app hits an unexpected error it keeps running, shows a short message and writes the details to the problem
log. Help &gt; <b>Report a problem…</b> shows the log: press <b>Copy details</b> and send them with a note of what you
were doing, or <b>Open log folder</b> (<i>%LOCALAPPDATA%\\BACnetInspector\\logs</i>) to attach the file. The log contains
error details and the app and Windows versions – not your captures or device data.</p>
""")

ch('glossary', 'BACnet words explained', 'Reference', """
<table cellpadding="5">
<tr><td width="26%"><b>Device ID</b></td><td>A number (0 – 4,194,302) that must be unique on the whole BACnet system.
Two devices with the same ID cause intermittent, confusing faults.</td></tr>
<tr><td><b>Network number</b></td><td>Each BACnet network (an IP subnet or an MS/TP trunk) has a number, unique across
the system, so routers know where to send messages.</td></tr>
<tr><td><b>BACnet router / gateway</b></td><td>Connects BACnet networks, for example an IP network to MS/TP
trunks.</td></tr>
<tr><td><b>BBMD</b></td><td>BACnet Broadcast Management Device: forwards broadcasts between IP subnets.</td></tr>
<tr><td><b>MS/TP</b></td><td>Master-Slave/Token-Passing: BACnet over RS-485 wiring. Devices take turns to talk by
passing a <b>token</b>.</td></tr>
<tr><td><b>MAC address (MS/TP)</b></td><td>A device's address on its trunk, 0 – 127 for masters.</td></tr>
<tr><td><b>Max Master</b></td><td>The highest MAC a master looks for when inviting new devices. Setting it just above
the highest real device speeds the trunk up.</td></tr>
<tr><td><b>Who-Is / I-Am</b></td><td>“Is anyone there?” and “Here I am: device N”. How devices are found.</td></tr>
<tr><td><b>Object / point</b></td><td>Something inside a device: an analog input (a sensor), a binary output (a relay),
a value (a set point)…</td></tr>
<tr><td><b>Property</b></td><td>A piece of information about an object: present-value, units, status-flags…</td></tr>
<tr><td><b>Present value</b></td><td>The point's current value.</td></tr>
<tr><td><b>Priority array</b></td><td>Sixteen levels of command for a point; the highest-priority active command wins
(1 is highest). Releasing a priority removes your command.</td></tr>
<tr><td><b>COV</b></td><td>Change of value: a device sends a new value only when it changes by more than the COV
increment, instead of being polled.</td></tr>
<tr><td><b>Error / reject / abort</b></td><td>Three ways a device can refuse a request; the Response times page explains
each one.</td></tr>
<tr><td><b>Capture (.pcap / .pcapng)</b></td><td>A recording of network traffic.</td></tr>
</table>
""")

ch('safety', 'Privacy and safety', 'Reference', """
<ul>
<li><b>Your data stays on your computer.</b> Captures are read from your disk and analysed on this PC. Nothing is
uploaded. The only internet access is the daily check for updates (which can be turned off).</li>
<li><b>Looking is passive.</b> Opening captures, analysing them and live capture never send anything to the BACnet
network. MS/TP live capture only listens.</li>
<li><b>Discover only asks.</b> It sends Who-Is and read requests – the same questions every front-end asks all day.</li>
<li><b>Writing is guarded.</b> Write access is off until you turn it on for a limited time, shows a red bar while on,
needs a confirmation for each write, writes only present-value, reads the value back and logs every write.</li>
<li><b>Joining an MS/TP trunk</b> makes the PC a token-passing master. It listens first, picks an unused address,
and stops if it detects that its address is already in use.</li>
</ul>
""")

ch('about', 'About this program', 'Reference', f"""
<p><b>BACnet Inspector</b> was designed and programmed by <b>{AUTHOR}</b>.</p>
<p>It reads BACnet/IP and BACnet MS/TP captures, explains what is on the network in plain English, points out
problems such as duplicate device IDs and duplicate network numbers, discovers devices and reads their points live,
and can capture straight from an MS/TP trunk.</p>
<p>Help &gt; <b>About BACnet Inspector</b> shows the version you have, and Help &gt; <b>What's new</b> lists what
changed in each release. See {go('updates', 'Updates')} for how new versions arrive.</p>
<h3>Credits</h3>
<ul>
<li>Qt and PySide6 – LGPL v3.</li>
</ul>
""")

# where F1 opens the manual for each view
FOR_VIEW = {'p': 'packets', 'f': 'findings', 'd': 'devices', 'w': 'changes', 't': 'traffic', 's': 'response',
            'o': 'online', 'g': 'map', 'a': 'ids', 'n': 'ids', 'm': 'mstp', 'b': 'mstp', 'c': 'compare', 'x': 'discover'}


def css():
    c = colors()
    dark = is_dark()
    return (f"body{{color:{c['fg']}}} h1{{font-size:20pt;font-weight:600;margin:0 0 6px 0}}"
            f"h3{{font-size:12.5pt;font-weight:600;margin:18px 0 4px 0}} p{{margin:6px 0}} li{{margin:3px 0}}"
            f"a{{color:{c['ac']};text-decoration:none}} code{{font-family:'Cascadia Mono',Consolas;"
            f"background-color:{'#3a3a3c' if dark else '#f0f0f2'}}}"
            f".key{{font-family:'Segoe UI';font-weight:600;background-color:{'#3a3a3c' if dark else '#ececf0'};"
            f"border:1px solid {c['bd']}}} .note{{background-color:{'#1e2a3a' if dark else '#eef4ff'};margin:12px 0}}"
            f".part{{color:{c['mu']};font-size:9pt;font-weight:600}}")


def page(cid):
    for i, (x, title, part, body) in enumerate(CH):
        if x == cid:
            nav = []
            if i > 0:
                nav.append(f'← {go(CH[i - 1][0], CH[i - 1][1])}')
            if i < len(CH) - 1:
                nav.append(f'{go(CH[i + 1][0], CH[i + 1][1])} →')
            return (f'<p class="part">{part.upper()}</p><h1>{title}</h1>{body}'
                    f'<hr><p>{" &nbsp; · &nbsp; ".join(nav)}</p>')
    return ''


def full_html():
    """The whole manual as one web page (for saving / printing)."""
    import re
    toc = ''.join(f'<li><a href="#{x}">{t}</a></li>' for x, t, _p, _b in CH)
    body = ''.join(f'<section id="{x}"><p class="part">{p.upper()}</p><h1>{t}</h1>{b}</section><hr>' for x, t, p, b in CH)
    body = re.sub(r'<span class="key">(.*?)</span>', r'<kbd>\1</kbd>', body)
    return ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>BACnet Inspector – User manual</title><style>'
            "body{font:15px/1.55 'Segoe UI',system-ui,sans-serif;max-width:860px;margin:30px auto;padding:0 20px;color:#1d1d1f}"
            'h1{font-size:26px;margin:4px 0 8px}h3{margin:22px 0 6px}a{color:#0071e3}code{background:#f0f0f2;padding:1px 4px;border-radius:4px}'
            'kbd{border:1px solid #c7c7cc;border-bottom-width:2px;border-radius:5px;padding:0 6px;background:#fff;font:600 13px "Segoe UI"}'
            '.note{background:#eef4ff;border-radius:10px;margin:14px 0}.part{color:#6e6e73;font-size:12px;font-weight:600;letter-spacing:.05em}'
            'td{vertical-align:top}hr{border:0;border-top:1px solid #e3e3e8;margin:30px 0}'
            f'</style></head><body><h1>BACnet Inspector – User manual</h1><p class="part">BY {AUTHOR.upper()}</p><ol>{toc}</ol><hr>{body}</body></html>')


# ------------------------------------------------------------------ window --
class ManualWindow(QDialog):
    """The manual: contents on the left (with search), the chapter on the right."""

    def __init__(self, win):
        super().__init__(win, Qt.WindowType.Window)
        self.setWindowTitle('BACnet Inspector – User manual')
        self.win = win
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        sp = QSplitter(Qt.Orientation.Horizontal)
        v.addWidget(sp)
        left = QFrame()
        left.setObjectName('mside')
        left.setStyleSheet(f"QFrame#mside{{background:{colors()['side']}}}")
        lv = QVBoxLayout(left)
        lv.setContentsMargins(12, 14, 8, 10)
        lv.setSpacing(8)
        lv.addWidget(label('User manual', bold=True, size=17, wrap=False))
        self.q = QLineEdit()
        self.q.setPlaceholderText('Search the manual')
        self.q.setClearButtonEnabled(True)
        self.q.addAction(U.icon('search', colors()['mu'], 16), QLineEdit.ActionPosition.LeadingPosition)
        lv.addWidget(self.q)
        self.toc = QListWidget()
        self.toc.setFrameShape(QFrame.Shape.NoFrame)
        c = colors()
        self.toc.setStyleSheet('QListWidget{background:transparent;outline:0}'
                               f"QListWidget::item{{padding:2px 6px;border-radius:6px;color:{c['fg']}}}"
                               'QListWidget::item:hover:!selected:enabled{background:rgba(118,118,128,0.14)}'
                               f"QListWidget::item:selected{{background:rgba(0,113,227,{0.28 if is_dark() else 0.14});color:{c['fg']}}}"
                               f"QListWidget::item:disabled{{color:{c['mu']};background:transparent}}")
        lv.addWidget(self.toc, 1)
        self.hits = label('', muted=True, wrap=False)
        lv.addWidget(self.hits)
        row = QHBoxLayout()
        sv = QPushButton('Save as web page…')
        sv.setToolTip('Save the whole manual as one web page – to print it, or read it on another computer')
        sv.clicked.connect(self.save)
        row.addWidget(sv)
        row.addStretch(1)
        lv.addLayout(row)
        sp.addWidget(left)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        self.tb = QTextBrowser()
        self.tb.setOpenLinks(False)
        self.tb.setFrameShape(QFrame.Shape.NoFrame)
        self.tb.document().setDocumentMargin(28)
        self.tb.document().setDefaultStyleSheet(css())
        self.tb.anchorClicked.connect(self.link)
        rv.addWidget(self.tb)
        sp.addWidget(right)
        sp.setSizes([270, 760])
        sp.setStretchFactor(1, 1)
        self.cur = None
        self.fill('')
        self.q.textChanged.connect(self.fill)
        self.q.returnPressed.connect(self.find_next)
        self.toc.currentItemChanged.connect(lambda it, _p: it and it.data(Qt.ItemDataRole.UserRole) and
                                            self.show_ch(it.data(Qt.ItemDataRole.UserRole)))
        self.resize(1080, 760)

    def fill(self, q):
        q = q.strip().lower()
        self.toc.blockSignals(True)
        self.toc.clear()
        last = None
        n = 0
        for cid, title, part, body in CH:
            if q:
                import re
                text = re.sub(r'<[^>]+>', ' ', body).lower() + ' ' + title.lower()
                if q not in text:
                    continue
            if part != last:
                h = QListWidgetItem(part.upper())
                f = h.font()
                f.setPointSizeF(7.5)
                f.setBold(True)
                h.setFont(f)
                h.setFlags(Qt.ItemFlag.NoItemFlags)
                self.toc.addItem(h)
                last = part
            it = QListWidgetItem(title)
            it.setData(Qt.ItemDataRole.UserRole, cid)
            self.toc.addItem(it)
            n += 1
            if cid == self.cur:
                self.toc.setCurrentItem(it)
        self.toc.blockSignals(False)
        self.hits.setText((f"{n} chapter{'' if n == 1 else 's'} mention “{q}” – press Enter to jump to it" if n else
                           f'Nothing found for “{q}”') if q else '')
        if q and n and (self.cur is None or not any(self.toc.item(i).data(Qt.ItemDataRole.UserRole) == self.cur
                                                    for i in range(self.toc.count()))):
            first = next(self.toc.item(i) for i in range(self.toc.count()) if self.toc.item(i).data(Qt.ItemDataRole.UserRole))
            self.toc.setCurrentItem(first)
        elif q:
            self._mark(q)

    def show_ch(self, cid):
        self.cur = cid
        self.tb.setHtml(page(cid))
        self.tb.verticalScrollBar().setValue(0)
        for i in range(self.toc.count()):
            if self.toc.item(i).data(Qt.ItemDataRole.UserRole) == cid:
                self.toc.blockSignals(True)
                self.toc.setCurrentRow(i)
                self.toc.blockSignals(False)
        q = self.q.text().strip()
        if q:
            self._mark(q)

    def _mark(self, q):
        """Highlight every occurrence of q in the chapter and scroll to the first."""
        from PySide6.QtGui import QColor, QTextCharFormat
        from PySide6.QtWidgets import QTextEdit
        doc = self.tb.document()
        sels = []
        fmt = QTextCharFormat()
        fmt.setBackground(QColor('#fde68a'))
        fmt.setForeground(QColor('#1c1917'))
        cur = doc.find(q)
        first = None
        while not cur.isNull():
            s = QTextEdit.ExtraSelection()
            s.cursor = cur
            s.format = fmt
            sels.append(s)
            first = first or QTextCursor(cur)
            cur = doc.find(q, cur)
        self.tb.setExtraSelections(sels)
        if first is not None:
            self.tb.setTextCursor(first)
            self.tb.ensureCursorVisible()

    def find_next(self):
        q = self.q.text().strip()
        if not q:
            return
        if self.tb.find(q):
            return
        ids = [self.toc.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.toc.count())
               if self.toc.item(i).data(Qt.ItemDataRole.UserRole)]
        if not ids:
            return
        i = ids.index(self.cur) if self.cur in ids else -1
        self.show_ch(ids[(i + 1) % len(ids)])
        self.tb.moveCursor(QTextCursor.MoveOperation.Start)
        self.tb.find(q, QTextDocument.FindFlag(0))

    def link(self, url: QUrl):
        frag = url.fragment() or url.toString().lstrip('#')
        if any(x == frag for x, *_ in CH):
            self.show_ch(frag)
        elif url.scheme() in ('http', 'https'):
            from PySide6.QtGui import QDesktopServices
            QDesktopServices.openUrl(url)

    def save(self):
        p, _ = QFileDialog.getSaveFileName(self, 'Save the manual', 'BACnet Inspector - User manual.html', 'Web page (*.html)')
        if not p:
            return
        if not p.lower().endswith('.html'):
            p += '.html'
        try:
            with open(p, 'w', encoding='utf-8') as f:
                f.write(full_html())
            self.win.toast('Saved ' + p)
        except OSError as e:
            self.win.toast(f'Save failed: {e.strerror}')

    def open_at(self, cid):
        self.q.blockSignals(True)
        self.q.clear()
        self.q.blockSignals(False)
        self.fill('')
        self.show_ch(cid if any(x == cid for x, *_ in CH) else 'welcome')
        self.show()
        self.raise_()
        self.activateWindow()

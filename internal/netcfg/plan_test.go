package netcfg

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func u8(v uint8) []byte { return []byte{v} }

func u16(v uint16) []byte { return binary.NativeEndian.AppendUint16(nil, v) }

func u32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }

func hw(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func static(p string) Addr { return Addr{Prefix: netip.MustParsePrefix(p), Global: true} }

func nic(idx int, name, mac string, addrs ...Addr) Link {
	return Link{Index: idx, Name: name, Type: arphrdEther, MAC: hw(mac), PermMAC: hw(mac), MTU: 1500, Addrs: addrs}
}

func route(dst, gw string, link int) Route {
	r := Route{Dst: netip.MustParsePrefix(dst), Link: link, Proto: protoStatic, Type: rtnUnicast, Table: tableMain}
	if gw != "" {
		r.Gw = netip.MustParseAddr(gw)
	}
	return r
}

// freshBond is what the kernel reports for a bond created with only a mode
// and miimon: every other parameter at its default.
func freshBond(mode uint8) Attrs {
	return Attrs{
		bondMode: u8(mode), bondActiveSlave: u32(0), bondMIIMon: u32(100), 4: u32(0), 5: u32(0), 6: u8(1), 7: u32(0),
		9: u32(0), 10: u32(0), 12: u8(0), 13: u8(0), 14: u8(0), 15: u32(1), 16: u8(1), 17: u8(0), 18: u32(0),
		19: u32(1), 20: u32(1), 21: u8(0), 22: u8(0), 27: u8(1), 28: u32(0), 29: u8(1), 30: u8(2), 32: u8(1), 33: u8(0),
	}
}

func freshBridge() Attrs {
	a := Attrs{
		1: u32(1500), 2: u32(200), 3: u32(2000), 4: u32(30000), 5: u32(0), 6: u16(32768), 7: u8(0),
		8: binary.BigEndian.AppendUint16(nil, 0x8100), 9: u16(0), 10: make([]byte, 8), 11: make([]byte, 8), 12: u16(0),
		13: u32(0), 14: u8(0), 15: u8(0), 16: make([]byte, 8), 17: make([]byte, 8), 18: make([]byte, 8), 19: make([]byte, 8),
		20: hw("01:80:c2:00:00:00"), 22: u8(1), 23: u8(1), 24: u8(0), 25: u8(0), 26: u32(16), 27: u32(4096),
		28: u32(2), 29: u32(2), 36: u8(0), 37: u8(0), 38: u8(0), 39: u16(1), 41: u8(0), 42: u8(0), 43: u8(2),
		44: u8(1), 45: u8(0), 46: make([]byte, 8), 48: u32(0), 49: u32(0),
	}
	for id, v := range map[uint16]uint64{30: 100, 31: 26000, 32: 25500, 33: 12500, 34: 1000, 35: 3125} {
		a[id] = binary.NativeEndian.AppendUint64(nil, v)
	}
	return a
}

func freshBridgePort() Attrs {
	return Attrs{
		1: u8(3), 2: u16(32), 3: u32(100), 4: u8(0), 5: u8(0), 6: u8(0), 7: u8(0), 8: u8(1), 9: u8(1), 10: u8(0),
		12: u8(0), 13: make([]byte, 8), 14: make([]byte, 8), 15: u16(32769), 16: u32(0), 17: u16(0x8001), 18: u16(1),
		19: u8(0), 20: u8(0), 21: make([]byte, 8), 22: make([]byte, 8), 23: make([]byte, 8), 25: u8(1), 27: u8(1),
		28: u8(0), 29: u8(0), 30: u8(1), 31: u16(0), 32: u8(0), 33: u8(0), 37: u32(512), 38: u32(0), 39: u8(0),
		40: u8(0), 41: u32(0), 42: u32(0), 43: u8(0),
	}
}

func files(t *testing.T, h Host) map[string]string {
	t.Helper()
	fs, _, err := Plan(&h)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, f := range fs {
		m[f.Path] = f.Content
	}
	return m
}

func want(t *testing.T, got map[string]string, path, content string) {
	t.Helper()
	c, ok := got[path]
	if !ok {
		t.Fatalf("no %s among %v", path, keys(got))
	}
	if c != content {
		t.Errorf("%s:\n%s\nwant:\n%s", path, c, content)
	}
}

func keys(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func TestStaticNIC(t *testing.T) {
	l := nic(2, "lan0", "52:54:00:12:34:56", static("10.0.2.50/24"), static("2001:db8::50/64"),
		Addr{Prefix: netip.MustParsePrefix("fe80::1/64")})
	l.MTU = 1400
	gw6 := route("::/0", "fe80::1", 2)
	gw6.Metric = 1024
	onlink := route("198.51.100.0/24", "203.0.113.1", 2)
	onlink.OnLink = true
	scoped := route("192.0.2.0/24", "", 2)
	scoped.Scope = scopeLink
	scoped.Src = netip.MustParseAddr("10.0.2.50")
	got := files(t, Host{
		Links:  []Link{{Index: 1, Name: "lo", Type: 772}, l},
		Routes: []Route{route("0.0.0.0/0", "10.0.2.2", 2), gw6, onlink, scoped},
		DNS:    []netip.Addr{netip.MustParseAddr("10.0.2.3"), netip.MustParseAddr("2001:db8::53")},
		Search: []string{"example.test", "example.org"},
	})
	if len(got) != 2 {
		t.Errorf("files %v, want the NIC's and resolved's", keys(got))
	}
	want(t, got, "/etc/systemd/network/10-btk-525400123456.network", `[Match]
PermanentMACAddress=52:54:00:12:34:56
Type=ether

[Link]
MTUBytes=1400

[Network]

[Address]
Address=10.0.2.50/24

[Address]
Address=2001:db8::50/64

[Route]
Gateway=10.0.2.2
Metric=0

[Route]
Gateway=fe80::1
Metric=1024

[Route]
Destination=198.51.100.0/24
Gateway=203.0.113.1
GatewayOnLink=yes
Metric=0

[Route]
Destination=192.0.2.0/24
Metric=0
Scope=link
PreferredSource=10.0.2.50
`)
	want(t, got, "/etc/systemd/resolved.conf.d/10-btk.conf", `[Resolve]
DNS=10.0.2.3 2001:db8::53
Domains=example.test example.org
`)
}

func TestAddressDetails(t *testing.T) {
	ptp := Addr{Prefix: netip.MustParsePrefix("192.0.2.1/32"), Peer: netip.MustParsePrefix("192.0.2.2/32"), Global: true}
	labelled := static("192.0.2.10/24")
	labelled.Label = "lan0:1"
	noroute := static("192.0.2.20/24")
	noroute.NoPrefixRoute = true
	sameLabel := static("192.0.2.30/24")
	sameLabel.Label = "lan0"
	got := files(t, Host{Links: []Link{nic(2, "lan0", "52:54:00:12:34:56", ptp, labelled, noroute, sameLabel)}})
	c := got["/etc/systemd/network/10-btk-525400123456.network"]
	for _, s := range []string{
		"[Address]\nAddress=192.0.2.1/32\nPeer=192.0.2.2/32\n",
		"[Address]\nAddress=192.0.2.10/24\nLabel=lan0:1\n",
		"[Address]\nAddress=192.0.2.20/24\nAddPrefixRoute=no\n",
		"[Address]\nAddress=192.0.2.30/24\n",
	} {
		if !strings.Contains(c, s) {
			t.Errorf("missing %q in\n%s", s, c)
		}
	}
	if strings.Contains(c, "Label=lan0\n") {
		t.Errorf("a label that is the link's own name is the default:\n%s", c)
	}
}

func TestDHCPOnlyNICIsLeftToKairos(t *testing.T) {
	dyn := static("10.0.2.15/24")
	dyn.Dynamic = true
	slaac := static("2001:db8::abcd/64")
	slaac.Dynamic = true
	dhcpRoute := route("0.0.0.0/0", "10.0.2.2", 2)
	dhcpRoute.Proto = 16
	fs, notes, err := Plan(&Host{
		Links:  []Link{nic(2, "enp0s2", "52:54:00:12:34:56", dyn, slaac)},
		Routes: []Route{dhcpRoute},
		DNS:    []netip.Addr{netip.MustParseAddr("10.0.2.3")},
	})
	if err != nil || len(fs) != 0 {
		t.Fatalf("files %v, err %v: a DHCP-only NIC is what Kairos configures by default", fs, err)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "DHCP") {
		t.Errorf("notes %q do not say why nothing is carried", notes)
	}
}

func TestDynamicV4BesideStaticRoute(t *testing.T) {
	dyn := static("10.0.2.15/24")
	dyn.Dynamic = true
	got := files(t, Host{
		Links:  []Link{nic(2, "enp0s2", "52:54:00:12:34:56", dyn)},
		Routes: []Route{route("192.0.2.0/24", "10.0.2.2", 2)},
	})
	c := got["/etc/systemd/network/10-btk-525400123456.network"]
	if !strings.Contains(c, "[Network]\nDHCP=ipv4\n") || !strings.Contains(c, "[DHCPv4]\nClientIdentifier=mac\n") {
		t.Errorf("a NIC with a DHCP lease must keep DHCP:\n%s", c)
	}
	if strings.Contains(c, "10.0.2.15") {
		t.Errorf("the leased address must not be pinned:\n%s", c)
	}
}

func TestJumboMTUAloneIsCarried(t *testing.T) {
	dyn := static("10.0.2.15/24")
	dyn.Dynamic = true
	l := nic(2, "enp0s2", "52:54:00:12:34:56", dyn)
	l.MTU = 9000
	got := files(t, Host{Links: []Link{l}})
	if c := got["/etc/systemd/network/10-btk-525400123456.network"]; !strings.Contains(c, "MTUBytes=9000") || !strings.Contains(c, "DHCP=ipv4") {
		t.Errorf("an MTU Kairos would not set must be carried, with DHCP kept:\n%s", c)
	}
}

func TestMACMatching(t *testing.T) {
	overridden := nic(2, "lan0", "52:54:00:12:34:56", static("10.0.2.50/24"))
	overridden.MAC = hw("02:00:00:00:00:01")
	unknown := nic(3, "lan1", "52:54:00:12:34:57", static("10.0.3.50/24"))
	unknown.PermMAC = nil
	got := files(t, Host{Links: []Link{overridden, unknown}})
	if c := got["/etc/systemd/network/10-btk-525400123456.network"]; !strings.Contains(c, "PermanentMACAddress=52:54:00:12:34:56\n") ||
		!strings.Contains(c, "[Link]\nMACAddress=02:00:00:00:00:01\n") {
		t.Errorf("an overridden MAC must be matched by the burnt-in one and set again:\n%s", c)
	}
	if c := got["/etc/systemd/network/10-btk-525400123457.network"]; !strings.Contains(c, "[Match]\nMACAddress=52:54:00:12:34:57\nType=ether\n") {
		t.Errorf("without a burnt-in MAC the current one is matched:\n%s", c)
	}
}

func TestBondWithPrimary(t *testing.T) {
	info := freshBond(1)
	info[bondPrimary] = u32(3)
	info[14] = u8(1)
	info[12] = u8(2)
	bond := Link{
		Index: 5, Name: "bond0", Kind: "bond", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1400, Info: info,
		Addrs: []Addr{static("10.0.2.50/24")},
	}
	m1 := nic(3, "eth0", "52:54:00:12:34:56", nil...)
	m1.Master, m1.SlaveKind, m1.SlaveInfo, m1.MTU = 5, "bond", Attrs{bondSlavePermHWAddr: hw("52:54:00:12:34:56")}, 1400
	m2 := nic(4, "eth1", "52:54:00:12:34:57", nil...)
	m2.MAC = hw("52:54:00:12:34:56")
	m2.Master, m2.SlaveKind, m2.MTU = 5, "bond", 1400
	got := files(t, Host{Links: []Link{m1, m2, bond}, Routes: []Route{route("0.0.0.0/0", "10.0.2.2", 5)}})
	if len(got) != 4 {
		t.Errorf("files %v, want a netdev and three networks", keys(got))
	}
	want(t, got, "/etc/systemd/network/10-btk-bond0.netdev", `[NetDev]
Name=bond0
Kind=bond
MACAddress=52:54:00:12:34:56

[Bond]
Mode=active-backup
MIIMonitorSec=100ms
PrimaryReselectPolicy=failure
TransmitHashPolicy=layer3+4
`)
	want(t, got, "/etc/systemd/network/10-btk-bond0.network", `[Match]
Name=bond0

[Link]
MTUBytes=1400

[Network]

[Address]
Address=10.0.2.50/24

[Route]
Gateway=10.0.2.2
Metric=0
`)
	want(t, got, "/etc/systemd/network/10-btk-525400123456.network", `[Match]
PermanentMACAddress=52:54:00:12:34:56
Type=ether

[Link]
MTUBytes=1400

[Network]
Bond=bond0
PrimarySlave=yes
`)
	// The member's current MAC is the bond's: it must not be set back on it.
	want(t, got, "/etc/systemd/network/10-btk-525400123457.network", `[Match]
PermanentMACAddress=52:54:00:12:34:57
Type=ether

[Link]
MTUBytes=1400

[Network]
Bond=bond0
`)
}

func TestBondParameters(t *testing.T) {
	info := freshBond(4)
	for id, v := range map[uint16][]byte{
		4: u32(200), 5: u32(300), 7: u32(1000), 9: u32(3), 10: u32(1), 13: u8(2), 15: u32(2), 16: u8(3), 17: u8(1),
		18: u32(1), 19: u32(5), 20: u32(4), 21: u8(1), 22: u8(2), 24: u16(100), 25: u16(7), 26: hw("02:00:00:00:00:09"),
		27: u8(0), 28: u32(400), 30: u8(5),
	} {
		info[id] = v
	}
	info[bondARPTargets] = nested(u32ip("192.0.2.1"), u32ip("192.0.2.2"))
	bond := Link{
		Index: 5, Name: "bond0", Kind: "bond", Type: arphrdEther, MAC: hw("02:00:00:00:00:05"), MTU: 1500, Info: info,
		Addrs: []Addr{static("10.0.2.50/24")},
	}
	m := nic(3, "eth0", "52:54:00:12:34:56")
	m.Master = 5
	got := files(t, Host{Links: []Link{m, bond}})
	want(t, got, "/etc/systemd/network/10-btk-bond0.netdev", `[NetDev]
Name=bond0
Kind=bond
MACAddress=02:00:00:00:00:05

[Bond]
Mode=802.3ad
MIIMonitorSec=100ms
UpDelaySec=200ms
DownDelaySec=300ms
ARPIntervalSec=1000ms
ARPIPTargets=192.0.2.1 192.0.2.2
ARPValidate=all
ARPAllTargets=all
FailOverMACPolicy=follow
ResendIGMP=2
GratuitousARP=3
AllSlavesActive=yes
MinLinks=1
LearnPacketIntervalSec=5s
PacketsPerSlave=4
LACPTransmitRate=fast
AdSelect=count
AdActorSystemPriority=100
AdUserPortKey=7
AdActorSystem=02:00:00:00:00:09
DynamicTransmitLoadBalancing=no
PeerNotifyDelaySec=400ms
ARPMissedMax=5
`)
}

func nested(items ...[]byte) []byte {
	var b []byte
	for i, it := range items {
		b = binary.NativeEndian.AppendUint16(b, uint16(4+len(it)))
		b = binary.NativeEndian.AppendUint16(b, uint16(i))
		b = append(b, it...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	return b
}

func u32ip(s string) []byte { a := netip.MustParseAddr(s).As4(); return a[:] }

func TestVLANOnBond(t *testing.T) {
	bond := Link{Index: 5, Name: "bond0", Kind: "bond", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1500, Info: freshBond(1)}
	m := nic(3, "eth0", "52:54:00:12:34:56")
	m.Master = 5
	vlan := Link{
		Index: 6, Name: "bond0.10", Kind: "vlan", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1500, Parent: 5,
		Info:  Attrs{1: u16(10), 2: append(u32(vlanReorderHdr|vlanGVRP), u32(0xffffffff)...), 5: binary.BigEndian.AppendUint16(nil, 0x88a8)},
		Addrs: []Addr{static("10.0.10.5/24")},
	}
	got := files(t, Host{Links: []Link{m, bond, vlan}})
	want(t, got, "/etc/systemd/network/10-btk-bond0.10.netdev", `[NetDev]
Name=bond0.10
Kind=vlan
MACAddress=52:54:00:12:34:56

[VLAN]
Id=10
Protocol=802.1ad
GVRP=yes
`)
	want(t, got, "/etc/systemd/network/10-btk-bond0.network", `[Match]
Name=bond0

[Link]
MTUBytes=1500

[Network]
VLAN=bond0.10
`)
	if _, ok := got["/etc/systemd/network/10-btk-525400123456.network"]; !ok {
		t.Errorf("the bond's member is not carried: %v", keys(got))
	}
}

func TestVLANFlagsOff(t *testing.T) {
	nicL := nic(2, "eth0", "52:54:00:12:34:56")
	vlan := Link{
		Index: 6, Name: "vlan20", Kind: "vlan", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1500, Parent: 2,
		Info:  Attrs{1: u16(20), 2: append(u32(vlanLooseBinding|vlanMVRP), u32(0xffffffff)...), 5: binary.BigEndian.AppendUint16(nil, 0x8100)},
		Addrs: []Addr{static("10.0.20.5/24")},
	}
	got := files(t, Host{Links: []Link{nicL, vlan}})
	want(t, got, "/etc/systemd/network/10-btk-vlan20.netdev", `[NetDev]
Name=vlan20
Kind=vlan
MACAddress=52:54:00:12:34:56

[VLAN]
Id=20
ReorderHeader=no
LooseBinding=yes
MVRP=yes
`)
	want(t, got, "/etc/systemd/network/10-btk-525400123456.network", `[Match]
PermanentMACAddress=52:54:00:12:34:56
Type=ether

[Link]
MTUBytes=1500

[Network]
VLAN=vlan20
`)
}

func TestBridgeWithPhysicalAndVirtualPorts(t *testing.T) {
	info := freshBridge()
	info[5] = u32(1)
	info[1] = u32(400)
	info[6] = u16(4096)
	info[23] = u8(0)
	info[8] = binary.BigEndian.AppendUint16(nil, 0x88a8)
	br := Link{
		Index: 7, Name: "br0", Kind: "bridge", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1500, Info: info,
		Addrs: []Addr{static("10.0.2.50/24")},
	}
	port := nic(2, "eth0", "52:54:00:12:34:56")
	port.Master, port.SlaveKind, port.SlaveInfo = 7, "bridge", freshBridgePort()
	port.SlaveInfo[3] = u32(4)
	port.SlaveInfo[2] = u16(16)
	port.SlaveInfo[4] = u8(1)
	port.SlaveInfo[5] = u8(1)
	port.SlaveInfo[6] = u8(1)
	tap := Link{
		Index: 8, Name: "vnet0", Kind: "tun", Type: arphrdEther, MAC: hw("fe:54:00:00:00:01"), MTU: 1500, Master: 7,
		SlaveKind: "bridge", SlaveInfo: freshBridgePort(),
	}
	fs, notes, err := Plan(&Host{Links: []Link{port, tap, br}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.Path] = f.Content
	}
	want(t, got, "/etc/systemd/network/10-btk-br0.netdev", `[NetDev]
Name=br0
Kind=bridge
MACAddress=52:54:00:12:34:56

[Bridge]
ForwardDelaySec=4000ms
STP=yes
Priority=4096
VLANProtocol=802.1ad
MulticastSnooping=no
`)
	want(t, got, "/etc/systemd/network/10-btk-525400123456.network", `[Match]
PermanentMACAddress=52:54:00:12:34:56
Type=ether

[Link]
MTUBytes=1500

[Network]
Bridge=br0

[Bridge]
Priority=16
Cost=4
HairPin=yes
UseBPDU=no
AllowPortToBeRoot=no
`)
	if len(got) != 3 {
		t.Errorf("files %v: the tap port must not be carried", keys(got))
	}
	if !strings.Contains(strings.Join(notes, "\n"), "vnet0") {
		t.Errorf("notes %q do not mention the skipped tap", notes)
	}
}

func TestBridgePortCostWithoutSTPIsNotPinned(t *testing.T) {
	br := Link{
		Index: 7, Name: "br0", Kind: "bridge", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1500, Info: freshBridge(),
		Addrs: []Addr{static("10.0.2.50/24")},
	}
	port := nic(2, "eth0", "52:54:00:12:34:56")
	port.Master, port.SlaveKind, port.SlaveInfo = 7, "bridge", freshBridgePort()
	got := files(t, Host{Links: []Link{port, br}})
	want(t, got, "/etc/systemd/network/10-btk-br0.netdev", `[NetDev]
Name=br0
Kind=bridge
MACAddress=52:54:00:12:34:56

[Bridge]
STP=no
`)
	if c := got["/etc/systemd/network/10-btk-525400123456.network"]; strings.Contains(c, "Cost") || strings.Contains(c, "[Bridge]") {
		t.Errorf("a default port must carry no port settings:\n%s", c)
	}
}

func TestVirtualOnlyLinksAreSkipped(t *testing.T) {
	docker := Link{
		Index: 3, Name: "docker0", Kind: "bridge", Type: arphrdEther, MAC: hw("02:42:00:00:00:01"), MTU: 1500,
		Info: freshBridge(), Addrs: []Addr{static("172.17.0.1/16")},
	}
	veth := Link{Index: 4, Name: "veth1", Kind: "veth", Type: arphrdEther, MAC: hw("02:42:00:00:00:02"), MTU: 1500, Master: 3}
	wg := Link{Index: 5, Name: "wg0", Kind: "wireguard", Type: 65534, MTU: 1420, Addrs: []Addr{static("10.9.0.1/24")}}
	ovs := Link{Index: 6, Name: "ovs-system", Kind: "openvswitch", Type: arphrdEther}
	tap := Link{Index: 7, Name: "tap0", Kind: "tun", Type: arphrdEther, Master: 6}
	fs, notes, err := Plan(&Host{
		Links:  []Link{docker, veth, wg, ovs, tap},
		Routes: []Route{route("10.10.0.0/16", "", 5)},
	})
	if err != nil || len(fs) != 0 {
		t.Fatalf("files %v, err %v: links with no NIC under them do not exist on the installed system", fs, err)
	}
	n := strings.Join(notes, "\n")
	for _, name := range []string{"docker0", "wg0"} {
		if !strings.Contains(n, name) {
			t.Errorf("notes %q do not mention %s", notes, name)
		}
	}
}

func TestRouteFilter(t *testing.T) {
	l := nic(2, "lan0", "52:54:00:12:34:56", static("10.0.2.50/24"))
	kernel := route("10.0.2.0/24", "", 2)
	kernel.Proto = 2
	dhcp := route("0.0.0.0/0", "10.0.2.2", 2)
	dhcp.Proto = 16
	bird := route("192.0.2.0/24", "10.0.2.9", 2)
	bird.Proto = 12
	other := route("198.51.100.0/24", "10.0.2.9", 2)
	other.Table = 100
	blackhole := route("203.0.113.0/24", "", 0)
	blackhole.Type = 6
	foreign := route("203.0.113.128/25", "", 9)
	foreign.OtherMetrics = 1
	foreignDaemon := route("198.18.0.0/15", "10.9.0.1", 9)
	foreignDaemon.Proto = 12
	boot := route("0.0.0.0/0", "10.0.2.2", 2)
	boot.Proto = protoBoot
	withMetrics := route("100.64.0.0/10", "10.0.2.3", 2)
	withMetrics.MTU, withMetrics.OtherMetrics = 1300, 1
	fs, notes, err := Plan(&Host{Links: []Link{l}, Routes: []Route{kernel, dhcp, bird, other, blackhole, foreign, foreignDaemon, boot, withMetrics}, ExtraRules: 2})
	if err != nil {
		t.Fatal(err)
	}
	c := fs[0].Content
	if strings.Count(c, "[Route]") != 2 || !strings.Contains(c, "Gateway=10.0.2.2") ||
		!strings.Contains(c, "Destination=100.64.0.0/10\nGateway=10.0.2.3\nMetric=0\nMTUBytes=1300\n") {
		t.Errorf("want the proto boot default route and the one with an MTU only:\n%s", c)
	}
	n := strings.Join(notes, "\n")
	for _, s := range []string{"192.0.2.0/24", "table 100", "203.0.113.0/24", "100.64.0.0/10", "2 policy routing rules"} {
		if !strings.Contains(n, s) {
			t.Errorf("notes %q do not mention %s", n, s)
		}
	}
	if strings.Contains(n, "203.0.113.128/25") || strings.Contains(n, "198.18.0.0/15") || strings.Contains(n, "10.0.2.0/24") {
		t.Errorf("notes %q mention routes that are neither carried nor lost", n)
	}
}

func TestLoopbackNameserversAreDropped(t *testing.T) {
	got := files(t, Host{
		Links: []Link{nic(2, "lan0", "52:54:00:12:34:56", static("10.0.2.50/24"))},
		DNS:   []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
	})
	if _, ok := got["/etc/systemd/resolved.conf.d/10-btk.conf"]; ok {
		t.Errorf("a local resolver does not exist on the installed system: %v", keys(got))
	}
}

func TestRefusals(t *testing.T) {
	bond := func(info Attrs) []Link {
		b := Link{
			Index: 5, Name: "bond0", Kind: "bond", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1500, Info: info,
			Addrs: []Addr{static("10.0.2.50/24")},
		}
		m := nic(3, "eth0", "52:54:00:12:34:56")
		m.Master = 5
		return []Link{m, b}
	}
	with := func(id uint16, v []byte) Attrs { a := freshBond(1); a[id] = v; return a }
	br := func(info, port Attrs) []Link {
		b := Link{
			Index: 7, Name: "br0", Kind: "bridge", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1500, Info: info,
			Addrs: []Addr{static("10.0.2.50/24")},
		}
		p := nic(2, "eth0", "52:54:00:12:34:56")
		p.Master, p.SlaveInfo = 7, port
		return []Link{p, b}
	}
	brWith := func(id uint16, v []byte) Attrs { a := freshBridge(); a[id] = v; return a }
	portWith := func(id uint16, v []byte) Attrs { a := freshBridgePort(); a[id] = v; return a }
	vlan := func(info Attrs) []Link {
		v := Link{
			Index: 6, Name: "vlan10", Kind: "vlan", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1500, Parent: 2,
			Info: info, Addrs: []Addr{static("10.0.10.5/24")},
		}
		return []Link{nic(2, "eth0", "52:54:00:12:34:56"), v}
	}
	team := nic(2, "eth0", "52:54:00:12:34:56")
	team.Master = 9
	macvlan := Link{
		Index: 6, Name: "mv0", Kind: "macvlan", Type: arphrdEther, MAC: hw("02:00:00:00:00:06"), Parent: 2,
		Addrs: []Addr{static("10.0.2.60/24")},
	}
	wifi := nic(2, "wlan0", "52:54:00:12:34:56", static("10.0.2.50/24"))
	wifi.Wireless = true
	ib := nic(2, "ib0", "52:54:00:12:34:56", static("10.0.2.50/24"))
	ib.Type = 32
	noMAC := nic(2, "eth0", "52:54:00:12:34:56", static("10.0.2.50/24"))
	noMAC.MAC, noMAC.PermMAC = nil, nil
	bondSlave := func(id uint16, v []byte) []Link {
		ls := bond(freshBond(1))
		ls[0].SlaveKind, ls[0].SlaveInfo = "bond", Attrs{id: v}
		return ls
	}
	l2 := nic(2, "lan0", "52:54:00:12:34:56", static("10.0.2.50/24"))
	multipath := route("0.0.0.0/0", "", 0)
	multipath.Hops = []int{2, 9}
	nh := route("192.0.2.0/24", "", 2)
	nh.NextHopID = 4
	bgpDefault := route("0.0.0.0/0", "10.0.2.1", 2)
	bgpDefault.Proto = 186
	bgpNH := route("0.0.0.0/0", "", 0)
	bgpNH.Proto, bgpNH.NextHopID = 186, 9
	for name, tc := range map[string]struct {
		h    Host
		want string
	}{
		"team port":            {Host{Links: []Link{team, {Index: 9, Name: "team0", Kind: "team", Type: arphrdEther, Addrs: []Addr{static("10.0.2.50/24")}}}}, "team0"},
		"ovs port":             {Host{Links: []Link{team, {Index: 9, Name: "ovs-system", Kind: "openvswitch", Type: arphrdEther}}}, "ovs-system"},
		"macvlan":              {Host{Links: []Link{nic(2, "eth0", "52:54:00:12:34:56"), macvlan}}, "macvlan"},
		"wifi":                 {Host{Links: []Link{wifi}}, "wlan0"},
		"infiniband":           {Host{Links: []Link{ib}}, "ib0"},
		"no MAC":               {Host{Links: []Link{noMAC}}, "eth0"},
		"duplicate MAC":        {Host{Links: []Link{l2, nic(3, "lan1", "52:54:00:12:34:56", static("10.0.3.50/24"))}}, "52:54:00:12:34:56"},
		"bond unknown attr":    {Host{Links: bond(with(99, u8(1)))}, "attribute 99"},
		"bond use_carrier off": {Host{Links: bond(with(6, u8(0)))}, "use_carrier"},
		"bond lacp passive":    {Host{Links: bond(with(29, u8(0)))}, "ad_lacp_active"},
		"bond hash vlan+mac":   {Host{Links: bond(with(14, u8(5)))}, "xmit_hash_policy"},
		"bond arp filter":      {Host{Links: bond(with(9, u32(4)))}, "arp_validate"},
		"bond mode unknown":    {Host{Links: bond(with(bondMode, u8(9)))}, "mode"},
		"bond ns targets":      {Host{Links: bond(with(31, nested(make([]byte, 16))))}, "ns_ip6_target"},
		"bond slave queue":     {Host{Links: bondSlave(5, u16(1))}, "queue_id"},
		"bridge vlan filter":   {Host{Links: br(brWith(7, u8(1)), freshBridgePort())}, "vlan_filtering"},
		"bridge group addr":    {Host{Links: br(brWith(20, hw("01:80:c2:00:00:0e")), freshBridgePort())}, "group_addr"},
		"bridge hash max":      {Host{Links: br(brWith(27, u32(512)), freshBridgePort())}, "mcast_hash_max"},
		"bridge boolopt":       {Host{Links: br(brWith(46, append(u32(2), u32(0)...)), freshBridgePort())}, "multi_boolopt"},
		"bridge unknown attr":  {Host{Links: br(brWith(77, u8(1)), freshBridgePort())}, "attribute 77"},
		"port bcast flood":     {Host{Links: br(freshBridge(), portWith(30, u8(0)))}, "bcast_flood"},
		"port backup":          {Host{Links: br(freshBridge(), portWith(34, u32(3)))}, "backup_port"},
		"vlan qos":             {Host{Links: vlan(Attrs{1: u16(10), 3: nested(make([]byte, 8))})}, "egress_qos"},
		"vlan bridge binding":  {Host{Links: vlan(Attrs{1: u16(10), 2: append(u32(vlanReorderHdr|0x10), u32(0xffffffff)...)})}, "flags"},
		"multipath":            {Host{Links: []Link{l2}, Routes: []Route{multipath}}, "multipath"},
		"nexthop object":       {Host{Links: []Link{l2}, Routes: []Route{nh}}, "nexthop"},
		"daemon default route": {Host{Links: []Link{l2}, Routes: []Route{bgpDefault}}, "routing daemon"},
		"daemon default route over a nexthop object": {Host{Links: []Link{l2}, Routes: []Route{bgpNH}}, "routing daemon"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Plan(&tc.h)
			if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want ErrUnsupported naming %q", err, tc.want)
			}
		})
	}
}

func TestFreshNetdevsCarryOnlyWhatIsAlwaysWritten(t *testing.T) {
	for kind, tc := range map[string]struct {
		info  Attrs
		lines int
	}{"bond": {freshBond(1), 8}, "bridge": {freshBridge(), 7}} {
		info := tc.info
		l := Link{
			Index: 5, Name: "x0", Kind: kind, Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1500, Info: info,
			Addrs: []Addr{static("10.0.2.50/24")},
		}
		m := nic(3, "eth0", "52:54:00:12:34:56")
		m.Master = 5
		if kind == "bridge" {
			m.SlaveKind, m.SlaveInfo = "bridge", freshBridgePort()
		}
		got := files(t, Host{Links: []Link{m, l}})
		c := got["/etc/systemd/network/10-btk-x0.netdev"]
		if n := strings.Count(c, "\n"); n != tc.lines {
			t.Errorf("%s: a default netdev has more than mode and monitor or STP:\n%s", kind, c)
		}
	}
}

func TestRouteAloneCarriesItsNIC(t *testing.T) {
	l := nic(2, "lan0", "52:54:00:12:34:56", Addr{Prefix: netip.MustParsePrefix("fe80::1/64")})
	r := route("192.0.2.0/24", "", 2)
	r.Proto, r.Scope = protoBoot, scopeLink
	got := files(t, Host{Links: []Link{l}, Routes: []Route{r}})
	if c := got["/etc/systemd/network/10-btk-525400123456.network"]; !strings.Contains(c, "Destination=192.0.2.0/24") {
		t.Errorf("a NIC with a route set up by hand and no address of its own must still be carried: %v", got)
	}
}

// NetworkManager adds addresses without their prefix route and installs it
// itself, as a kernel route with its own metric.
func TestPrefixRouteInstalledBesideTheAddress(t *testing.T) {
	a := static("10.0.0.5/24")
	a.NoPrefixRoute = true
	prefix := route("10.0.0.0/24", "", 2)
	prefix.Proto, prefix.Scope, prefix.Metric = protoKernel, scopeLink, 100
	gw := route("0.0.0.0/0", "10.0.0.1", 2)
	gw.Metric = 100
	got := files(t, Host{Links: []Link{nic(2, "eth0", "52:54:00:12:34:56", a)}, Routes: []Route{prefix, gw}})
	c := got["/etc/systemd/network/10-btk-525400123456.network"]
	if !strings.Contains(c, "[Address]\nAddress=10.0.0.5/24\nRouteMetric=100\n") || strings.Contains(c, "AddPrefixRoute=no") {
		t.Errorf("the prefix route must come back with its metric, or the gateway is unreachable:\n%s", c)
	}
}

func TestSourceSpecificRoute(t *testing.T) {
	r := route("::/0", "fe80::1", 2)
	r.From = netip.MustParsePrefix("2001:db8:1::/48")
	got := files(t, Host{Links: []Link{nic(2, "eth0", "52:54:00:12:34:56", static("2001:db8:1::5/64"))}, Routes: []Route{r}})
	if c := got["/etc/systemd/network/10-btk-525400123456.network"]; !strings.Contains(c, "[Route]\nSource=2001:db8:1::/48\nGateway=fe80::1\n") {
		t.Errorf("a source-specific route must keep its source:\n%s", c)
	}
}

func TestPortsOfUnsupportedMasters(t *testing.T) {
	bond := Link{Index: 5, Name: "bond0", Kind: "bond", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), MTU: 1500, Info: freshBond(1), Master: 9}
	m := nic(3, "eth0", "52:54:00:12:34:56")
	m.Master = 5
	for _, master := range []Link{
		{Index: 9, Name: "ovs-system", Kind: "openvswitch", Type: arphrdEther},
		{Index: 9, Name: "vrf-blue", Kind: "vrf", Type: arphrdEther, Addrs: []Addr{static("10.0.2.50/24")}},
	} {
		brEx := Link{Index: 10, Name: "br-ex", Kind: "openvswitch", Type: arphrdEther, Master: 9, Addrs: []Addr{static("10.0.2.50/24")}}
		_, _, err := Plan(&Host{Links: []Link{m, bond, master, brEx}})
		if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "bond0") || !strings.Contains(err.Error(), master.Name) {
			t.Errorf("%s: err = %v, want a refusal naming bond0 and its master", master.Kind, err)
		}
	}
}

func TestVirtualFunctionOfANICIsLeftToTheDriver(t *testing.T) {
	netvsc := nic(2, "eth0", "00:0d:3a:00:00:01", static("10.0.0.4/24"))
	netvsc.Driver = "hv_netvsc"
	vf := nic(3, "enP1s1", "00:0d:3a:00:00:01")
	vf.Master, vf.Driver = 2, "mlx5_core"
	fs, notes, err := Plan(&Host{Links: []Link{netvsc, vf}})
	if err != nil || len(fs) != 1 {
		t.Fatalf("files %v, err %v", fs, err)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "enP1s1") {
		t.Errorf("notes %q do not mention the VF", notes)
	}
	// The VF has the NIC's MAC address: only the driver tells them apart.
	if !strings.Contains(fs[0].Content, "[Match]\nPermanentMACAddress=00:0d:3a:00:00:01\nType=ether\nDriver=hv_netvsc\n") {
		t.Errorf("the NIC's file would match its VF too:\n%s", fs[0].Content)
	}
	netvsc.Driver = ""
	if _, _, err := Plan(&Host{Links: []Link{netvsc, vf}}); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "enP1s1") {
		t.Errorf("err = %v: without a driver the NIC cannot be told from its VF", err)
	}
	// net_failover gives its master the standby's driver; the primary VF,
	// with a driver of its own, may come first.
	netvsc.Driver, vf.Driver = "virtio_net", "mlx5_core"
	standby := nic(4, "eth0nsby", "00:0d:3a:00:00:01")
	standby.Master, standby.Driver = 2, "virtio_net"
	if _, _, err := Plan(&Host{Links: []Link{netvsc, vf, standby}}); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "eth0nsby") {
		t.Errorf("err = %v: a port with the NIC's own driver cannot be told from it", err)
	}
}

// dhclient-script and udhcpc install the lease's gateway as proto boot,
// which a DHCP client on the installed system sets again.
func TestLeaseGatewayIsNotPinned(t *testing.T) {
	dyn := static("10.0.2.15/24")
	dyn.Dynamic = true
	leasedGw := route("0.0.0.0/0", "10.0.2.2", 2)
	leasedGw.Proto = protoBoot
	handGw := route("192.0.2.0/24", "10.0.2.2", 2)
	onLink := route("198.51.100.0/24", "", 2)
	onLink.Proto = protoBoot
	other := route("203.0.113.0/24", "10.0.2.9", 2)
	other.Proto = protoBoot
	for name, l := range map[string]Link{
		"from the lease":   {Index: 2, Name: "eth0", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), PermMAC: hw("52:54:00:12:34:56"), MTU: 1500, Addrs: []Addr{dyn}, LeaseGateways: []netip.Addr{netip.MustParseAddr("10.0.2.2")}},
		"client, no lease": {Index: 2, Name: "eth0", Type: arphrdEther, MAC: hw("52:54:00:12:34:56"), PermMAC: hw("52:54:00:12:34:56"), MTU: 1500, Addrs: []Addr{dyn}, DHCPClient: true},
	} {
		t.Run(name, func(t *testing.T) {
			fs, notes, err := Plan(&Host{Links: []Link{l}, Routes: []Route{leasedGw, handGw, onLink, other}})
			if err != nil || len(fs) != 1 {
				t.Fatalf("files %v, err %v", fs, err)
			}
			c := fs[0].Content
			if strings.Contains(c, "[Route]\nGateway=10.0.2.2") {
				t.Errorf("the lease's gateway is pinned:\n%s", c)
			}
			for _, d := range []string{"192.0.2.0/24", "198.51.100.0/24"} {
				if !strings.Contains(c, "Destination="+d) {
					t.Errorf("route %s is lost:\n%s", d, c)
				}
			}
			if name == "from the lease" && !strings.Contains(c, "Destination=203.0.113.0/24") {
				t.Errorf("a proto boot route through another gateway is lost:\n%s", c)
			}
			if !strings.Contains(strings.Join(notes, "\n"), "default via 10.0.2.2") {
				t.Errorf("notes %q do not say the lease's route is left to DHCP", notes)
			}
		})
	}
}

func TestDaemonRoutesBesideTheDefaultAreNoted(t *testing.T) {
	l := nic(2, "lan0", "52:54:00:12:34:56", static("10.0.2.50/24"))
	ecmp := route("192.0.2.0/24", "", 0)
	ecmp.Proto, ecmp.Hops = 186, []int{2, 3}
	nh := route("198.51.100.0/24", "", 0)
	nh.Proto, nh.NextHopID = 186, 7
	fs, notes, err := Plan(&Host{Links: []Link{l}, Routes: []Route{ecmp, nh, route("0.0.0.0/0", "10.0.2.2", 2)}})
	if err != nil || len(fs) != 1 {
		t.Fatalf("files %v, err %v: a routing daemon's routes other than the default are noted whatever their shape", fs, err)
	}
	n := strings.Join(notes, "\n")
	for _, d := range []string{"192.0.2.0/24", "198.51.100.0/24"} {
		if !strings.Contains(n, d) {
			t.Errorf("notes %q do not mention %s", n, d)
		}
	}
}

func TestDHCPOnlyNICWithAPortItCannotTellApart(t *testing.T) {
	dyn := static("10.0.2.15/24")
	dyn.Dynamic = true
	master := nic(2, "eth0", "52:54:00:12:34:56", dyn)
	master.Driver = "virtio_net"
	standby := nic(3, "eth0nsby", "52:54:00:12:34:56")
	standby.Master, standby.Driver = 2, "virtio_net"
	fs, _, err := Plan(&Host{Links: []Link{master, standby}})
	if err != nil || len(fs) != 0 {
		t.Errorf("files %v, err %v: a NIC Kairos's default DHCP covers gets no file to match wrongly", fs, err)
	}
}

func TestNameserversWithNothingElseCarriedAreNoted(t *testing.T) {
	dyn := static("10.0.2.15/24")
	dyn.Dynamic = true
	_, notes, err := Plan(&Host{Links: []Link{nic(2, "eth0", "52:54:00:12:34:56", dyn)}, DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, Search: []string{"example.test"}})
	if err != nil || !strings.Contains(strings.Join(notes, "\n"), "192.0.2.53") || !strings.Contains(strings.Join(notes, "\n"), "example.test") {
		t.Errorf("notes %q, err %v: dropped nameservers must be named", notes, err)
	}
}

// A link-local nameserver is reachable through one link only, which the
// zone names by the old system's interface name or index; neither need
// match on the installed system, so it goes into that link's own file.
func TestLinkLocalNameserver(t *testing.T) {
	lan := nic(2, "lan0", "52:54:00:12:34:56", static("2001:db8::50/64"))
	dyn := static("10.0.3.15/24")
	dyn.Dynamic = true
	dhcp := nic(3, "eth1", "52:54:00:12:34:57", dyn)
	idle := nic(4, "eth2", "52:54:00:12:34:58")
	for zone, ok := range map[string]bool{"lan0": true, "2": true, "eth1": false, "eth2": false, "9": false, "": false} {
		t.Run(zone, func(t *testing.T) {
			ns := netip.MustParseAddr("fe80::1")
			if zone != "" {
				ns = ns.WithZone(zone)
			}
			// The same nameserver named by the link's index.
			same := ns
			if zone == "lan0" {
				same = ns.WithZone("2")
			}
			fs, notes, err := Plan(&Host{Links: []Link{lan, dhcp, idle}, DNS: []netip.Addr{ns, same, netip.MustParseAddr("169.254.169.253"), netip.MustParseAddr("2001:db8::53")}})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for _, f := range fs {
				got[f.Path] = f.Content
			}
			want(t, got, "/etc/systemd/resolved.conf.d/10-btk.conf", "[Resolve]\nDNS=169.254.169.253 2001:db8::53\n")
			nw := got["/etc/systemd/network/10-btk-525400123456.network"]
			if carried := strings.Contains(nw, "[Network]\nDNS=fe80::1\n"); carried != ok {
				t.Errorf("zone %q: carried in lan0's file %v, want %v:\n%s", zone, carried, ok, nw)
			}
			if noted := strings.Contains(strings.Join(notes, "\n"), "fe80::1"); noted == ok {
				t.Errorf("zone %q: noted %v, want %v: %q", zone, noted, !ok, notes)
			}
			if strings.Count(nw, "DNS=") > 1 {
				t.Errorf("zone %q: the nameserver is set twice:\n%s", zone, nw)
			}
			if zone == "" && !strings.Contains(strings.Join(notes, "\n"), "names no interface") {
				t.Errorf("notes %q do not say the nameserver names no interface", notes)
			}
		})
	}
}

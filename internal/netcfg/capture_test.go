//go:build linux

package netcfg

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const netnsEnv = "BOOT_TO_KAIROS_NETCFG_NETNS"

// netnsSetup builds, in the child's own network namespace, a bond of two
// dummies with a VLAN on it, and a bridge, with addresses, routes and a rule.
const netnsSetup = `set -e
ip link add d1 type dummy
ip link add d2 type dummy
ip link add bond0 type bond mode active-backup miimon 100
ip link set d1 master bond0
ip link set d2 master bond0
ip link set bond0 type bond primary d2
ip link add link bond0 name bond0.10 type vlan id 10
ip link add br0 type bridge stp_state 1
ip link add d3 type dummy
ip link set d3 master br0
for l in d1 d2 d3 bond0 bond0.10 br0; do ip link set "$l" up; done
ip link set bond0.10 mtu 1400
ip addr add 192.0.2.10/24 dev bond0.10
ip addr add 2001:db8::10/64 dev bond0.10 nodad
ip addr add 198.51.100.5/24 dev br0 valid_lft 300 preferred_lft 300
ip route add 203.0.113.0/24 via 192.0.2.1 dev bond0.10 proto static metric 7
ip route add default via 198.51.100.200 dev bond0.10 onlink
ip rule add from 192.0.2.10 table 100 prio 100
ip -6 route add 2001:db8:5::/48 from 2001:db8::/64 via fe80::1 dev bond0.10 proto static
`

// TestMain doubles as the child, re-run in a network namespace of its own.
func TestMain(m *testing.M) {
	if os.Getenv(netnsEnv) != "" {
		os.Exit(netnsChild())
	}
	os.Exit(m.Run())
}

func netnsChild() int {
	// Fail closed before anything is created: in the host's namespace the
	// links below would take the host off its network.
	if err := freshNetns(); err != nil {
		os.Stderr.WriteString(err.Error())
		return 2
	}
	// Loaded without these, either module creates a device in the host's
	// namespace, whichever namespace asked for it; already loaded, modprobe
	// changes nothing and only this namespace gets devices.
	for _, m := range [][]string{{"bonding", "max_bonds=0"}, {"dummy", "numdummies=0"}} {
		if out, err := exec.CommandContext(context.Background(), "modprobe", m...).CombinedOutput(); err != nil {
			os.Stderr.WriteString("modprobe " + strings.Join(m, " ") + ": " + err.Error() + ": " + string(out))
			return 6
		}
	}
	if out, err := exec.CommandContext(context.Background(), "sh", "-c", netnsSetup).CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		return 3
	}
	h, err := capture("/nonexistent")
	if err != nil {
		os.Stderr.WriteString(err.Error())
		return 4
	}
	if err := json.NewEncoder(os.Stdout).Encode(h); err != nil { //nolint:musttag // round-trips through the field names
		return 5
	}
	return 0
}

var errSharedNetns = errors.New("not in a network namespace of its own")

func freshNetns() error {
	own, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	parent, err := os.Readlink("/proc/" + strconv.Itoa(os.Getppid()) + "/ns/net")
	if err != nil {
		return err
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return err
	}
	if own == parent || own == init {
		return errSharedNetns
	}
	return nil
}

func TestFreshNetnsRefusesTheParentsNamespace(t *testing.T) {
	// Unprivileged, /proc/1/ns cannot be read, which refuses too.
	err := freshNetns()
	if err == nil || os.Geteuid() == 0 && !errors.Is(err, errSharedNetns) {
		t.Fatalf("err = %v: the guard must refuse the namespace the tests run in", err)
	}
}

func TestCaptureInANetworkNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a network namespace")
	}
	for _, tool := range []string{"ip", "modprobe"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("needs %s: %v", tool, err)
		}
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), netnsEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v", err)
	}
	var h Host
	if err := json.Unmarshal(out, &h); err != nil { //nolint:musttag // round-trips through the field names
		t.Fatal(err)
	}
	links := map[string]*Link{}
	for i := range h.Links {
		links[h.Links[i].Name] = &h.Links[i]
	}
	d1, d2, d3, bond, vlan, br := links["d1"], links["d2"], links["d3"], links["bond0"], links["bond0.10"], links["br0"]
	if d1 == nil || d2 == nil || d3 == nil || bond == nil || vlan == nil || br == nil {
		t.Fatalf("links %+v", h.Links)
	}
	if bond.Kind != "bond" || bond.Info[bondMode][0] != 1 || d1.Master != bond.Index || d2.Master != bond.Index || d1.SlaveKind != "bond" {
		t.Errorf("bond: %+v; d1 %+v", bond, d1)
	}
	if v, _ := uintOf(bond.Info[bondPrimary], false); int(v) != d2.Index {
		t.Errorf("bond primary %d, want d2 %d", v, d2.Index)
	}
	// The bond gives d2 its own MAC; the burnt-in one comes from the bond.
	if !slices.Equal(d2.MAC, bond.MAC) || slices.Equal(d2.PermMAC, d2.MAC) || !known(d2.PermMAC) {
		t.Errorf("d2 MAC %s, permanent %s, bond %s", d2.MAC, d2.PermMAC, bond.MAC)
	}
	if vlan.Kind != "vlan" || vlan.Parent != bond.Index || vlan.MTU != 1400 {
		t.Errorf("vlan %+v", vlan)
	}
	if v, _ := uintOf(vlan.Info[vlanID], false); v != 10 {
		t.Errorf("vlan id %d", v)
	}
	if br.Kind != "bridge" || d3.Master != br.Index || d3.SlaveKind != "bridge" {
		t.Errorf("bridge %+v; d3 %+v", br, d3)
	}
	wantAddrs := map[string]Addr{
		// The kernel labels every IPv4 address, by default with the link's name.
		"192.0.2.10/24":   {Prefix: netip.MustParsePrefix("192.0.2.10/24"), Global: true, Label: "bond0.10"},
		"2001:db8::10/64": {Prefix: netip.MustParsePrefix("2001:db8::10/64"), Global: true},
	}
	for _, a := range vlan.Addrs {
		if w, ok := wantAddrs[a.Prefix.String()]; ok {
			if a != w {
				t.Errorf("address %+v, want %+v", a, w)
			}
			delete(wantAddrs, a.Prefix.String())
		}
	}
	if len(wantAddrs) > 0 {
		t.Errorf("missing %v among %+v", wantAddrs, vlan.Addrs)
	}
	if len(br.Addrs) != 1 || !br.Addrs[0].Dynamic || !br.Addrs[0].Global {
		t.Errorf("br0 addresses %+v, want one with a lifetime", br.Addrs)
	}
	var static, onlink, sourced bool
	for _, r := range h.Routes {
		switch {
		case r.Dst.String() == "2001:db8:5::/48":
			sourced = r.From.String() == "2001:db8::/64" && r.Gw.String() == "fe80::1"
		case r.Dst.String() == "203.0.113.0/24":
			static = r.Proto == protoStatic && r.Metric == 7 && r.Gw.String() == "192.0.2.1" && r.Link == vlan.Index && r.Table == tableMain
		case r.Dst.Bits() == 0 && r.Dst.Addr().Is4():
			onlink = r.OnLink && r.Proto == protoBoot && r.Gw.String() == "198.51.100.200"
		}
	}
	if !static || !onlink || !sourced {
		t.Errorf("routes %+v", h.Routes)
	}
	if h.ExtraRules != 1 {
		t.Errorf("extra rules %d, want 1", h.ExtraRules)
	}

	// The dummies stand in for NICs: the kernel's attributes of a bond, a
	// VLAN and a bridge made with only the options above must all be known,
	// at their defaults where not set.
	for _, d := range []*Link{d1, d2, d3} {
		d.Kind = ""
	}
	files, _, err := Plan(&h)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = f.Content
	}
	for path, lines := range map[string][]string{
		"/etc/systemd/network/10-btk-bond0.netdev":                                                     {"[Bond]\nMode=active-backup\nMIIMonitorSec=100ms\n"},
		"/etc/systemd/network/10-btk-bond0.10.netdev":                                                  {"[VLAN]\nId=10\n"},
		"/etc/systemd/network/10-btk-br0.netdev":                                                       {"[Bridge]\nSTP=yes\n"},
		"/etc/systemd/network/10-btk-br0.network":                                                      {"DHCP=ipv4"},
		"/etc/systemd/network/10-btk-" + strings.ReplaceAll(d2.PermMAC.String(), ":", "") + ".network": {"Bond=bond0\nPrimarySlave=yes\n"},
	} {
		for _, l := range lines {
			if !strings.Contains(got[path], l) {
				t.Errorf("%s:\n%s\nwant %q", path, got[path], l)
			}
		}
	}
	if c := got["/etc/systemd/network/10-btk-bond0.netdev"]; strings.Count(c, "\n") != 8 {
		t.Errorf("a bond with defaults carries more than its mode and miimon:\n%s", c)
	}
}

func TestCaptureReadsTheLoopback(t *testing.T) {
	h, err := capture(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range h.Links {
		if l.Type == arphrdLoopback {
			for _, a := range l.Addrs {
				if a.Prefix.String() == "127.0.0.1/8" && !a.Dynamic && !a.Global {
					return
				}
			}
			t.Fatalf("loopback addresses %+v", l.Addrs)
		}
	}
	t.Fatalf("no loopback among %+v", h.Links)
}

func TestCaptureMarksLeases(t *testing.T) {
	root := t.TempDir()
	put(t, root, "run/systemd/netif/leases/1", "ADDRESS=127.0.0.1\n")
	h, err := capture(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range h.Links {
		for _, a := range l.Addrs {
			if l.Index == 1 && a.Prefix.String() == "127.0.0.1/8" && a.Dynamic {
				return
			}
		}
	}
	t.Fatalf("a leased address is taken for a static one: %+v", h.Links)
}

func TestReadDNS(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "resolv.conf")
	upstream := filepath.Join(dir, "upstream.conf")
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(upstream, "# generated\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch from-upstream.test\n")

	write(stub, "nameserver 127.0.0.53\noptions edns0\nsearch example.test example.org\n")
	dns, search := readDNS(stub, upstream)
	if len(dns) != 2 || dns[0].String() != "192.0.2.53" || dns[1].String() != "2001:db8::53" || strings.Join(search, " ") != "from-upstream.test" {
		t.Errorf("behind the resolved stub: dns %v search %v, want resolved's upstream file", dns, search)
	}

	write(stub, "domain example.net\nnameserver 192.0.2.1\nnameserver bogus\n")
	dns, search = readDNS(stub, upstream)
	if len(dns) != 1 || dns[0].String() != "192.0.2.1" || strings.Join(search, " ") != "example.net" {
		t.Errorf("plain resolv.conf: dns %v search %v", dns, search)
	}

	write(stub, "search a.test\ndomain b.test\nnameserver 127.0.0.1\n")
	dns, search = readDNS(stub, upstream)
	if len(dns) != 1 || !dns[0].IsLoopback() || strings.Join(search, " ") != "b.test" {
		t.Errorf("last of search and domain wins, a local resolver is kept for Plan to drop: dns %v search %v", dns, search)
	}

	if dns, search = readDNS(filepath.Join(dir, "missing"), upstream); dns != nil || search != nil {
		t.Errorf("no resolv.conf: dns %v search %v", dns, search)
	}
}

func TestWireless(t *testing.T) {
	sys := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sys, "wlan0/wireless"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sys, "eth0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !wireless(sys, "wlan0") || wireless(sys, "eth0") {
		t.Error("wireless is told by the sysfs wireless directory")
	}
}

func TestDriver(t *testing.T) {
	sys := t.TempDir()
	drv := filepath.Join(sys, "bus/vmbus/drivers/hv_netvsc")
	if err := os.MkdirAll(drv, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sys, "eth0/device"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(drv, filepath.Join(sys, "eth0/device/driver")); err != nil {
		t.Fatal(err)
	}
	if got := driver(sys, "eth0"); got != "hv_netvsc" {
		t.Errorf("driver = %q", got)
	}
	if got := driver(sys, "bond0"); got != "" {
		t.Errorf("a device without a driver: %q", got)
	}
}

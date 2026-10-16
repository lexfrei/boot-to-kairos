package netcfg

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func put(t *testing.T, root, path, content string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// bootp is a dhcpcd lease: the DHCP message, with the offered address at
// yiaddr and, if given, the lease time in option 51.
func bootp(addr string, lifetime ...uint32) string {
	return bootpWith(addr, lifetime, nil)
}

func bootpWith(addr string, lifetime []uint32, routers []string) string {
	var b bytes.Buffer
	b.Write(make([]byte, 16))
	a := netip.MustParseAddr(addr).As4()
	b.Write(a[:])
	b.Write(make([]byte, 236-b.Len()))
	b.Write([]byte{99, 130, 83, 99})
	if len(routers) > 0 {
		b.Write([]byte{0, 3, byte(4 * len(routers))})
		for _, r := range routers {
			ra := netip.MustParseAddr(r).As4()
			b.Write(ra[:])
		}
	}
	for _, l := range lifetime {
		b.Write(binary.BigEndian.AppendUint32([]byte{51, 4}, l))
	}
	b.WriteByte(255)
	return b.String()
}

var leaseNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func leased(t *testing.T, root string) map[string]bool {
	t.Helper()
	h := &Host{Links: []Link{
		nic(2, "eth0", "52:54:00:12:34:56", static("10.0.2.15/24"), static("10.0.2.99/24"), static("2001:db8::15/64")),
		nic(3, "eth1", "52:54:00:12:34:57", static("10.0.3.15/24")),
	}}
	markLeases(root, h, leaseNow)
	got := map[string]bool{}
	for _, l := range h.Links {
		for _, a := range l.Addrs {
			got[a.Prefix.String()] = a.Dynamic
		}
	}
	return got
}

func TestLeases(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		want  []string
	}{
		"none": {nil, nil},
		"networkd lease": {
			map[string]string{"run/systemd/netif/leases/2": "# This is private data. Do not parse.\nADDRESS=10.0.2.15\nNETMASK=255.255.255.0\n"},
			[]string{"10.0.2.15/24"},
		},
		"networkd lease for another link": {map[string]string{"run/systemd/netif/leases/3": "ADDRESS=10.0.2.15\n"}, nil},
		"NetworkManager internal lease": {
			map[string]string{"var/lib/NetworkManager/internal-1b2c-eth1.lease": "# generated\nADDRESS=10.0.3.15\n"},
			[]string{"10.0.3.15/24"},
		},
		"stale NetworkManager lease": {map[string]string{"var/lib/NetworkManager/internal-1b2c-eth1.lease": "ADDRESS=10.0.3.99\n"}, nil},
		"dhclient lease": {map[string]string{"var/lib/dhcp/dhclient.leases": `lease {
  interface "eth1";
  fixed-address 10.0.9.9;
}
lease {
  interface "eth0";
  fixed-address 10.0.2.15;
  option subnet-mask 255.255.255.0;
}
`}, []string{"10.0.2.15/24"}},
		"dhclient lease of another interface": {map[string]string{"var/lib/dhclient/dhclient--eth1.lease": "lease {\n  interface \"eth1\";\n  fixed-address 10.0.2.15;\n}\n"}, nil},
		"NetworkManager dhclient lease": {
			map[string]string{"var/lib/NetworkManager/dhclient-1b2c-eth0.lease": "lease {\n  fixed-address 10.0.2.15;\n}\n"},
			[]string{"10.0.2.15/24"},
		},
		"NetworkManager dhclient lease of another interface": {map[string]string{"var/lib/NetworkManager/dhclient-1b2c-eth0.lease": "lease {\n  interface \"eth1\";\n  fixed-address 10.0.2.15;\n}\n"}, nil},
		"dhcpcd lease":                 {map[string]string{"var/lib/dhcpcd/eth0.lease": bootp("10.0.2.15")}, []string{"10.0.2.15/24"}},
		"old dhcpcd lease":             {map[string]string{"var/lib/dhcpcd/dhcpcd-eth1.lease": bootp("10.0.3.15")}, []string{"10.0.3.15/24"}},
		"dhcpcd lease with time left":  {map[string]string{"var/lib/dhcpcd/eth0.lease": bootp("10.0.2.15", 86400)}, []string{"10.0.2.15/24"}},
		"expired dhcpcd lease":         {map[string]string{"var/lib/dhcpcd/eth0.lease": bootp("10.0.2.15", 86400)}, nil},
		"expired NetworkManager lease": {map[string]string{"var/lib/NetworkManager/internal-1b2c-eth1.lease": "ADDRESS=10.0.3.15\nLIFETIME=3600\n"}, nil},
		"NetworkManager lease with time left": {
			map[string]string{"var/lib/NetworkManager/internal-1b2c-eth1.lease": "ADDRESS=10.0.3.15\nLIFETIME=3600\n"},
			[]string{"10.0.3.15/24"},
		},
		"stale dhcpcd lease": {map[string]string{"var/lib/dhcpcd/eth0.lease": bootp("10.0.2.16")}, nil},
		"dhclient running": {
			map[string]string{"proc/411/comm": "dhclient\n", "proc/411/cmdline": "/sbin/dhclient\x00-4\x00-v\x00eth1\x00"},
			[]string{"10.0.3.15/24"},
		},
		"udhcpc running": {
			map[string]string{"proc/412/comm": "udhcpc\n", "proc/412/cmdline": "udhcpc\x00-i\x00eth0\x00-f\x00"},
			[]string{"10.0.2.15/24", "10.0.2.99/24"},
		},
		"udhcpc joined flag":        {map[string]string{"proc/413/comm": "udhcpc\n", "proc/413/cmdline": "udhcpc\x00-ieth1\x00"}, []string{"10.0.3.15/24"}},
		"dhcpcd long flag":          {map[string]string{"proc/414/comm": "dhcpcd\n", "proc/414/cmdline": "dhcpcd\x00--interface=eth0\x00"}, []string{"10.0.2.15/24", "10.0.2.99/24"}},
		"other process naming eth0": {map[string]string{"proc/415/comm": "tcpdump\n", "proc/415/cmdline": "tcpdump\x00-i\x00eth0\x00"}, nil},
		"client and lease": {
			map[string]string{"proc/417/comm": "udhcpc\n", "proc/417/cmdline": "udhcpc\x00-i\x00eth0\x00", "run/systemd/netif/leases/2": "ADDRESS=10.0.2.15\n"},
			[]string{"10.0.2.15/24"},
		},
		"expired dhclient lease":        {map[string]string{"var/lib/dhcp/dhclient.eth0.leases": "lease {\n  interface \"eth0\";\n  fixed-address 10.0.2.15;\n  expire 3 2026/10/14 09:00:00;\n}\n"}, nil},
		"expired dhclient lease, epoch": {map[string]string{"var/lib/dhcp/dhclient.eth0.leases": "lease {\n  interface \"eth0\";\n  fixed-address 10.0.2.15;\n  expire epoch 1760000000; # Thu Oct 09 08:53:20 2025\n}\n"}, nil},
		"current dhclient lease": {
			map[string]string{"var/lib/dhcp/dhclient.eth0.leases": "lease {\n  interface \"eth0\";\n  fixed-address 10.0.2.15;\n  expire 6 2026/10/17 09:00:00;\n}\n"},
			[]string{"10.0.2.15/24"},
		},
		"dhclient lease that never expires": {
			map[string]string{"var/lib/dhcp/dhclient.eth0.leases": "lease {\n  interface \"eth0\";\n  fixed-address 10.0.2.15;\n  expire never;\n}\n"},
			[]string{"10.0.2.15/24"},
		},
		"dhcpcd for all interfaces": {map[string]string{"proc/416/comm": "dhcpcd\n", "proc/416/cmdline": "dhcpcd\x00-q\x00"}, nil},
	} {
		// A lease file under /var/lib counts only while a DHCP client runs:
		// one left from before a switch to a static address would take the
		// host off the network.
		// These were written two days before now.
		aged := map[string]bool{"expired dhcpcd lease": true, "expired NetworkManager lease": true}[name]
		persistent := false
		for p := range tc.files {
			persistent = persistent || strings.HasPrefix(p, "var/lib/")
		}
		if persistent {
			t.Run(name+", no client running", func(t *testing.T) {
				root := t.TempDir()
				for p, c := range tc.files {
					put(t, root, p, c)
				}
				for a, dyn := range leased(t, root) {
					if dyn {
						t.Errorf("%s is taken for a lease with no DHCP client running", a)
					}
				}
			})
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for p, c := range tc.files {
				put(t, root, p, c)
				mtime := leaseNow.Add(-time.Minute)
				if aged {
					mtime = leaseNow.Add(-48 * time.Hour)
				}
				if err := os.Chtimes(filepath.Join(root, p), mtime, mtime); err != nil {
					t.Fatal(err)
				}
			}
			if persistent {
				put(t, root, "proc/9/comm", "dhclient\n")
				put(t, root, "proc/9/cmdline", "dhclient\x00-q\x00")
			}
			got := leased(t, root)
			for _, a := range tc.want {
				if !got[a] {
					t.Errorf("%s is not taken for a lease: %v", a, got)
				}
				delete(got, a)
			}
			for a, dyn := range got {
				if dyn {
					t.Errorf("%s is taken for a lease: %v", a, got)
				}
			}
		})
	}
}

func TestLeasedAddressGetsDHCP(t *testing.T) {
	root := t.TempDir()
	put(t, root, "run/systemd/netif/leases/2", "ADDRESS=10.0.2.15\n")
	h := &Host{Links: []Link{nic(2, "eth0", "52:54:00:12:34:56", static("10.0.2.15/24"))}, Routes: []Route{route("192.0.2.0/24", "10.0.2.2", 2)}}
	markLeases(root, h, leaseNow)
	fs, _, err := Plan(h)
	if err != nil || len(fs) != 1 {
		t.Fatalf("files %v, err %v", fs, err)
	}
	if c := fs[0].Content; strings.Contains(c, "Address=10.0.2.15") || !strings.Contains(c, "DHCP=ipv4") {
		t.Errorf("a leased address must stay a DHCP lease, never become static:\n%s", c)
	}
}

func TestLeaseGateways(t *testing.T) {
	client := map[string]string{"proc/9/comm": "dhclient\n", "proc/9/cmdline": "dhclient\x00-q\x00"}
	for name, tc := range map[string]struct {
		files  map[string]string
		want   string
		client bool
	}{
		"networkd":                 {map[string]string{"run/systemd/netif/leases/2": "ADDRESS=10.0.2.15\nROUTER=10.0.2.2 10.0.2.3\n"}, "10.0.2.2 10.0.2.3", false},
		"NetworkManager":           {map[string]string{"var/lib/NetworkManager/internal-1b2c-eth0.lease": "ADDRESS=10.0.2.15\nROUTER=10.0.2.2\n"}, "10.0.2.2", false},
		"dhclient":                 {map[string]string{"var/lib/dhcp/dhclient.leases": "lease {\n  interface \"eth0\";\n  fixed-address 10.0.2.15;\n  option routers 10.0.2.2,10.0.2.4;\n}\n"}, "10.0.2.2 10.0.2.4", false},
		"dhcpcd":                   {map[string]string{"var/lib/dhcpcd/eth0.lease": bootpWith("10.0.2.15", nil, []string{"10.0.2.2"})}, "10.0.2.2", false},
		"lease of another address": {map[string]string{"run/systemd/netif/leases/2": "ADDRESS=10.0.2.16\nROUTER=10.0.2.2\n"}, "", false},
		"client without a lease":   {map[string]string{"proc/7/comm": "udhcpc\n", "proc/7/cmdline": "udhcpc\x00-i\x00eth0\x00"}, "", true},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for p, c := range tc.files {
				put(t, root, p, c)
			}
			for p, c := range client {
				put(t, root, p, c)
			}
			h := &Host{Links: []Link{nic(2, "eth0", "52:54:00:12:34:56", static("10.0.2.15/24"))}}
			markLeases(root, h, leaseNow)
			var got []string
			for _, g := range h.Links[0].LeaseGateways {
				got = append(got, g.String())
			}
			if strings.Join(got, " ") != tc.want || h.Links[0].DHCPClient != tc.client {
				t.Errorf("gateways %v, client-owned %v; want %q, %v", got, h.Links[0].DHCPClient, tc.want, tc.client)
			}
		})
	}
}

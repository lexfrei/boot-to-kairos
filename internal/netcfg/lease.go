package netcfg

import (
	"bufio"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// markLeases marks the IPv4 addresses a DHCP client owns as dynamic, and
// records the gateways their leases name. Some clients, dhclient among
// them, install a lease without a lifetime, and its gateway as a proto boot
// route; carried as static they would outlive the lease and collide with
// the next host given the address.
//
// networkd's leases live in /run and go with the client. A lease file under
// /var/lib outlives its client, and is also left behind when an address
// handed out by DHCP is made static; one counts only while a DHCP client
// runs, unexpired, and for the address it records. A client running for a
// link owns the addresses its leases record, or all of the link's IPv4
// addresses when none is found.
func markLeases(root string, h *Host, now time.Time) {
	clients, anyClient := runningClients(root)
	for i := range h.Links {
		l := &h.Links[i]
		leases := keyValueLeases(filepath.Join(root, "run/systemd/netif/leases", strconv.Itoa(l.Index)))
		if anyClient {
			leases = append(leases, storedLeases(root, l, now)...)
		}
		l.DHCPClient = clients[l.Name] && len(leases) == 0
		for j := range l.Addrs {
			a := &l.Addrs[j]
			if !a.Prefix.Addr().Is4() {
				continue
			}
			for _, ls := range leases {
				if ls.addr == a.Prefix.Addr() {
					a.Dynamic = true
					l.LeaseGateways = append(l.LeaseGateways, ls.routers...)
				}
			}
			a.Dynamic = a.Dynamic || l.DHCPClient
		}
	}
}

type lease struct {
	addr    netip.Addr
	routers []netip.Addr
}

func storedLeases(root string, l *Link, now time.Time) []lease {
	var out []lease
	nm, _ := filepath.Glob(filepath.Join(root, "var/lib/NetworkManager", "*-"+l.Name+".lease"))
	for _, f := range nm {
		if !expiredAt(f, keyValueLifetime(f), now) {
			out = append(out, keyValueLeases(f)...)
		}
		out = append(out, dhclientLeases(f, l.Name, true, now)...)
	}
	for _, dir := range []string{"var/lib/dhcp", "var/lib/dhclient"} {
		fs, _ := filepath.Glob(filepath.Join(root, dir, "*.lease*"))
		for _, f := range fs {
			out = append(out, dhclientLeases(f, l.Name, false, now)...)
		}
	}
	for _, name := range []string{l.Name + ".lease", "dhcpcd-" + l.Name + ".lease"} {
		// dhcpcd stores the DHCP message; the address it got is yiaddr.
		f := filepath.Join(root, "var/lib/dhcpcd", name)
		if b, err := os.ReadFile(f); err == nil && len(b) >= 20 && !expiredAt(f, bootpLifetime(b), now) {
			ls := lease{addr: netip.AddrFrom4([4]byte(b[16:20]))}
			opt := bootpOption(b, dhcpRouters)
			for i := 0; i+4 <= len(opt); i += 4 {
				ls.routers = append(ls.routers, netip.AddrFrom4([4]byte(opt[i:i+4])))
			}
			out = append(out, ls)
		}
	}
	return out
}

// expiredAt tells whether a lease written at the file's modification time
// with lifetime seconds has run out by now. Without a lifetime it has not.
func expiredAt(path string, lifetime uint32, now time.Time) bool {
	st, err := os.Stat(path)
	return err == nil && lifetime > 0 && st.ModTime().Add(time.Duration(lifetime)*time.Second).Before(now)
}

func keyValueLifetime(path string) uint32 {
	var out uint32
	forLines(path, func(line string) {
		if v, ok := strings.CutPrefix(line, "LIFETIME="); ok {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				out = uint32(n)
			}
		}
	})
	return out
}

const (
	dhcpRouters   = 3
	dhcpLeaseTime = 51
)

// bootpLifetime reads the lease time from a DHCP message.
func bootpLifetime(b []byte) uint32 {
	if v := bootpOption(b, dhcpLeaseTime); len(v) == 4 {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

// bootpOption returns the value of a DHCP option from the options that
// follow the magic cookie of a DHCP message.
func bootpOption(b []byte, code byte) []byte {
	const optionsAt, pad, end = 240, 0, 255
	for i := optionsAt; i < len(b); {
		switch b[i] {
		case pad:
			i++
			continue
		case end:
			return nil
		}
		if i+1 >= len(b) || i+2+int(b[i+1]) > len(b) {
			return nil
		}
		if b[i] == code {
			return b[i+2 : i+2+int(b[i+1])]
		}
		i += 2 + int(b[i+1])
	}
	return nil
}

// keyValueLeases reads ADDRESS= and ROUTER= from a lease of networkd or of
// NetworkManager's internal client.
func keyValueLeases(path string) []lease {
	var ls lease
	forLines(path, func(line string) {
		if v, ok := strings.CutPrefix(line, "ADDRESS="); ok {
			ls.addr, _ = netip.ParseAddr(v)
		}
		if v, ok := strings.CutPrefix(line, "ROUTER="); ok {
			ls.routers = append(ls.routers, addrList(strings.Fields(v))...)
		}
	})
	if !ls.addr.IsValid() {
		return nil
	}
	return []lease{ls}
}

func addrList(ss []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// dhclientLeases reads fixed-address and option routers from the unexpired
// lease blocks of a dhclient lease file that are for ifname, or from every
// block when the file is named for it.
func dhclientLeases(path, ifname string, named bool, now time.Time) []lease {
	var out []lease
	var iface string
	var ls lease
	var expired bool
	forLines(path, func(line string) {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ";"))
		switch {
		case len(f) > 1 && f[0] == "lease" && f[1] == "{":
			iface, ls, expired = "", lease{}, false
		case len(f) == 2 && f[0] == "interface":
			iface = strings.Trim(f[1], `"`)
		case len(f) == 2 && f[0] == "fixed-address":
			ls.addr, _ = netip.ParseAddr(f[1])
		case len(f) == 3 && f[0] == "option" && f[1] == "routers":
			ls.routers = addrList(strings.Split(f[2], ","))
		case len(f) > 1 && f[0] == "expire":
			expired = dhclientExpiry(f[1:]).Before(now)
		case len(f) == 1 && f[0] == "}":
			if ls.addr.IsValid() && !expired && (iface == ifname || named && iface == "") {
				out = append(out, ls)
			}
		}
	})
	return out
}

// dhclientExpiry reads "never", "epoch <seconds>" or "<weekday>
// yyyy/mm/dd hh:mm:ss" in UTC. What it cannot read counts as unexpired.
func dhclientExpiry(f []string) time.Time {
	switch {
	case len(f) == 2 && f[0] == "epoch":
		if s, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			return time.Unix(s, 0)
		}
	case len(f) == 3:
		if t, err := time.Parse("2006/01/02 15:04:05", f[1]+" "+f[2]); err == nil {
			return t
		}
	}
	return time.Unix(1<<62, 0)
}

func forLines(path string, f func(string)) {
	fh, err := os.Open(path)
	if err != nil {
		return
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		f(strings.TrimSpace(sc.Text()))
	}
}

var dhcpClients = []string{"dhclient", "dhcpcd", "udhcpc"} //nolint:gochecknoglobals // fixed list

// runningClients returns the interfaces a running DHCP client names on its
// command line, and whether any DHCP client runs at all. One started without
// an interface leaves lease files, which storedLeases reads.
func runningClients(root string) (map[string]bool, bool) {
	out := map[string]bool{}
	running := false
	comms, _ := filepath.Glob(filepath.Join(root, "proc/[0-9]*/comm"))
	for _, c := range comms {
		comm, err := os.ReadFile(c)
		if err != nil || !slices.Contains(dhcpClients, strings.TrimSpace(string(comm))) {
			continue
		}
		running = true
		cmdline, err := os.ReadFile(filepath.Join(filepath.Dir(c), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		for _, a := range args[1:] {
			switch {
			case strings.HasPrefix(a, "--interface="):
				out[strings.TrimPrefix(a, "--interface=")] = true
			case strings.HasPrefix(a, "-i") && len(a) > 2:
				out[a[2:]] = true
			case !strings.HasPrefix(a, "-"):
				out[a] = true
			}
		}
	}
	return out, running
}

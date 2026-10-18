//go:build linux

package netcfg

import (
	"bufio"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cockroachdb/errors"
)

// Capture reads the host's network configuration from the kernel, its DHCP
// clients and its resolver configuration.
func Capture() (*Host, error) { return capture("/") }

// capture reads files under root, the kernel through netlink.
func capture(root string) (*Host, error) {
	h := &Host{}
	links, err := dump(syscall.RTM_GETLINK, syscall.RTM_NEWLINK)
	if err != nil {
		return nil, errors.Wrap(err, "list links")
	}
	byIndex := map[int]*Link{}
	for _, m := range links {
		l, err := parseLink(m)
		if err != nil {
			return nil, err
		}
		l.Wireless = wireless(filepath.Join(root, "sys/class/net"), l.Name)
		l.Driver = driver(filepath.Join(root, "sys/class/net"), l.Name)
		h.Links = append(h.Links, l)
	}
	for i := range h.Links {
		byIndex[h.Links[i].Index] = &h.Links[i]
	}
	addrs, err := dump(syscall.RTM_GETADDR, syscall.RTM_NEWADDR)
	if err != nil {
		return nil, errors.Wrap(err, "list addresses")
	}
	for _, m := range addrs {
		idx, a, ok := parseAddr(m)
		if l := byIndex[idx]; ok && l != nil {
			l.Addrs = append(l.Addrs, a)
		}
	}
	routes, err := dump(syscall.RTM_GETROUTE, syscall.RTM_NEWROUTE)
	if err != nil {
		return nil, errors.Wrap(err, "list routes")
	}
	for _, m := range routes {
		if r, ok := parseRoute(m); ok {
			h.Routes = append(h.Routes, r)
		}
	}
	rules, err := dump(rtmGetRule, rtmNewRule)
	if err != nil {
		return nil, errors.Wrap(err, "list routing rules")
	}
	for _, m := range rules {
		if !defaultRule(m) {
			h.ExtraRules++
		}
	}
	markLeases(root, h, time.Now())
	markAdvertised(h)
	h.DNS, h.Search = readDNS(filepath.Join(root, "etc/resolv.conf"), filepath.Join(root, "run/systemd/resolve/resolv.conf"))
	return h, nil
}

const (
	rtmNewRule = 32
	rtmGetRule = 34

	iflaLinkInfo      = 18
	iflaLinkNetnsID   = 37
	iflaPermAddress   = 54
	iflaInfoKind      = 1
	iflaInfoData      = 2
	iflaInfoSlaveKind = 4
	iflaInfoSlaveData = 5

	ifaFlags          = 8
	ifaFPermanent     = 0x80
	ifaFMngTmpAddr    = 0x100
	ifaFNoPrefixRoute = 0x200

	rtaMetrics   = 8
	rtaMultipath = 9
	rtaTable     = 15
	rtaVia       = 18
	rtaNHID      = 30
	rtaxMTU      = 2
	rtnhFOnLink  = 4

	fraPriority = 6
	fraTable    = 15

	nlaTypeMask = 0x3fff
)

func dump(req, want int) ([][]byte, error) {
	b, err := syscall.NetlinkRIB(req, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, m := range msgs {
		if int(m.Header.Type) == want {
			out = append(out, m.Data)
		}
	}
	return out, nil
}

type attr struct {
	typ uint16
	val []byte
}

func attrs(b []byte) []attr {
	var out []attr
	for len(b) >= 4 {
		n := int(binary.NativeEndian.Uint16(b))
		if n < 4 || n > len(b) {
			break
		}
		out = append(out, attr{binary.NativeEndian.Uint16(b[2:]) & nlaTypeMask, b[4:n]})
		next := (n + 3) &^ 3
		if next > len(b) {
			break
		}
		b = b[next:]
	}
	return out
}

func toAttrs(as []attr) Attrs {
	m := Attrs{}
	for _, a := range as {
		m[a.typ] = a.val
	}
	return m
}

func cstring(b []byte) string { return strings.TrimRight(string(b), "\x00") }

func u32At(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	return int(binary.NativeEndian.Uint32(b))
}

func parseLink(m []byte) (Link, error) {
	if len(m) < syscall.SizeofIfInfomsg {
		return Link{}, errors.New("short link message")
	}
	l := Link{Type: binary.NativeEndian.Uint16(m[2:]), Index: int(int32(binary.NativeEndian.Uint32(m[4:])))}
	var otherNetns bool
	for _, a := range attrs(m[syscall.SizeofIfInfomsg:]) {
		switch a.typ {
		case syscall.IFLA_IFNAME:
			l.Name = cstring(a.val)
		case syscall.IFLA_ADDRESS:
			l.MAC = net.HardwareAddr(a.val)
		case iflaPermAddress:
			l.PermMAC = net.HardwareAddr(a.val)
		case syscall.IFLA_MTU:
			l.MTU = uint32(u32At(a.val))
		case syscall.IFLA_MASTER:
			l.Master = u32At(a.val)
		case syscall.IFLA_LINK:
			l.Parent = u32At(a.val)
		case iflaLinkNetnsID:
			otherNetns = true
		case iflaLinkInfo:
			for _, i := range attrs(a.val) {
				switch i.typ {
				case iflaInfoKind:
					l.Kind = cstring(i.val)
				case iflaInfoData:
					l.Info = toAttrs(attrs(i.val))
				case iflaInfoSlaveKind:
					l.SlaveKind = cstring(i.val)
				case iflaInfoSlaveData:
					l.SlaveInfo = toAttrs(attrs(i.val))
				}
			}
		}
	}
	// IFLA_LINK of a veth or of a device whose lower link lives elsewhere
	// is an index in another namespace.
	if otherNetns {
		l.Parent = 0
	}
	if !known(l.PermMAC) && l.SlaveKind == "bond" {
		if p := l.SlaveInfo[bondSlavePermHWAddr]; known(p) {
			l.PermMAC = net.HardwareAddr(p)
		}
	}
	return l, nil
}

func addrOf(b []byte) netip.Addr {
	a, _ := netip.AddrFromSlice(b)
	return a.Unmap()
}

func parseAddr(m []byte) (int, Addr, bool) {
	if len(m) < syscall.SizeofIfAddrmsg {
		return 0, Addr{}, false
	}
	bits, flags, scope := int(m[1]), uint32(m[2]), m[3]
	idx := int(binary.NativeEndian.Uint32(m[4:]))
	var address, local netip.Addr
	// RFC 3879 deprecated site-local addresses, but one set by hand is
	// still the host's own; the kernel gives it site scope.
	a := Addr{Global: scope == syscall.RT_SCOPE_UNIVERSE || scope == syscall.RT_SCOPE_SITE}
	for _, at := range attrs(m[syscall.SizeofIfAddrmsg:]) {
		switch at.typ {
		case syscall.IFA_ADDRESS:
			address = addrOf(at.val)
		case syscall.IFA_LOCAL:
			local = addrOf(at.val)
		case syscall.IFA_LABEL:
			a.Label = cstring(at.val)
		case ifaFlags:
			flags = uint32(u32At(at.val))
		}
	}
	if !local.IsValid() {
		local = address
	}
	if !local.IsValid() {
		return 0, Addr{}, false
	}
	a.Prefix = netip.PrefixFrom(local, bits)
	if address.IsValid() && address != local {
		a.Peer = netip.PrefixFrom(address, bits)
	}
	a.Dynamic = flags&ifaFPermanent == 0
	a.NoPrefixRoute = flags&ifaFNoPrefixRoute != 0
	a.TempTemplate = flags&ifaFMngTmpAddr != 0
	return idx, a, true
}

func parseRoute(m []byte) (Route, bool) {
	if len(m) < syscall.SizeofRtMsg {
		return Route{}, false
	}
	family, dstLen, srcLen := m[0], int(m[1]), int(m[2])
	r := Route{Table: uint32(m[4]), Proto: m[5], Scope: m[6], Type: m[7], OnLink: binary.NativeEndian.Uint32(m[8:])&rtnhFOnLink != 0}
	var dst netip.Addr
	for _, a := range attrs(m[syscall.SizeofRtMsg:]) {
		switch a.typ {
		case syscall.RTA_DST:
			dst = addrOf(a.val)
		case syscall.RTA_SRC:
			r.From = netip.PrefixFrom(addrOf(a.val), srcLen)
		case syscall.RTA_GATEWAY:
			r.Gw = addrOf(a.val)
		case rtaVia:
			// struct rtvia: the family, then the address.
			if len(a.val) > 2 {
				r.Gw = addrOf(a.val[2:])
			}
		case syscall.RTA_OIF:
			r.Link = u32At(a.val)
		case syscall.RTA_PRIORITY:
			r.Metric = uint32(u32At(a.val))
		case syscall.RTA_PREFSRC:
			r.Src = addrOf(a.val)
		case rtaTable:
			r.Table = uint32(u32At(a.val))
		case rtaNHID:
			r.NextHopID = uint32(u32At(a.val))
		case rtaMetrics:
			for _, x := range attrs(a.val) {
				if x.typ == rtaxMTU {
					r.MTU = uint32(u32At(x.val))
				} else {
					r.OtherMetrics++
				}
			}
		case rtaMultipath:
			r.Hops = hops(a.val)
		}
	}
	if !dst.IsValid() {
		switch family {
		case syscall.AF_INET:
			dst = netip.IPv4Unspecified()
		case syscall.AF_INET6:
			dst = netip.IPv6Unspecified()
		default:
			return Route{}, false
		}
	}
	r.Dst = netip.PrefixFrom(dst, dstLen)
	return r, true
}

// hops returns the links of a multipath route's struct rtnexthop entries.
func hops(b []byte) []int {
	var out []int
	for len(b) >= 8 {
		n := int(binary.NativeEndian.Uint16(b))
		if n < 8 || n > len(b) {
			break
		}
		out = append(out, u32At(b[4:]))
		next := (n + 3) &^ 3
		if next > len(b) {
			break
		}
		b = b[next:]
	}
	return out
}

// defaultRule tells the rules the kernel creates on its own: local at 0,
// main at 32766 and, for IPv4, default at 32767.
func defaultRule(m []byte) bool {
	// struct fib_rule_hdr is laid out like struct rtmsg.
	if len(m) < syscall.SizeofRtMsg {
		return true
	}
	// Multicast routing has rules of its own, which are not carried.
	if m[0] != syscall.AF_INET && m[0] != syscall.AF_INET6 {
		return true
	}
	table, prio := uint32(m[4]), uint32(0)
	for _, a := range attrs(m[syscall.SizeofRtMsg:]) {
		switch a.typ {
		case fraPriority:
			prio = uint32(u32At(a.val))
		case fraTable:
			table = uint32(u32At(a.val))
		}
	}
	switch {
	case prio == 0 && table == syscall.RT_TABLE_LOCAL:
	case prio == 32766 && table == syscall.RT_TABLE_MAIN:
	case prio == 32767 && table == syscall.RT_TABLE_DEFAULT:
	default:
		return false
	}
	return true
}

// readDNS reads the nameservers and search domains from resolvConf, or from
// upstream when resolvConf only points at systemd-resolved's local stub.
func readDNS(resolvConf, upstream string) ([]netip.Addr, []string) {
	dns, search := parseResolvConf(resolvConf)
	if len(dns) > 0 && !slices.ContainsFunc(dns, func(a netip.Addr) bool { return a != resolvedStub }) {
		return parseResolvConf(upstream)
	}
	return dns, search
}

var resolvedStub = netip.MustParseAddr("127.0.0.53") //nolint:gochecknoglobals // constant

func parseResolvConf(path string) ([]netip.Addr, []string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	var dns []netip.Addr
	var search []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if a, err := netip.ParseAddr(fields[1]); err == nil {
				dns = append(dns, a)
			}
		case "search", "domain":
			// The last of the two wins, as for the resolver. systemd-resolved
			// writes "search ." for none; resolved.conf reads it as a route.
			search = slices.DeleteFunc(fields[1:], func(d string) bool { return d == "." })
		}
	}
	return dns, search
}

func driver(sysNet, name string) string {
	d, err := filepath.EvalSymlinks(filepath.Join(sysNet, name, "device/driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(d)
}

func wireless(sysNet, name string) bool {
	_, err := os.Stat(filepath.Join(sysNet, name, "wireless"))
	return err == nil
}

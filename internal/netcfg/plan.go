package netcfg

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
)

// ErrUnsupported is a configuration that cannot be carried faithfully.
var ErrUnsupported = errors.New("the host's network configuration cannot be carried over")

const (
	arphrdEther    = 1
	arphrdLoopback = 772

	protoRedirect = 1
	protoKernel   = 2
	protoBoot     = 3
	protoStatic   = 4
	protoRA       = 9
	protoDHCP     = 16

	rtnUnicast = 1
	tableMain  = 254
	scopeSite  = 200
	scopeLink  = 253
	scopeHost  = 254

	bondMode            = 1
	bondActiveSlave     = 2
	bondMIIMon          = 3
	bondARPTargets      = 8
	bondPrimary         = 11
	bondSlavePermHWAddr = 4

	vlanReorderHdr   = 1
	vlanGVRP         = 2
	vlanLooseBinding = 4
	vlanMVRP         = 8

	defaultMTU   = 1500
	networkDir   = "/etc/systemd/network/"
	filePrefix   = networkDir + "10-btk-"
	resolvedConf = "/etc/systemd/resolved.conf.d/10-btk.conf"
)

type planner struct {
	h       *Host
	byIndex map[int]*Link
	// members are the ports of each bond or bridge, uppers the VLANs on
	// each link.
	members, uppers map[int][]int
	routes          map[int][]Route
	// linkDNS are the link-local nameservers of each link.
	linkDNS map[int][]netip.Addr
	carried map[int]bool
	notes   []string
	// addrs and routeList say what the rendered files set, for the user.
	addrs, routeList []string
}

// Plan turns the host's configuration into the files that recreate it.
// Notes say what was left out and why.
func Plan(h *Host) (files []File, notes []string, err error) {
	files, p, err := plan(h)
	if err != nil {
		return nil, nil, err
	}
	return files, p.notes, nil
}

func plan(h *Host) ([]File, *planner, error) {
	p := &planner{
		h: h, byIndex: map[int]*Link{}, members: map[int][]int{}, uppers: map[int][]int{},
		routes: map[int][]Route{}, carried: map[int]bool{}, linkDNS: map[int][]netip.Addr{},
	}
	for i := range h.Links {
		l := &h.Links[i]
		p.byIndex[l.Index] = l
	}
	for i := range h.Links {
		l := &h.Links[i]
		if l.Master != 0 {
			p.members[l.Master] = append(p.members[l.Master], l.Index)
		}
		if l.Parent != 0 {
			p.uppers[l.Parent] = append(p.uppers[l.Parent], l.Index)
		}
	}
	if err := p.checkPorts(); err != nil {
		return nil, nil, err
	}
	if err := p.selectLinks(); err != nil {
		return nil, nil, err
	}
	if err := p.sortRoutes(); err != nil {
		return nil, nil, err
	}
	p.sortDNS()
	if h.ExtraRules > 0 {
		p.notef("%d policy routing rules are not carried", h.ExtraRules)
	}
	files, err := p.render()
	if err != nil {
		return nil, nil, err
	}
	return files, p, nil
}

func (p *planner) notef(format string, args ...any) {
	p.notes = append(p.notes, fmt.Sprintf(format, args...))
}

func nicLike(l *Link) bool { return l.Kind == "" && l.Type != arphrdLoopback }

// checkPorts refuses a link enslaved to anything but a bond or a bridge
// when a NIC is at or under it, even without addresses of its own: the
// address then sits on a device this tool cannot recreate, and leaving the
// NIC to DHCP would half-carry it. A port of a NIC is a virtual function its
// driver pairs with it, as on Azure, and is left to that driver.
func (p *planner) checkPorts() error {
	for i := range p.h.Links {
		l := &p.h.Links[i]
		if l.Master == 0 {
			continue
		}
		m := p.byIndex[l.Master]
		switch {
		case m != nil && (m.Kind == "bond" || m.Kind == "bridge"):
		case m != nil && nicLike(m):
			p.notef("%s is a port of the NIC %s, which its driver pairs with it, so it is not carried", l.Name, m.Name)
		case !p.reachesNIC(l.Index, map[int]bool{}):
		case m == nil:
			return unsupported("%s is a port of an unknown device %d", l.Name, l.Master)
		default:
			return unsupported("%s is a port of %s (%s), which this tool does not carry", l.Name, m.Name, m.Kind)
		}
	}
	return nil
}

func hasGlobal(l *Link) bool {
	return slices.ContainsFunc(l.Addrs, func(a Addr) bool { return a.Global })
}

// candidate is a route set up by hand or by a network configuration tool,
// which is what is carried.
func candidate(r *Route) bool {
	return (r.Proto == protoBoot || r.Proto == protoStatic) && r.Table == tableMain && r.Type == rtnUnicast &&
		len(r.Hops) == 0 && r.NextHopID == 0
}

func (p *planner) reachesNIC(idx int, seen map[int]bool) bool {
	l := p.byIndex[idx]
	if l == nil || seen[idx] {
		return false
	}
	seen[idx] = true
	if nicLike(l) {
		return true
	}
	if l.Parent != 0 && p.reachesNIC(l.Parent, seen) {
		return true
	}
	return slices.ContainsFunc(p.members[idx], func(m int) bool { return p.reachesNIC(m, seen) })
}

// selectLinks picks every link that has an address or a route to carry,
// with what it is built on, down to the NICs. A link with no NIC under it,
// such as a container bridge or a tunnel, does not exist on the installed
// system and is left out.
func (p *planner) selectLinks() error {
	routed := map[int]bool{}
	for i := range p.h.Routes {
		if r := &p.h.Routes[i]; candidate(r) {
			routed[r.Link] = true
		}
	}
	for i := range p.h.Links {
		l := &p.h.Links[i]
		if !hasGlobal(l) && !routed[l.Index] {
			continue
		}
		if !p.reachesNIC(l.Index, map[int]bool{}) {
			p.notef("%s (%s) has no NIC under it, so it is not carried", l.Name, l.Kind)
			continue
		}
		if err := p.carry(l.Index); err != nil {
			return err
		}
	}
	return nil
}

func (p *planner) carry(idx int) error {
	if p.carried[idx] {
		return nil
	}
	l := p.byIndex[idx]
	p.carried[idx] = true
	switch {
	case nicLike(l):
		switch {
		case l.Wireless:
			return unsupported("%s is a wireless NIC, which the installed system does not bring up", l.Name)
		case l.Type != arphrdEther:
			return unsupported("%s is not an Ethernet NIC (hardware type %d)", l.Name, l.Type)
		case len(l.MAC) == 0 && len(l.PermMAC) == 0:
			return unsupported("%s has no MAC address to find it by after the reboot", l.Name)
		}
		return nil
	case l.Kind == "vlan":
		return p.carry(l.Parent)
	case l.Kind == "bond" || l.Kind == "bridge":
		for _, m := range p.members[idx] {
			if !p.reachesNIC(m, map[int]bool{}) {
				p.notef("%s (%s), a port of %s, has no NIC under it, so it is not carried", p.byIndex[m].Name, p.byIndex[m].Kind, l.Name)
				continue
			}
			if err := p.carry(m); err != nil {
				return err
			}
		}
		return nil
	}
	return unsupported("%s is a %s device, which this tool does not carry", l.Name, l.Kind)
}

func dst(r *Route) string {
	if r.Dst.Bits() == 0 {
		return "default"
	}
	return r.Dst.String()
}

func (p *planner) sortRoutes() error {
	for i := range p.h.Routes {
		r := &p.h.Routes[i]
		touches := p.carried[r.Link] || slices.ContainsFunc(r.Hops, func(h int) bool { return p.carried[h] })
		// A route over a nexthop object names no link; it may use any.
		reach := touches || r.Link == 0 && r.NextHopID != 0
		daemon := r.Proto != protoBoot && r.Proto != protoStatic
		switch {
		case r.Table != tableMain && !touches:
		case r.Proto == protoRedirect || r.Proto == protoKernel || r.Proto == protoRA || r.Proto == protoDHCP:
		case daemon && reach && r.Table == tableMain && r.Type == rtnUnicast && r.Dst.Bits() == 0:
			// Without it the host is reachable from its own subnets only.
			return unsupported("the default route comes from a routing daemon (protocol %d), which the installed system does not run; "+
				"configure the network in the cloud-config", r.Proto)
		case daemon && reach:
			p.notef("route %s from protocol %d, a routing daemon, is not carried", dst(r), r.Proto)
		case r.NextHopID != 0 && (touches || r.Link == 0):
			return unsupported("route %s uses nexthop object %d, which this tool does not carry", dst(r), r.NextHopID)
		case len(r.Hops) > 0 && touches:
			return unsupported("route %s is a multipath route, which this tool does not carry", dst(r))
		case r.Type != rtnUnicast:
			p.notef("route %s of type %d is not carried", dst(r), r.Type)
		case !touches:
		case r.Table != tableMain:
			p.notef("route %s in table %d is not carried", dst(r), r.Table)
		case r.Proto == protoBoot && r.Gw.Is4() && p.leasedGateway(r):
			p.notef("route %s via %s came with a DHCP lease, which sets it again", dst(r), r.Gw)
		default:
			if r.OtherMetrics > 0 {
				p.notef("route %s: metrics other than the MTU are not carried", dst(r))
			}
			p.routes[r.Link] = append(p.routes[r.Link], *r)
		}
	}
	return nil
}

// leasedGateway tells a route a DHCP client installed: dhclient-script and
// udhcpc add the lease's gateway as proto boot, the protocol of a route
// added by hand.
func (p *planner) leasedGateway(r *Route) bool {
	l := p.byIndex[r.Link]
	return l != nil && (l.DHCPClient || slices.Contains(l.LeaseGateways, r.Gw))
}

func (p *planner) render() ([]File, error) {
	var files []File
	macs := map[string]string{}
	for i := range p.h.Links {
		l := &p.h.Links[i]
		if !p.carried[l.Index] {
			continue
		}
		if !nicLike(l) {
			nd, err := p.netdev(l)
			if err != nil {
				return nil, err
			}
			files = append(files, File{filePrefix + l.Name + ".netdev", nd})
		}
		nw, err := p.network(l)
		if err != nil {
			return nil, err
		}
		if nw == "" {
			for _, a := range p.linkDNS[l.Index] {
				p.notef("nameserver %s on %s is not carried, as its link is left to DHCP or SLAAC", a, l.Name)
			}
			p.notef("%s gets its addresses from DHCP or SLAAC only, which Kairos configures by default", l.Name)
			continue
		}
		name := l.Name
		if nicLike(l) {
			mac := matchMAC(l).String()
			if other, dup := macs[mac]; dup {
				return nil, unsupported("%s and %s share the MAC address %s, by which they are found after the reboot", other, l.Name, mac)
			}
			macs[mac] = l.Name
			name = strings.ReplaceAll(mac, ":", "")
		}
		files = append(files, File{filePrefix + name + ".network", nw})
	}
	if len(files) > 0 {
		if r := p.resolved(); r != "" {
			files = append(files, File{resolvedConf, r})
		}
	} else if len(p.h.DNS) > 0 || len(p.h.Search) > 0 {
		p.notef("nameservers %v and search domains %v are not carried, as no interface is; DHCP brings its own", p.h.DNS, p.h.Search)
	}
	return files, nil
}

func matchMAC(l *Link) net.HardwareAddr {
	if known(l.PermMAC) {
		return l.PermMAC
	}
	return l.MAC
}

func known(mac net.HardwareAddr) bool {
	return slices.ContainsFunc(mac, func(b byte) bool { return b != 0 })
}

func (p *planner) netdev(l *Link) (string, error) {
	var section string
	var lines []string
	var err error
	switch l.Kind {
	case "bond":
		section = "Bond"
		lines, err = bondSettings(l)
	case "bridge":
		section = "Bridge"
		lines, err = bridgeSettings(l)
	case "vlan":
		section = "VLAN"
		lines, err = vlanSettings(l)
	}
	if err != nil {
		return "", err
	}
	// networkd would otherwise make up a MAC address, and the network would
	// see a new machine.
	return sections(
		[]string{"[NetDev]", "Name=" + l.Name, "Kind=" + l.Kind, "MACAddress=" + l.MAC.String()},
		append([]string{"[" + section + "]"}, lines...),
	), nil
}

// matchLink returns the [Match] section of l and what its [Link] section
// must set before the MTU.
func (p *planner) matchLink(l, master *Link) (match, link []string, err error) {
	if !nicLike(l) {
		return []string{"[Match]", "Name=" + l.Name}, nil, nil
	}
	key := "MACAddress="
	if known(l.PermMAC) {
		key = "PermanentMACAddress="
	}
	match = []string{"[Match]", key + matchMAC(l).String(), "Type=ether"}
	// A bond sets its own MAC address on its ports.
	if known(l.PermMAC) && !slices.Equal(l.MAC, l.PermMAC) && (master == nil || master.Kind != "bond") {
		link = append(link, "MACAddress="+l.MAC.String())
	}
	// A port of a NIC, such as a VF its driver pairs with it, has its MAC
	// address: only the driver tells them apart. The error comes with link,
	// as it only matters when a file is written.
	ports := false
	for _, m := range p.members[l.Index] {
		if port := p.byIndex[m]; nicLike(port) {
			if l.Driver == "" || port.Driver == l.Driver {
				return nil, link, unsupported("%s cannot be told apart from its port %s: they share a MAC address, and their drivers do not tell them apart", l.Name, port.Name)
			}
			ports = true
		}
	}
	if ports {
		match = append(match, "Driver="+l.Driver)
	}
	return match, link, nil
}

// network renders the .network file of a carried link, or nothing for a
// stand-alone NIC that Kairos's own DHCP configuration already covers.
func (p *planner) network(l *Link) (string, error) {
	master := p.byIndex[l.Master]
	var network, extra []string
	match, link, matchErr := p.matchLink(l, master)
	link = append(link, "MTUBytes="+strconv.FormatUint(uint64(l.MTU), 10))
	static := slices.ContainsFunc(l.Addrs, func(a Addr) bool { return a.Global && !a.Dynamic })
	if nicLike(l) && master == nil && len(link) == 1 && l.MTU == defaultMTU && !static && len(p.routes[l.Index]) == 0 &&
		!slices.ContainsFunc(p.uppers[l.Index], func(u int) bool { return p.carried[u] }) {
		return "", nil
	}
	if matchErr != nil {
		return "", matchErr
	}
	dhcp := slices.ContainsFunc(l.Addrs, func(a Addr) bool { return a.Global && a.Dynamic && a.Prefix.Addr().Is4() })
	if dhcp {
		network = append(network, "DHCP=ipv4")
	}
	if master != nil {
		port, err := p.portSettings(l, master)
		if err != nil {
			return "", err
		}
		network = append(network, port.network...)
		extra = append(extra, port.extra...)
	}
	for _, u := range p.uppers[l.Index] {
		if p.carried[u] {
			network = append(network, "VLAN="+p.byIndex[u].Name)
		}
	}
	for _, a := range p.linkDNS[l.Index] {
		network = append(network, "DNS="+a.String())
	}
	if dhcp {
		extra = append(extra, sections([]string{"[DHCPv4]", "ClientIdentifier=mac"}))
	}
	for i := range l.Addrs {
		if a := &l.Addrs[i]; a.Global && !a.Dynamic {
			extra = append(extra, p.address(l, a))
			p.addrs = append(p.addrs, l.Name+" "+a.Prefix.String())
		}
	}
	for i := range p.routes[l.Index] {
		r := &p.routes[l.Index][i]
		extra = append(extra, routeSection(r))
		p.routeList = append(p.routeList, routeSummary(l.Name, r))
	}
	return sections(append([]string{}, match...), append([]string{"[Link]"}, link...), append([]string{"[Network]"}, network...)) +
		strings.Join(prefixEach(extra), ""), nil
}

type portConfig struct{ network, extra []string }

func (p *planner) portSettings(l, master *Link) (portConfig, error) {
	var c portConfig
	switch master.Kind {
	case "bond":
		if err := bondSlaveSettings(l); err != nil {
			return c, err
		}
		c.network = append(c.network, "Bond="+master.Name)
		if v, ok := uintOf(master.Info[bondPrimary], false); ok && int(v) == l.Index {
			c.network = append(c.network, "PrimarySlave=yes")
		}
	case "bridge":
		stp, _ := uintOf(master.Info[bridgeSTP], false)
		lines, err := bridgePortSettings(l, stp != 0)
		if err != nil {
			return c, err
		}
		c.network = append(c.network, "Bridge="+master.Name)
		if len(lines) > 0 {
			c.extra = append(c.extra, sections(append([]string{"[Bridge]"}, lines...)))
		}
	}
	return c, nil
}

// prefixEach separates each extra section from the one before it.
func prefixEach(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = "\n" + s
	}
	return out
}

func sections(ss ...[]string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = strings.Join(s, "\n") + "\n"
	}
	return strings.Join(parts, "\n")
}

func (p *planner) address(l *Link, a *Addr) string {
	lines := []string{"[Address]", "Address=" + a.Prefix.String()}
	if a.Peer.IsValid() {
		lines = append(lines, "Peer="+a.Peer.String())
	}
	if a.Label != "" && a.Label != l.Name {
		lines = append(lines, "Label="+a.Label)
	}
	if a.NoPrefixRoute {
		// NetworkManager adds the prefix route itself, with a metric of its
		// own; without it the gateway is unreachable.
		if r := p.prefixRoute(l, a); r == nil {
			lines = append(lines, "AddPrefixRoute=no")
		} else if r.Metric != 0 {
			lines = append(lines, "RouteMetric="+strconv.FormatUint(uint64(r.Metric), 10))
		}
	}
	return sections(lines)
}

func (p *planner) prefixRoute(l *Link, a *Addr) *Route {
	for i := range p.h.Routes {
		r := &p.h.Routes[i]
		if r.Link == l.Index && r.Dst == a.Prefix.Masked() && r.Table == tableMain && r.Type == rtnUnicast && !r.Gw.IsValid() {
			return r
		}
	}
	return nil
}

func routeSummary(link string, r *Route) string {
	s := link + " " + dst(r)
	if r.From.IsValid() {
		s += " from " + r.From.String()
	}
	if r.Gw.IsValid() {
		s += " via " + r.Gw.String()
	}
	return s
}

func routeSection(r *Route) string {
	lines := []string{"[Route]"}
	if r.Dst.Bits() != 0 {
		lines = append(lines, "Destination="+r.Dst.String())
	}
	if r.From.IsValid() {
		lines = append(lines, "Source="+r.From.String())
	}
	if r.Gw.IsValid() {
		lines = append(lines, "Gateway="+r.Gw.String())
	}
	if r.OnLink {
		lines = append(lines, "GatewayOnLink=yes")
	}
	lines = append(lines, "Metric="+strconv.FormatUint(uint64(r.Metric), 10))
	switch r.Scope {
	case scopeLink:
		lines = append(lines, "Scope=link")
	case scopeHost:
		lines = append(lines, "Scope=host")
	case scopeSite:
		lines = append(lines, "Scope=site")
	}
	if r.Src.IsValid() {
		lines = append(lines, "PreferredSource="+r.Src.String())
	}
	if r.MTU > 0 {
		lines = append(lines, "MTUBytes="+strconv.FormatUint(uint64(r.MTU), 10))
	}
	return sections(lines)
}

// sortDNS moves each link-local nameserver to the link its zone names, by
// the old system's interface name or index, neither of which needs to hold on
// the installed system.
func (p *planner) sortDNS() {
	for _, a := range p.h.DNS {
		if !linkLocal6(a) {
			continue
		}
		idx := slices.IndexFunc(p.h.Links, func(l Link) bool { return l.Name == a.Zone() || strconv.Itoa(l.Index) == a.Zone() })
		switch {
		case a.Zone() == "":
			p.notef("nameserver %s is link-local and names no interface, so it is not carried", a)
		case idx < 0 || !p.carried[p.h.Links[idx].Index]:
			p.notef("nameserver %s is not carried, as its interface is not", a)
		default:
			l, a := p.h.Links[idx].Index, a.WithZone("")
			if !slices.Contains(p.linkDNS[l], a) {
				p.linkDNS[l] = append(p.linkDNS[l], a)
			}
		}
	}
}

// linkLocal6 tells an IPv6 link-local address. An IPv4 one is left alone:
// clouds route theirs, such as AWS's resolver at 169.254.169.253, through
// any interface.
func linkLocal6(a netip.Addr) bool { return a.Is6() && a.IsLinkLocalUnicast() }

func (p *planner) resolved() string {
	var servers []string
	for _, a := range p.h.DNS {
		if linkLocal6(a) {
			continue
		}
		if a.IsLoopback() {
			p.notef("nameserver %s is local to this system and is not carried", a)
			continue
		}
		servers = append(servers, a.String())
	}
	var lines []string
	if len(servers) > 0 {
		lines = append(lines, "DNS="+strings.Join(servers, " "))
	}
	if len(p.h.Search) > 0 {
		lines = append(lines, "Domains="+strings.Join(p.h.Search, " "))
	}
	if len(lines) == 0 {
		return ""
	}
	return sections(append([]string{"[Resolve]"}, lines...))
}

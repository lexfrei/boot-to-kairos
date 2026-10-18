// Package netcfg carries the host's network configuration into the
// installed Kairos system, so that a machine reachable only at a static
// address, or only through a bond, VLAN or bridge, comes back on the network
// after the reboot.
//
// Kairos runs systemd-networkd and writes its default DHCP configuration from
// a yip stage on every boot, because /etc is not persistent. The carried
// configuration is therefore a yip stage too, added to the cloud-config that
// kairos-agent stores on the OEM partition, which outlives upgrades.
package netcfg

import (
	"net"
	"net/netip"
)

// Attrs are netlink attributes by type, values as the kernel sent them.
type Attrs map[uint16][]byte

// Link is a network interface as the kernel reports it.
type Link struct {
	Index int
	Name  string
	// Kind is IFLA_INFO_KIND: empty for a NIC driven by hardware.
	Kind string
	// Type is the ARPHRD_* hardware type.
	Type uint16
	MAC  net.HardwareAddr
	// PermMAC is the address burnt into the NIC, empty if the kernel does
	// not know it.
	PermMAC net.HardwareAddr
	MTU     uint32
	// Master is the bond or bridge this link is a port of, 0 if none.
	Master int
	// Parent is the link a VLAN sits on, 0 if none or in another namespace.
	Parent   int
	Wireless bool
	// Driver is the kernel driver of a NIC.
	Driver    string
	Info      Attrs
	SlaveKind string
	SlaveInfo Attrs
	Addrs     []Addr
	// LeaseGateways are the routers of the DHCP leases its addresses came
	// from.
	LeaseGateways []netip.Addr
	// DHCPClient is set when a DHCP client runs for the link and no lease
	// says which of its addresses and gateways the client set.
	DHCPClient bool
}

// Addr is an address on a link.
type Addr struct {
	Prefix netip.Prefix
	// Peer is the other end of a point-to-point address.
	Peer netip.Prefix
	// Dynamic addresses have a lifetime, are owned by a DHCP client, or
	// came from a router advertisement.
	Dynamic       bool
	Global        bool
	Label         string
	NoPrefixRoute bool
	// TempTemplate is IFA_F_MANAGETEMPADDR: temporary addresses (RFC 8981)
	// are made from this one.
	TempTemplate bool
}

// Route is a route from the kernel's routing tables.
type Route struct {
	Dst netip.Prefix
	// From is the source prefix of a source-specific route.
	From   netip.Prefix
	Gw     netip.Addr
	Src    netip.Addr
	Link   int
	Metric uint32
	Proto  uint8
	Type   uint8
	Scope  uint8
	Table  uint32
	OnLink bool
	// Hops are the links of a multipath route.
	Hops []int
	// NextHopID is set when the route uses a nexthop object.
	NextHopID uint32
	MTU       uint32
	// OtherMetrics counts RTAX_* metrics other than the MTU.
	OtherMetrics int
}

// Host is everything carried over, or examined to refuse.
type Host struct {
	Links  []Link
	Routes []Route
	// ExtraRules counts policy routing rules beyond the kernel's own.
	ExtraRules int
	DNS        []netip.Addr
	Search     []string
}

// File is a file written into the installed system at every boot.
type File struct {
	Path    string
	Content string
}

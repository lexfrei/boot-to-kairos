package netcfg

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
)

// param maps one kernel attribute of a bond, bridge or port onto
// systemd-networkd. Every attribute the kernel reports must be known: one
// at its kernel default is left out, as networkd then leaves the kernel
// default too; any other value is written, or refused when networkd has no
// key for it, so nothing is dropped in silence.
type param struct {
	name string
	// key is the networkd setting, empty if networkd has none.
	key string
	def uint64
	// format renders a value for key; false if networkd cannot express it.
	format func(uint64) (string, bool)
	// always writes the value even at its default, where networkd's own
	// default would differ or the value matters to whoever reads the file.
	always bool
	// state is runtime state, not configuration.
	state     bool
	bigEndian bool
}

func enum(names ...string) func(uint64) (string, bool) {
	return func(v uint64) (string, bool) {
		if v >= uint64(len(names)) {
			return "", false
		}
		return names[v], true
	}
}

func ms(v uint64) (string, bool) { return strconv.FormatUint(v, 10) + "ms", true }

func sec(v uint64) (string, bool) { return strconv.FormatUint(v, 10) + "s", true }

// centisec renders the kernel's USER_HZ clock ticks, in which bridge timers
// are reported.
func centisec(v uint64) (string, bool) { return strconv.FormatUint(v*10, 10) + "ms", true }

func vlanProto(v uint64) (string, bool) {
	switch v {
	case ethP8021Q:
		return "802.1q", true
	case ethP8021AD:
		return "802.1ad", true
	}
	return "", false
}

func num(v uint64) (string, bool) { return strconv.FormatUint(v, 10), true }

func boolean(v uint64) (string, bool) {
	switch v {
	case 0:
		return "no", true
	case 1:
		return "yes", true
	}
	return "", false
}

func inverted(v uint64) (string, bool) {
	switch v {
	case 0:
		return "yes", true
	case 1:
		return "no", true
	}
	return "", false
}

func state(name string) param { return param{name: name, state: true} }

func fixed(name string, def uint64) param { return param{name: name, def: def} }

// The tables follow enum IFLA_BOND_*, IFLA_BR_*, IFLA_BRPORT_* and
// IFLA_BOND_SLAVE_* in include/uapi/linux/if_link.h; the networkd keys and
// values follow systemd's netdev-gperf.gperf, networkd-network-gperf.gperf
// and bond-util.c.
var bondParams = map[uint16]param{ //nolint:gochecknoglobals // fixed table
	bondMode:        {name: "mode", key: "Mode", format: enum("balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"), always: true},
	bondActiveSlave: state("active_slave"),
	bondMIIMon:      {name: "miimon", key: "MIIMonitorSec", format: ms, always: true},
	4:               {name: "updelay", key: "UpDelaySec", format: ms},
	5:               {name: "downdelay", key: "DownDelaySec", format: ms},
	6:               fixed("use_carrier", 1),
	7:               {name: "arp_interval", key: "ARPIntervalSec", format: ms},
	9:               {name: "arp_validate", key: "ARPValidate", format: enum("none", "active", "backup", "all")},
	10:              {name: "arp_all_targets", key: "ARPAllTargets", format: enum("any", "all")},
	bondPrimary:     state("primary"),
	12:              {name: "primary_reselect", key: "PrimaryReselectPolicy", format: enum("always", "better", "failure")},
	13:              {name: "fail_over_mac", key: "FailOverMACPolicy", format: enum("none", "active", "follow")},
	14:              {name: "xmit_hash_policy", key: "TransmitHashPolicy", format: enum("layer2", "layer3+4", "layer2+3", "encap2+3", "encap3+4")},
	15:              {name: "resend_igmp", key: "ResendIGMP", def: 1, format: num},
	16:              {name: "num_peer_notif", key: "GratuitousARP", def: 1, format: num},
	17:              {name: "all_slaves_active", key: "AllSlavesActive", format: boolean},
	18:              {name: "min_links", key: "MinLinks", format: num},
	19:              {name: "lp_interval", key: "LearnPacketIntervalSec", def: 1, format: sec},
	20:              {name: "packets_per_slave", key: "PacketsPerSlave", def: 1, format: num},
	21:              {name: "ad_lacp_rate", key: "LACPTransmitRate", format: enum("slow", "fast")},
	22:              {name: "ad_select", key: "AdSelect", format: enum("stable", "bandwidth", "count")},
	23:              state("ad_info"),
	24:              {name: "ad_actor_sys_prio", key: "AdActorSystemPriority", def: 65535, format: num},
	25:              {name: "ad_user_port_key", key: "AdUserPortKey", format: num},
	27:              {name: "tlb_dynamic_lb", key: "DynamicTransmitLoadBalancing", def: 1, format: boolean},
	28:              {name: "peer_notif_delay", key: "PeerNotifyDelaySec", format: ms},
	29:              fixed("ad_lacp_active", 1),
	30:              {name: "missed_max", key: "ARPMissedMax", def: 2, format: num},
	32:              fixed("coupled_control", 1),
	33:              fixed("broadcast_neigh", 0),
	34:              fixed("lacp_strict", 0),
}

const (
	bondActorSystem = 26
	bondNSTargets   = 31
)

var bondSlaveParams = map[uint16]param{ //nolint:gochecknoglobals // fixed table
	1: state("state"), 2: state("mii_status"), 3: state("link_failure_count"), bondSlavePermHWAddr: state("perm_hwaddr"),
	5: fixed("queue_id", 0), 6: state("ad_aggregator_id"), 7: state("ad_actor_oper_port_state"),
	8: state("ad_partner_oper_port_state"), 9: fixed("prio", 0), 10: fixed("actor_port_prio", 255),
}

const (
	bridgeSTP       = 5
	bridgeGroupAddr = 20
	bridgeBoolOpts  = 46
)

var bridgeParams = map[uint16]param{ //nolint:gochecknoglobals // fixed table
	1:         {name: "forward_delay", key: "ForwardDelaySec", def: 1500, format: centisec},
	2:         {name: "hello_time", key: "HelloTimeSec", def: 200, format: centisec},
	3:         {name: "max_age", key: "MaxAgeSec", def: 2000, format: centisec},
	4:         {name: "ageing_time", key: "AgeingTimeSec", def: 30000, format: centisec},
	bridgeSTP: {name: "stp_state", key: "STP", format: boolean, always: true},
	6:         {name: "priority", key: "Priority", def: 32768, format: num},
	// Port VLAN tables are not carried, so neither is filtering on them.
	7:  fixed("vlan_filtering", 0),
	8:  {name: "vlan_protocol", key: "VLANProtocol", def: ethP8021Q, bigEndian: true, format: vlanProto},
	9:  {name: "group_fwd_mask", key: "GroupForwardMask", format: num},
	10: state("root_id"), 11: state("bridge_id"), 12: state("root_port"), 13: state("root_path_cost"),
	14: state("topology_change"), 15: state("topology_change_detected"), 16: state("hello_timer"), 17: state("tcn_timer"),
	18: state("topology_change_timer"), 19: state("gc_timer"), 21: state("fdb_flush"),
	22: fixed("mcast_router", 1),
	23: {name: "mcast_snooping", key: "MulticastSnooping", def: 1, format: boolean},
	24: fixed("mcast_query_use_ifaddr", 0),
	25: {name: "mcast_querier", key: "MulticastQuerier", format: boolean},
	26: fixed("mcast_hash_elasticity", 16), 27: fixed("mcast_hash_max", 4096), 28: fixed("mcast_last_member_cnt", 2),
	29: fixed("mcast_startup_query_cnt", 2), 30: fixed("mcast_last_member_intvl", 100), 31: fixed("mcast_membership_intvl", 26000),
	32: fixed("mcast_querier_intvl", 25500), 33: fixed("mcast_query_intvl", 12500), 34: fixed("mcast_query_response_intvl", 1000),
	35: fixed("mcast_startup_query_intvl", 3125), 36: fixed("nf_call_iptables", 0), 37: fixed("nf_call_ip6tables", 0),
	38: fixed("nf_call_arptables", 0),
	39: {name: "vlan_default_pvid", key: "DefaultPVID", def: 1, format: num},
	40: state("pad"), 41: fixed("vlan_stats_enabled", 0), 42: fixed("mcast_stats_enabled", 0),
	43: {name: "mcast_igmp_version", key: "MulticastIGMPVersion", def: 2, format: num},
	44: fixed("mcast_mld_version", 1), 45: fixed("vlan_stats_per_port", 0),
	47: state("mcast_querier_state"), 48: state("fdb_n_learned"),
	49: {name: "fdb_max_learned", key: "FDBMaxLearned", format: num},
}

const bridgePortCost = 3

var bridgePortParams = map[uint16]param{ //nolint:gochecknoglobals // fixed table
	1: state("state"),
	2: {name: "priority", key: "Priority", def: 32, format: num},
	// The cost is derived from the link speed unless set; it only matters
	// to STP, and is written only then.
	bridgePortCost: state("cost"),
	4:              {name: "mode", key: "HairPin", format: boolean},
	5:              {name: "guard", key: "UseBPDU", format: inverted},
	6:              {name: "protect", key: "AllowPortToBeRoot", format: inverted},
	7:              {name: "fast_leave", key: "FastLeave", format: boolean},
	8:              {name: "learning", key: "Learning", def: 1, format: boolean},
	9:              {name: "unicast_flood", key: "UnicastFlood", def: 1, format: boolean},
	10:             {name: "proxyarp", key: "ProxyARP", format: boolean},
	11:             fixed("learning_sync", 0),
	12:             {name: "proxyarp_wifi", key: "ProxyARPWiFi", format: boolean},
	13:             state("root_id"), 14: state("bridge_id"), 15: state("designated_port"), 16: state("designated_cost"),
	17: state("id"), 18: state("no"), 19: state("topology_change_ack"), 20: state("config_pending"),
	21: state("message_age_timer"), 22: state("forward_delay_timer"), 23: state("hold_timer"), 24: state("flush"),
	25: {name: "multicast_router", key: "MulticastRouter", def: 1, format: enum("no", "query", "permanent", "temporary")},
	26: state("pad"),
	27: {name: "mcast_flood", key: "MulticastFlood", def: 1, format: boolean},
	28: {name: "mcast_to_ucast", key: "MulticastToUnicast", format: boolean},
	29: {name: "vlan_tunnel", key: "VLANTunnel", format: boolean},
	30: fixed("bcast_flood", 1), 31: fixed("group_fwd_mask", 0),
	32: {name: "neigh_suppress", key: "NeighborSuppression", format: boolean},
	33: {name: "isolated", key: "Isolated", format: boolean},
	34: fixed("backup_port", 0), 35: state("mrp_ring_open"), 36: state("mrp_in_open"),
	37: fixed("mcast_eht_hosts_limit", 512), 38: state("mcast_eht_hosts_cnt"),
	39: {name: "locked", key: "Locked", format: boolean},
	40: {name: "mab", key: "MACAuthenticationBypass", format: boolean},
	41: state("mcast_n_groups"), 42: fixed("mcast_max_groups", 0), 43: fixed("neigh_vlan_suppress", 0),
	44: fixed("backup_nhid", 0),
}

// unsupported is a refusal naming what cannot be carried.
func unsupported(format string, args ...any) error {
	return errors.Wrapf(ErrUnsupported, format, args...)
}

func uintOf(b []byte, bigEndian bool) (uint64, bool) {
	var order binary.ByteOrder = binary.NativeEndian
	if bigEndian {
		order = binary.BigEndian
	}
	switch len(b) {
	case 1:
		return uint64(b[0]), true
	case 2:
		return uint64(order.Uint16(b)), true
	case 4:
		return uint64(order.Uint32(b)), true
	case 8:
		return order.Uint64(b), true
	}
	return 0, false
}

func sortedIDs(a Attrs) []uint16 {
	ids := make([]uint16, 0, len(a))
	for id := range a {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// settings renders one attribute through its table; special handles the
// attributes that are not plain numbers, and reports whether it did.
func settings(link, what string, a Attrs, table map[uint16]param, special func(id uint16, v []byte) ([]string, bool, error)) ([]string, error) {
	var lines []string
	for _, id := range sortedIDs(a) {
		if special != nil {
			l, done, err := special(id, a[id])
			if err != nil {
				return nil, err
			}
			if done {
				lines = append(lines, l...)
				continue
			}
		}
		p, ok := table[id]
		if !ok {
			return nil, unsupported("%s: %s attribute %d is unknown to this tool", link, what, id)
		}
		if p.state {
			continue
		}
		v, ok := uintOf(a[id], p.bigEndian)
		if !ok {
			return nil, unsupported("%s: %s %s has an unexpected size", link, what, p.name)
		}
		if v == p.def && !p.always {
			continue
		}
		if p.key == "" {
			return nil, unsupported("%s: %s %s is %d, which systemd-networkd cannot set", link, what, p.name, v)
		}
		s, ok := p.format(v)
		if !ok {
			return nil, unsupported("%s: %s %s %d has no systemd-networkd equivalent", link, what, p.name, v)
		}
		lines = append(lines, p.key+"="+s)
	}
	return lines, nil
}

func nestedAttrs(b []byte) [][]byte {
	var out [][]byte
	for len(b) >= 4 {
		n := int(binary.NativeEndian.Uint16(b))
		if n < 4 || n > len(b) {
			break
		}
		out = append(out, b[4:n])
		next := (n + 3) &^ 3
		if next > len(b) {
			break
		}
		b = b[next:]
	}
	return out
}

func bondSettings(l *Link) ([]string, error) {
	return settings(l.Name, "bond", l.Info, bondParams, func(id uint16, v []byte) ([]string, bool, error) {
		switch id {
		case bondARPTargets:
			var ips []string
			for _, ip := range nestedAttrs(v) {
				a, ok := netip.AddrFromSlice(ip)
				if !ok {
					return nil, true, unsupported("%s: bond arp_ip_target has an unexpected size", l.Name)
				}
				ips = append(ips, a.String())
			}
			if len(ips) == 0 {
				return nil, true, nil
			}
			return []string{"ARPIPTargets=" + strings.Join(ips, " ")}, true, nil
		case bondActorSystem:
			if slices.ContainsFunc(v, func(b byte) bool { return b != 0 }) {
				return []string{"AdActorSystem=" + net.HardwareAddr(v).String()}, true, nil
			}
			return nil, true, nil
		case bondNSTargets:
			if len(nestedAttrs(v)) > 0 {
				return nil, true, unsupported("%s: bond ns_ip6_target is set, which systemd-networkd cannot set", l.Name)
			}
			return nil, true, nil
		}
		return nil, false, nil
	})
}

var defaultGroupAddr = net.HardwareAddr{0x01, 0x80, 0xc2, 0, 0, 0} //nolint:gochecknoglobals // constant

const boolOptNoLinkLocalLearn = 1

func bridgeSettings(l *Link) ([]string, error) {
	return settings(l.Name, "bridge", l.Info, bridgeParams, func(id uint16, v []byte) ([]string, bool, error) {
		switch id {
		case bridgeGroupAddr:
			if !slices.Equal(v, defaultGroupAddr) {
				return nil, true, unsupported("%s: bridge group_addr is %s, which systemd-networkd cannot set", l.Name, net.HardwareAddr(v))
			}
			return nil, true, nil
		case bridgeBoolOpts:
			// struct br_boolopt_multi: optval, then optmask.
			if len(v) < 4 {
				return nil, true, unsupported("%s: bridge multi_boolopt has an unexpected size", l.Name)
			}
			switch binary.NativeEndian.Uint32(v) {
			case 0:
				return nil, true, nil
			case boolOptNoLinkLocalLearn:
				return []string{"LinkLocalLearning=no"}, true, nil
			}
			return nil, true, unsupported("%s: bridge multi_boolopt %#x has options systemd-networkd cannot set", l.Name, binary.NativeEndian.Uint32(v))
		}
		return nil, false, nil
	})
}

func bridgePortSettings(l *Link, stp bool) ([]string, error) {
	return settings(l.Name, "bridge port", l.SlaveInfo, bridgePortParams, func(id uint16, v []byte) ([]string, bool, error) {
		if id != bridgePortCost {
			return nil, false, nil
		}
		c, ok := uintOf(v, false)
		if !stp || !ok {
			return nil, true, nil
		}
		return []string{"Cost=" + strconv.FormatUint(c, 10)}, true, nil
	})
}

func bondSlaveSettings(l *Link) error {
	_, err := settings(l.Name, "bond port", l.SlaveInfo, bondSlaveParams, nil)
	return err
}

const (
	vlanID         = 1
	vlanFlags      = 2
	vlanEgressQoS  = 3
	vlanIngressQoS = 4
	vlanProtocol   = 5

	ethP8021Q  = 0x8100
	ethP8021AD = 0x88a8
)

func vlanSettings(l *Link) ([]string, error) {
	var id, proto []string
	flags := uint32(vlanReorderHdr)
	for _, a := range sortedIDs(l.Info) {
		v := l.Info[a]
		switch a {
		case vlanID:
			n, ok := uintOf(v, false)
			if !ok {
				return nil, unsupported("%s: vlan id has an unexpected size", l.Name)
			}
			id = []string{fmt.Sprintf("Id=%d", n)}
		case vlanFlags:
			if len(v) < 4 {
				return nil, unsupported("%s: vlan flags have an unexpected size", l.Name)
			}
			flags = binary.NativeEndian.Uint32(v)
		case vlanEgressQoS, vlanIngressQoS:
			if len(nestedAttrs(v)) > 0 {
				return nil, unsupported("%s: vlan egress_qos or ingress_qos maps are set, which this tool does not carry", l.Name)
			}
		case vlanProtocol:
			switch p, _ := uintOf(v, true); p {
			case ethP8021Q:
			case ethP8021AD:
				proto = []string{"Protocol=802.1ad"}
			default:
				return nil, unsupported("%s: vlan protocol %#x has no systemd-networkd equivalent", l.Name, p)
			}
		default:
			return nil, unsupported("%s: vlan attribute %d is unknown to this tool", l.Name, a)
		}
	}
	if id == nil {
		return nil, unsupported("%s: the kernel did not report the VLAN id", l.Name)
	}
	lines := slices.Concat(id, proto)
	if flags&vlanReorderHdr == 0 {
		lines = append(lines, "ReorderHeader=no")
	}
	for _, f := range []struct {
		bit uint32
		key string
	}{{vlanGVRP, "GVRP"}, {vlanLooseBinding, "LooseBinding"}, {vlanMVRP, "MVRP"}} {
		if flags&f.bit != 0 {
			lines = append(lines, f.key+"=yes")
		}
	}
	if rest := flags &^ (vlanReorderHdr | vlanGVRP | vlanLooseBinding | vlanMVRP); rest != 0 {
		return nil, unsupported("%s: vlan flags %#x have no systemd-networkd equivalent", l.Name, rest)
	}
	return lines, nil
}

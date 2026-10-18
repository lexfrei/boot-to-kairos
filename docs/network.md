# Network

Kairos brings every Ethernet NIC up with DHCP by default. A machine reachable only at a static address, or only through a bond, a VLAN or a bridge, would not come back after the reboot. So the running system's network configuration is carried over, unless you pass `--keep-network=false` or the [cloud-config configures the network](#when-the-cloud-config-configures-the-network).

The configuration is read from the kernel, not from configuration files. That covers addresses, routes, MTUs, bonds, VLANs and bridges. Nameservers and search domains come from `/etc/resolv.conf`, or from `/run/systemd/resolve/resolv.conf` behind systemd-resolved's local stub. A cloud-config stage writes systemd-networkd files on every boot, as Kairos does with its own default, so the configuration survives upgrades. NICs are found by their burnt-in MAC address, so Kairos naming them differently does not matter.

## What is carried

Addresses:

- An address without a lifetime is written as static, unless a DHCP client owns it.
- An address with a lifetime came from DHCP or SLAAC. So did an IPv4 address that a lease records. That is networkd's lease in `/run/systemd/netif/leases`, or an unexpired NetworkManager, dhclient or dhcpcd lease under `/var/lib` for that address, while a DHCP client is running.
- A dhclient, dhcpcd or udhcpc running for a NIC with no lease to read owns all of the NIC's IPv4 addresses.
- A NIC with a lease keeps DHCP for IPv4, and router advertisements still configure IPv6.
- A client started without naming the NIC and without a lease file is not detected. Its addresses are written as static.

Routes:

- Routes set up by the system's network configuration (`proto boot` and `proto static`) in the main table are carried. Source-specific ones keep their source.
- On the carried interfaces, routes from a routing daemon, routes in other tables and routes of types other than unicast are not carried, and the installer names them. Policy routing rules are not carried either.
- A prefix route that NetworkManager installs beside its addresses comes back with its metric.
- A `proto boot` route through the gateway of a DHCP lease is left to DHCP. dhclient-script and udhcpc install such routes.
- Where a DHCP client runs for an interface with no lease to read, every `proto boot` IPv4 route through a gateway on it is left to DHCP too, hand-added ones included.

Interfaces:

- A NIC that only uses DHCP, at the default MTU, outside any bond, VLAN or bridge, is left to Kairos's default configuration.
- Bonds, VLANs and bridges are recreated with their MAC addresses and with every parameter that differs from the kernel's default.
- Interfaces with no NIC under them, such as container bridges, VPN tunnels or a bridge's tap ports, are left out.
- A virtual function its driver pairs with a NIC, as on Azure, is left to that driver. The NIC's file matches the driver as well as the MAC address the two share.

## Refusals

These setups are refused with `network-unsupported` before anything is written, and the error names the cause:

- a default route from a routing daemon, since without the daemon the installed system would be reachable from its own subnets only (configure such a host's network in the cloud-config);
- a bond, VLAN or bridge parameter that systemd-networkd cannot set;
- team devices, Open vSwitch, VRFs, macvlan, ipvlan, other tunnel devices bound to a NIC, Wi-Fi and non-Ethernet NICs, when a NIC is at or under them;
- multipath routes, and routes over nexthop objects, that the network configuration set up;
- bridges with VLAN filtering, and VLAN priority maps;
- two NICs with the same MAC address;
- a virtual function whose driver does not tell it apart from its NIC, as with virtio's net_failover.

## When the cloud-config configures the network

The cloud-config can take over the network. Then nothing is carried, and its configuration applies alone. That happens when it writes files under `/etc/systemd/network/`, `/run/systemd/network/`, `/etc/systemd/resolved.conf*` or `/etc/resolv.conf`, sets `dns` in a stage, or passes `ip=` in `install.grub_options`. What a stage's `commands` do is not checked.

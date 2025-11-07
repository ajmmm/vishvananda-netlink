package netlink

import (
	"fmt"
	"net"
	"net/netip"
)

// NetIPToNetAddr converts net.IP to a netip.Addr
func NetIPToNetAddr(ip net.IP) (netip.Addr, error) {
	if ip == nil {
		return netip.Addr{}, fmt.Errorf("ip is nil")
	}

	// The net.IP type doesn't reliably let us differentiate between pure
	// IPv4 and IPv6-mapped IPv4, because the underlying representation is
	// likely 16 bytes. This is the case when using net.IPv4() for example.
	//
	// So, we first try do an IPv4 conversion. Things to note:
	//
	//	1. If this is a pure IPv4 address, it will just return ip.
	//
	//	2. If this is an IPv6-mapped address, it will return the last
	//	   4 bytes. In effect, this converts and we'll lose real IPv6
	//	   mapping here.
	//
	//	3. If this is a pure IPv6 address, the v4 conversion will return
	// 	   nil, meaning we can just call AddrFromSlice() safely.

	if v4 := ip.To4(); v4 != nil {
		addr, ok := netip.AddrFromSlice(v4)
		if !ok {
			return netip.Addr{}, fmt.Errorf("invalid IPv4 address")
		}
		return addr, nil
	}

	// If we get here, we're on a pure IPv6 address.

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid IPv6 address")
	}
	return addr, nil
}

// NetAddrToNetIP converts netip.Addr to net.IP
func NetAddrToNetIP(addr netip.Addr) (net.IP, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("invalid addr")
	}
	return net.IP(addr.AsSlice()), nil
}

// NetIPNetToNetPrefix converts net.IPNet to netip.Prefix
func NetIPNetToNetPrefix(ipnet *net.IPNet) (netip.Prefix, error) {
	if ipnet == nil {
		return netip.Prefix{}, fmt.Errorf("ipnet is nil")
	}

	ones, bits := ipnet.Mask.Size()
	addr, err := NetIPToNetAddr(ipnet.IP)
	if (ones == 0 && bits == 0) || err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP Network")
	}

	return netip.PrefixFrom(addr, bits), nil
}

// NetPrefixToNetIP converts netip.Prefix to net.IPNet
func NetPrefixToNetIP(prefix netip.Prefix) (*net.IPNet, error) {
	if !prefix.IsValid() {
		return nil, fmt.Errorf("invalid prefix")
	}

	masked := prefix.Masked()
	maskedBytes := masked.Addr().AsSlice()
	ipnet := &net.IPNet{
		IP:   net.IP(maskedBytes),
		Mask: net.CIDRMask(masked.Bits(), 8*len(maskedBytes)),
	}

	return ipnet, nil
}

// NetPrefixFrom converts raw bytes and a bit length into a netip.Prefix
func NetPrefixFrom(slice []byte, bits int) (netip.Prefix, error) {
	addr, ok := netip.AddrFromSlice(slice)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid slice")
	}

	return netip.PrefixFrom(addr, bits), nil
}

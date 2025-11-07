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

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid IP")
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
	addr, ok := netip.AddrFromSlice(ipnet.IP)
	if (ones == 0 && bits == 0) || !ok {
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

package http_utils

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// ParseCIDRs parses CIDR blocks. A bare IP address is accepted and treated as
// a single-host network.
func ParseCIDRs(values []string) ([]net.IPNet, error) {
	nets := make([]net.IPNet, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(value); err == nil {
			nets = append(nets, *network)
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP or CIDR %q", raw)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

// IPInNets reports whether ip belongs to any of the networks.
func IPInNets(ip net.IP, nets []net.IPNet) bool {
	if ip == nil {
		return false
	}
	for i := range nets {
		if nets[i].Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the client address of r as a string. The direct peer
// (RemoteAddr) is used unless it is one of the trusted proxies; then the
// right-most X-Forwarded-For hop that is not itself trusted is returned, and
// X-Real-IP is consulted when every hop is trusted. Forwarded headers from an
// untrusted peer are ignored because any client can set them.
func ClientIP(r *http.Request, trusted []net.IPNet) string {
	remote := hostOnly(r.RemoteAddr)
	remoteIP := net.ParseIP(remote)
	if remoteIP == nil || len(trusted) == 0 || !IPInNets(remoteIP, trusted) {
		return remote
	}
	var hops []net.IP
	for _, header := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(header, ",") {
			if ip := net.ParseIP(hostOnly(strings.TrimSpace(part))); ip != nil {
				hops = append(hops, ip)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !IPInNets(hops[i], trusted) {
			return hops[i].String()
		}
	}
	if real := net.ParseIP(hostOnly(strings.TrimSpace(r.Header.Get("X-Real-IP")))); real != nil {
		return real.String()
	}
	return remote
}

// BucketIP returns ip unchanged for IPv4 and the enclosing prefixBits network
// for IPv6, so that clients rotating addresses inside one allocation share a
// budget. Unparsable input is returned unchanged.
func BucketIP(ip string, prefixBits int) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil || prefixBits <= 0 || prefixBits >= 128 {
		return ip
	}
	return parsed.Mask(net.CIDRMask(prefixBits, 128)).String() + "/" + strconv.Itoa(prefixBits)
}

// hostOnly strips a port and IPv6 brackets from a host:port or host string.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return strings.Trim(addr, "[]")
}

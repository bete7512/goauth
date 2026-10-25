package http_utils

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseCIDRs(t *testing.T) {
	nets, err := ParseCIDRs([]string{"10.0.0.0/8", " 192.0.2.7 ", "2001:db8::1", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 3 {
		t.Fatalf("parsed %d networks, want 3", len(nets))
	}
	if ones, _ := nets[1].Mask.Size(); ones != 32 {
		t.Fatalf("bare IPv4 mask = /%d, want /32", ones)
	}
	if ones, _ := nets[2].Mask.Size(); ones != 128 {
		t.Fatalf("bare IPv6 mask = /%d, want /128", ones)
	}
	if _, err := ParseCIDRs([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid entry")
	}
}

func TestClientIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.4:4321"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("X-Real-IP", "203.0.113.10")
	if got := ClientIP(r, nil); got != "198.51.100.4" {
		t.Fatalf("got %q, want remote address", got)
	}
	trusted, _ := ParseCIDRs([]string{"10.0.0.0/8"})
	if got := ClientIP(r, trusted); got != "198.51.100.4" {
		t.Fatalf("got %q, want remote address when peer is not trusted", got)
	}
}

func TestClientIPUsesRightmostUntrustedHop(t *testing.T) {
	trusted, _ := ParseCIDRs([]string{"10.0.0.0/8"})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:443"
	r.Header.Add("X-Forwarded-For", "1.1.1.1, 203.0.113.9")
	r.Header.Add("X-Forwarded-For", "10.9.9.9")
	if got := ClientIP(r, trusted); got != "203.0.113.9" {
		t.Fatalf("got %q, want 203.0.113.9", got)
	}
}

func TestClientIPFallsBackToRealIPThenRemote(t *testing.T) {
	trusted, _ := ParseCIDRs([]string{"10.0.0.0/8"})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:443"
	r.Header.Set("X-Forwarded-For", "10.4.4.4, garbage")
	r.Header.Set("X-Real-IP", "203.0.113.12")
	if got := ClientIP(r, trusted); got != "203.0.113.12" {
		t.Fatalf("got %q, want X-Real-IP", got)
	}
	r.Header.Del("X-Real-IP")
	if got := ClientIP(r, trusted); got != "10.1.2.3" {
		t.Fatalf("got %q, want remote address", got)
	}
}

func TestClientIPHandlesIPv6RemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[2001:db8::5]:8080"
	if got := ClientIP(r, nil); got != "2001:db8::5" {
		t.Fatalf("got %q", got)
	}
}

func TestBucketIP(t *testing.T) {
	if got := BucketIP("198.51.100.4", 64); got != "198.51.100.4" {
		t.Fatalf("IPv4 changed: %q", got)
	}
	if got := BucketIP("2001:db8:abcd:1234:5678:9abc:def0:1", 64); got != "2001:db8:abcd:1234::/64" {
		t.Fatalf("IPv6 bucket = %q", got)
	}
	if got := BucketIP("junk", 64); got != "junk" {
		t.Fatalf("unparsable input changed: %q", got)
	}
}

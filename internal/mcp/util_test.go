package mcp

import "testing"

func TestDetectLANIPv4_ExcludesLoopbackAndLinkLocal(t *testing.T) {
	ips, err := DetectLANIPv4()
	if err != nil {
		t.Fatalf("DetectLANIPv4: %v", err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			t.Fatalf("did not expect a loopback address in results, got %s", ip)
		}
		if ip.IsLinkLocalUnicast() {
			t.Fatalf("did not expect a link-local address in results, got %s", ip)
		}
		if ip.To4() == nil {
			t.Fatalf("expected only IPv4 addresses, got %s", ip)
		}
	}
}

package validation

import (
	"net"
	"testing"
)

func TestValidateURLRejectsNonDefaultPortsAndReservedNetworks(t *testing.T) {
	tests := []struct{name, target string; wantErr bool}{
		{name:"https nondefault port", target:"https://example.com:8443", wantErr:true},
		{name:"http with tls port", target:"http://example.com:443", wantErr:true},
		{name:"https with http port", target:"https://example.com:80", wantErr:true},
		{name:"https default port", target:"https://example.com:443", wantErr:false},
		{name:"documentation ipv4", target:"http://192.0.2.10", wantErr:true},
		{name:"carrier grade nat", target:"http://100.64.0.1", wantErr:true},
		{name:"benchmark ipv4", target:"https://198.18.0.1", wantErr:true},
		{name:"documentation ipv6", target:"https://[2001:db8::1]", wantErr:true},
		{name:"reserved hostname", target:"https://service.internal", wantErr:true},
		{name:"decimal IPv4 shorthand", target:"http://2130706433", wantErr:true},
		{name:"abbreviated IPv4 shorthand", target:"http://127.1", wantErr:true},
		{name:"hexadecimal IPv4 shorthand", target:"http://0x7f000001", wantErr:true},
		{name:"octal IPv4 shorthand", target:"http://0177.0.0.1", wantErr:true},
		{name:"public target", target:"https://example.com", wantErr:false},
		{name:"canonical public IPv4", target:"http://8.8.8.8", wantErr:false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateURL(tt.target)
			if tt.wantErr && err == nil { t.Fatalf("ValidateURL(%q) expected an error", tt.target) }
			if !tt.wantErr && err != nil { t.Fatalf("ValidateURL(%q) returned unexpected error: %v", tt.target, err) }
		})
	}
}

func TestIsPublicIPRejectsSpecialUseRanges(t *testing.T) {
	for _, raw := range []string{"0.0.0.1", "100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.1", "224.0.0.1", "2001:db8::1", "fd00::1", "fe80::1", "ff02::1"} {
		if IsPublicIP(net.ParseIP(raw)) { t.Errorf("IsPublicIP(%q) = true, want false", raw) }
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !IsPublicIP(net.ParseIP(raw)) { t.Errorf("IsPublicIP(%q) = false, want true", raw) }
	}
}

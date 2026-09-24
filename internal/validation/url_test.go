package validation

import "testing"

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantURL string
	}{
		{name: "adds HTTPS scheme", input: "example.com", wantURL: "https://example.com"},
		{name: "accepts HTTPS", input: "https://example.com/path", wantURL: "https://example.com/path"},
		{name: "accepts HTTP", input: "http://example.com", wantURL: "http://example.com"},
		{name: "rejects empty", input: "", wantErr: true},
		{name: "rejects unsupported scheme", input: "ftp://example.com", wantErr: true},
		{name: "rejects localhost", input: "http://localhost", wantErr: true},
		{name: "rejects loopback IPv4", input: "http://127.0.0.1", wantErr: true},
		{name: "rejects loopback IPv6", input: "http://[::1]", wantErr: true},
		{name: "rejects private IPv4", input: "http://192.168.1.10", wantErr: true},
		{name: "rejects private IPv6", input: "http://[fd00::1]", wantErr: true},
		{name: "rejects link-local", input: "http://169.254.169.254", wantErr: true},
		{name: "rejects userinfo", input: "https://user:pass@example.com", wantErr: true},
		{name: "rejects fragment", input: "https://example.com/#section", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ValidateURL(%q) expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateURL(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.wantURL {
				t.Fatalf("ValidateURL(%q) = %q, want %q", tt.input, got, tt.wantURL)
			}
		})
	}
}

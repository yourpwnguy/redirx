package detector

import (
	"testing"
)

// TestGetRegistrableDomain Table check of eTLD+1 extraction: subdomain collapse, FQDN dots, IPs, junk hosts.
func TestGetRegistrableDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"standard domain", "https://www.example.com/path?q=1", "example.com", false},
		{"subdomain", "https://app.auth.example.co.uk/login", "example.co.uk", false},
		{"with port", "https://example.com:8443/api", "example.com", false},
		{"bare hostname", "http://example.com/test", "example.com", false},
		{"localhost", "http://localhost:3000/health", "", true},
		{"ip literal", "http://192.168.1.1:8080/admin", "192.168.1.1", false},
		{"ip no port", "http://10.0.0.1/api", "10.0.0.1", false},
		{"single label no dot", "http://intranet/", "", true},
		{"uppercase", "https://EXAMPLE.COM/Path", "example.com", false},
		{"trailing dot", "https://example.com./path", "example.com", false},
		{"multi subdomain", "https://a.b.c.d.example.com/x", "example.com", false},
		{"google", "https://www.google.com/search", "google.com", false},
		{"github", "https://github.com/user/repo", "github.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRegistrableDomain(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRegistrableDomain(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetRegistrableDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestExtractHost Table check of host extraction from assorted URL shapes.
func TestExtractHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com/path", "example.com"},
		{"http://192.168.1.1:8080/api", "192.168.1.1:8080"},
		{"https://sub.example.com/", "sub.example.com"},
		{"http://localhost:3000/health", "localhost:3000"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ExtractHost(tt.input)
			if err != nil {
				t.Fatalf("ExtractHost(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ExtractHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestNormalizeURL Verifies scheme-less inputs get http:// prepended; already-schemed URLs pass through.
func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com/path?q=1", "http://example.com/path?q=1"},
		{"https://example.com/ok", "https://example.com/ok"},
		{"", ""},
		{"  https://a.com  ", "https://a.com"},
		{"192.168.1.1:8080/api", "http://192.168.1.1:8080/api"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeURL(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

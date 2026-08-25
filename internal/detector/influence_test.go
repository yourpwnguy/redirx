package detector

import (
	"testing"

	"github.com/yourpwnguy/redirx/internal/httpclient"
)

// TestPayloadIdentities Table check: host extraction from encoded/glued/userinfo payload soup.
func TestPayloadIdentities(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    []string
	}{
		{"scheme-relative", `//google.com/%2f..`, []string{"google.com"}},
		{"userinfo confusion", `//example.com@google.com/%2f%2e%2e`, []string{"example.com", "google.com"}},
		{"full scheme", `https://example.com/%2e%2e`, []string{"example.com"}},
		{"tab glued", `/%09/example.com`, []string{"example.com"}},
		{"backslash escaped", `/https:/%5cexample.com/`, []string{"example.com"}},
		{"hex encoded scheme", `/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d`, []string{"google.com"}},
		{"dot prefix", `/.example.com`, []string{"example.com"}},
		{"semicolon userinfo", `////\\;@example.com`, []string{"example.com"}},
		{"ip literal", `/http://127.0.0.1`, []string{"127.0.0.1"}},
		{"subdomain collapses", `/https://www.example.com/`, []string{"example.com"}},
		{"no host at all", `/..%2f..%2fadmin`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PayloadIdentities(tt.payload)
			if len(got) != len(tt.want) {
				t.Fatalf("PayloadIdentities(%q) = %v, want %v", tt.payload, got, tt.want)
			}
			for _, w := range tt.want {
				if !got[w] {
					t.Errorf("PayloadIdentities(%q) missing %q (got %v)", tt.payload, w, got)
				}
			}
		})
	}
}

// TestInfluencedByPayload_PlaytikaFalsePositive pins the regression from the
// wild: news.playtika.com bounces every thumbnail request to its CDN
// (filecache.mediaroom.com) regardless of the injected payload value. The
// landing has nothing to do with example.com/google.com — must NOT count as
// influenced.
func TestInfluencedByPayload_PlaytikaFalsePositive(t *testing.T) {
	chain := []httpclient.Hop{
		{URL: "https://filecache.mediaroom.com/mr5mr_playtika/177808/JJ_General_Visual__thumbnail_2.jpg", Status: 302},
	}

	for _, payload := range []string{
		`/%09/example.com`,
		`/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d`,
	} {
		final := "https://filecache.mediaroom.com/mr5mr_playtika/177808/JJ_General_Visual__thumbnail_2.jpg"
		if InfluencedByPayload(payload, final, chain) {
			t.Errorf("payload %q: CDN bounce with no payload trace wrongly counted as influenced", payload)
		}
	}
}

// TestInfluencedByPayload Table check of both influence signals plus the fail-open rule for identity-less payloads.
func TestInfluencedByPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		final   string
		chain   []httpclient.Hop
		want    bool
	}{
		{
			name:    "landing on payload domain",
			payload: `//google.com/%2f..`,
			final:   "https://www.google.com/",
			chain:   []httpclient.Hop{{URL: "https://google.com/", Status: 301}},
			want:    true,
		},
		{
			name:    "hex payload decoded by server lands on google",
			payload: `/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d`,
			final:   "https://www.google.com/",
			chain:   []httpclient.Hop{{URL: "https://google.com/", Status: 302}},
			want:    true,
		},
		{
			name:    "server echoes raw encoded payload into location",
			payload: `%2f%2fgoogle.com`,
			final:   "https://evil.corp/%2f%2fgoogle.com",
			chain:   []httpclient.Hop{{URL: "https://evil.corp/%2f%2fgoogle.com", Status: 302}},
			want:    true,
		},
		{
			name:    "payload domain as intermediate hop",
			payload: `//bit.ly/x`,
			final:   "https://attacker.com/",
			chain:   []httpclient.Hop{{URL: "https://bit.ly/x", Status: 301}, {URL: "https://attacker.com/", Status: 301}},
			want:    true,
		},
		{
			name:    "unrelated CDN bounce",
			payload: `//example.com@google.com/%2f..`,
			final:   "https://filecache.mediaroom.com/img.jpg",
			chain:   []httpclient.Hop{{URL: "https://filecache.mediaroom.com/img.jpg", Status: 302}},
			want:    false,
		},
		{
			name:    "lookalike subdomain of payload domain counts",
			payload: `/https://example.com`,
			final:   "https://example.com.evil.net/",
			chain:   nil,
			want:    false, // registrable domain is evil.net — no identity match, no echo
		},
		{
			name:    "traversal-only payload fails open",
			payload: `/..%2f..%2f`,
			final:   "https://other.domain/",
			chain:   []httpclient.Hop{{URL: "https://other.domain/", Status: 302}},
			want:    true,
		},
		{
			name:    "empty chain but final matches",
			payload: `//google.com`,
			final:   "https://google.com/x",
			chain:   nil,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InfluencedByPayload(tt.payload, tt.final, tt.chain); got != tt.want {
				t.Errorf("InfluencedByPayload(%q, %q) = %v, want %v", tt.payload, tt.final, got, tt.want)
			}
		})
	}
}

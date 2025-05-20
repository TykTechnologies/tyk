package request

import (
	"context"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

var ipHeaderTests = []struct {
	remoteAddr string
	key        string
	value      string
	expected   string
	comment    string
}{
	{remoteAddr: "10.0.1.4:8080", key: "X-Real-IP", value: "10.0.0.1", expected: "10.0.0.1", comment: "X-Real-IP"},
	{remoteAddr: "10.0.1.4:8080", key: "X-Forwarded-For", value: "10.0.0.2", expected: "10.0.0.2", comment: "X-Forwarded-For (single)"},
	{remoteAddr: "10.0.1.4:8080", key: "X-Forwarded-For", value: "10.0.0.3, 10.0.0.2, 10.0.0.1", expected: "10.0.0.3", comment: "X-Forwarded-For (multiple)"},
	{remoteAddr: "10.0.1.4:8080", expected: "10.0.1.4", comment: "RemoteAddr"},
	{remoteAddr: "10.0.1.4:8080", key: "X-Forwarded-For", value: "bob", expected: "10.0.1.4", comment: "invalid X-Forwarded-For"},
	{remoteAddr: "10.0.1.4:8080", key: "X-Real-IP", value: "bob", expected: "10.0.1.4", comment: "invalid X-Real-IP"},
}

func TestRealIP(t *testing.T) {
	// Initialize the Global function with a mock config that has XFFDepth set to 0 (first IP in chain)
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.XFFDepth = 0
	Global = func() config.Config {
		return mockConfig
	}

	for _, test := range ipHeaderTests {
		t.Log(test.comment)

		r, _ := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
		r.Header.Set(test.key, test.value)
		r.RemoteAddr = test.remoteAddr

		ip := RealIP(r)

		if ip != test.expected {
			t.Errorf("\texpected %s got %s", test.expected, ip)
		}
	}

	t.Log("Context")
	r, _ := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)

	ctx := context.WithValue(r.Context(), "remote_addr", "10.0.0.5")
	r = r.WithContext(ctx)

	ip := RealIP(r)
	if ip != "10.0.0.5" {
		t.Errorf("\texpected %s got %s", "10.0.0.5", ip)
	}
	
	// Test with XFFDepth = 1 (last IP in chain)
	t.Log("XFFDepth=1 (last IP)")
	mockConfig.HttpServerOptions.XFFDepth = 1
	
	r, _ = http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	r.Header.Set("X-Forwarded-For", "10.0.0.3, 10.0.0.2, 10.0.0.1")
	
	ip = RealIP(r)
	if ip != "10.0.0.1" {
		t.Errorf("\texpected %s got %s", "10.0.0.1", ip)
	}
	
	// Test with XFFDepth = 2 (second to last IP in chain)
	t.Log("XFFDepth=2 (second to last IP)")
	mockConfig.HttpServerOptions.XFFDepth = 2
	
	r, _ = http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	r.Header.Set("X-Forwarded-For", "10.0.0.3, 10.0.0.2, 10.0.0.1")
	
	ip = RealIP(r)
	if ip != "10.0.0.2" {
		t.Errorf("\texpected %s got %s", "10.0.0.2", ip)
	}
}

func BenchmarkRealIP_RemoteAddr(b *testing.B) {
	b.ReportAllocs()
	
	// Initialize the Global function for benchmark
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.XFFDepth = 0
	Global = func() config.Config {
		return mockConfig
	}

	r, _ := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	r.RemoteAddr = "10.0.1.4:8081"

	for n := 0; n < b.N; n++ {
		ip := RealIP(r)
		if ip != "10.0.1.4" {
			b.Errorf("\texpected %s got %s", "10.0.1.4", ip)
		}
	}
}

func BenchmarkRealIP_ForwardedFor(b *testing.B) {
	b.ReportAllocs()
	
	// Initialize the Global function for benchmark
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.XFFDepth = 0
	Global = func() config.Config {
		return mockConfig
	}

	r, _ := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	r.Header.Set("X-Forwarded-For", "10.0.0.3, 10.0.0.2, 10.0.0.1")

	for n := 0; n < b.N; n++ {
		ip := RealIP(r)
		if ip != "10.0.0.3" {
			b.Errorf("\texpected %s got %s", "10.0.1.3", ip)
		}
	}
}

func BenchmarkRealIP_RealIP(b *testing.B) {
	b.ReportAllocs()
	
	// Initialize the Global function for benchmark
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.XFFDepth = 0
	Global = func() config.Config {
		return mockConfig
	}

	r, _ := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	r.Header.Set("X-Real-IP", "10.0.0.1")

	for n := 0; n < b.N; n++ {
		ip := RealIP(r)
		if ip != "10.0.0.1" {
			b.Errorf("\texpected %s got %s", "10.0.0.1", ip)
		}
	}
}

func BenchmarkRealIP_Context(b *testing.B) {
	b.ReportAllocs()
	
	// Initialize the Global function for benchmark
	mockConfig := config.Config{}
	mockConfig.HttpServerOptions.XFFDepth = 0
	Global = func() config.Config {
		return mockConfig
	}

	r, _ := http.NewRequest(http.MethodGet, "http://abc.com:8080", nil)
	r.Header.Set("X-Real-IP", "10.0.0.1")
	ctx := context.WithValue(r.Context(), "remote_addr", "10.0.0.5")
	r = r.WithContext(ctx)

	for n := 0; n < b.N; n++ {
		ip := RealIP(r)
		if ip != "10.0.0.5" {
			b.Errorf("\texpected %s got %s", "10.0.0.5", ip)
		}
	}
}

func TestXFFDepth(t *testing.T) {
	// Define test cases for XFFDepth
	testCases := []struct {
		name     string
		xffValue string
		depth    int
		expected string
	}{
		{
			name:     "Depth 1 (last IP)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    1,
			expected: "13.0.0.1",
		},
		{
			name:     "Depth 2 (second to last IP)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    2,
			expected: "12.0.0.1",
		},
		{
			name:     "Depth 3 (third to last IP)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    3,
			expected: "11.0.0.1",
		},
		{
			name:     "Depth 4 (fourth to last IP)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    4,
			expected: "10.0.0.1",
		},
		{
			name:     "Depth 5 (exceeds chain length)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    5,
			expected: "",
		},
		{
			name:     "Depth 0 (first IP)",
			xffValue: "10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1",
			depth:    0,
			expected: "10.0.0.1",
		},
		{
			name:     "Header with spaces",
			xffValue: "10.0.0.1, 11.0.0.1, 12.0.0.1, 13.0.0.1",
			depth:    2,
			expected: "12.0.0.1",
		},
		{
			name:     "Header with mixed format",
			xffValue: "10.0.0.1,11.0.0.1, 12.0.0.1,  13.0.0.1",
			depth:    3,
			expected: "11.0.0.1",
		},
		{
			name:     "Invalid IP at selected depth",
			xffValue: "10.0.0.1,invalid-ip,12.0.0.1,13.0.0.1",
			depth:    3,
			expected: "192.168.1.1", // Should fall back to RemoteAddr
		},
	}

	// Initialize mock config for tests
	mockConfig := config.Config{}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set the XFFDepth for this test case
			mockConfig.HttpServerOptions.XFFDepth = tc.depth
			Global = func() config.Config {
				return mockConfig
			}

			// Create request with X-Forwarded-For header
			r, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
			r.Header.Set("X-Forwarded-For", tc.xffValue)
			r.RemoteAddr = "192.168.1.1:8080" // Fallback IP if XFF processing fails

			// Get client IP
			ip := RealIP(r)

			// Check result
			if ip != tc.expected {
				t.Errorf("Expected IP %q, got %q", tc.expected, ip)
			}
		})
	}
}

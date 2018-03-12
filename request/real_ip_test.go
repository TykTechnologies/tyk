package request

import (
	"context"
	"net/http"
	"testing"
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
}

func TestRealIP(t *testing.T) {

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
}

func BenchmarkRealIP_RemoteAddr(b *testing.B) {
	b.ReportAllocs()

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

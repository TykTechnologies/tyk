package main

import "testing"

func TestGeoIPLookup(t *testing.T) {
	testCases := [...]struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"foobar", true},
		{"1.2.3.4", false},
	}
	for _, tc := range testCases {
		_, err := geoIPLookup(tc.in)
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("geoIPLookup(%q) did not error", tc.in)
		case !tc.wantErr && err != nil:
			t.Errorf("geoIPLookup(%q) errored", tc.in)
		}
	}
}

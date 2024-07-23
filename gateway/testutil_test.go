package gateway

import "testing"

// TestStartTest serves as a baseline for integration tests.
// It will run a test server, and then shut it down on exit.
//
// Extended tests trigger additional code paths. The coverage
// from this test is substracted from others to better understand
// what is covered by a particular test.
func TestStartTest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
}


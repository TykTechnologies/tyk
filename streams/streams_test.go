package streams

import "testing"

func TestServer(t *testing.T) {
	s := New()
	s.Start()
}

package redeo

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// ------------------------------------------------------------------------

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "redeo")
}

// ------------------------------------------------------------------------

type badWriter struct{ bytes.Buffer }

func (w *badWriter) Write(p []byte) (int, error) {
	w.Buffer.Write(p)
	return 0, io.EOF
}

type mockConn struct {
	bytes.Buffer
	Port   int
	closed bool
}

func (m *mockConn) Close() error { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 9736, Zone: ""}
}
func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP{1, 2, 3, 4}, Port: m.Port, Zone: ""}
}
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

var _ net.Conn = &mockConn{}

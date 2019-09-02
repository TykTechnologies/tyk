package proxyproto

import (
	"bufio"
	"net"
	"sync"
	"time"
)

// Listener is used to wrap an underlying listener,
// whose connections may be using the HAProxy Proxy Protocol.
// If the connection is using the protocol, the RemoteAddr() will return
// the correct client address.
//
// Optionally define ProxyHeaderTimeout to set a maximum time to
// receive the Proxy Protocol Header. Zero means no timeout.
type Listener struct {
	Listener           net.Listener
	ProxyHeaderTimeout time.Duration
}

// Conn is used to wrap and underlying connection which
// may be speaking the Proxy Protocol. If it is, the RemoteAddr() will
// return the address of the client instead of the proxy address.
type Conn struct {
	bufReader          *bufio.Reader
	conn               net.Conn
	header             *Header
	once               sync.Once
	proxyHeaderTimeout time.Duration
}

// Accept waits for and returns the next connection to the listener.
func (p *Listener) Accept() (net.Conn, error) {
	// Get the underlying connection
	conn, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewConn(conn, p.ProxyHeaderTimeout), nil
}

// Close closes the underlying listener.
func (p *Listener) Close() error {
	return p.Listener.Close()
}

// Addr returns the underlying listener's network address.
func (p *Listener) Addr() net.Addr {
	return p.Listener.Addr()
}

// NewConn is used to wrap a net.Conn that may be speaking
// the proxy protocol into a proxyproto.Conn
func NewConn(conn net.Conn, timeout time.Duration) *Conn {
	pConn := &Conn{
		bufReader:          bufio.NewReader(conn),
		conn:               conn,
		proxyHeaderTimeout: timeout,
	}
	return pConn
}

// Read is check for the proxy protocol header when doing
// the initial scan. If there is an error parsing the header,
// it is returned and the socket is closed.
func (p *Conn) Read(b []byte) (int, error) {
	var err error
	p.once.Do(func() {
		err = p.readHeader()
	})
	if err != nil {
		return 0, err
	}
	return p.bufReader.Read(b)
}

// Write wraps original conn.Write
func (p *Conn) Write(b []byte) (int, error) {
	return p.conn.Write(b)
}

// Close wraps original conn.Close
func (p *Conn) Close() error {
	return p.conn.Close()
}

// LocalAddr returns the address of the server if the proxy
// protocol is being used, otherwise just returns the address of
// the socket server.
func (p *Conn) LocalAddr() net.Addr {
	p.once.Do(func() { p.readHeader() })
	if p.header == nil {
		return p.conn.LocalAddr()
	}

	return p.header.LocalAddr()
}

// RemoteAddr returns the address of the client if the proxy
// protocol is being used, otherwise just returns the address of
// the socket peer.
func (p *Conn) RemoteAddr() net.Addr {
	p.once.Do(func() { p.readHeader() })
	if p.header == nil {
		return p.conn.RemoteAddr()
	}

	return p.header.RemoteAddr()
}

// SetDeadline wraps original conn.SetDeadline
func (p *Conn) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

// SetReadDeadline wraps original conn.SetReadDeadline
func (p *Conn) SetReadDeadline(t time.Time) error {
	return p.conn.SetReadDeadline(t)
}

// SetWriteDeadline wraps original conn.SetWriteDeadline
func (p *Conn) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}

func (p *Conn) readHeader() (err error) {
	p.header, err = Read(p.bufReader)
	// For the purpose of this wrapper shamefully stolen from armon/go-proxyproto
	// let's act as if there was no error when PROXY protocol is not present.
	if err == ErrNoProxyProtocol {
		err = nil
	}

	return
}

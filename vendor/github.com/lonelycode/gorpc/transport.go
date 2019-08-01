package gorpc

import (
	"crypto/tls"
	"io"
	"net"
	"time"
)

var (
	dialer = &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
)

// DialFunc is a function intended for setting to Client.Dial.
//
// It is expected that the returned conn immediately
// sends all the data passed via Write() to the server.
// Otherwise gorpc may hang.
// The conn implementation must call Flush() on underlying buffered
// streams before returning from Write().
type DialFunc func(addr string) (conn io.ReadWriteCloser, err error)

// Listener is an interface for custom listeners intended for the Server.
type Listener interface {
	// Init is called on server start.
	//
	// addr contains the address set at Server.Addr.
	Init(addr string) error

	// Accept must return incoming connections from clients.
	// clientAddr must contain client's address in user-readable view.
	//
	// It is expected that the returned conn immediately
	// sends all the data passed via Write() to the client.
	// Otherwise gorpc may hang.
	// The conn implementation must call Flush() on underlying buffered
	// streams before returning from Write().
	Accept() (conn io.ReadWriteCloser, clientAddr string, err error)

	// Close closes the listener.
	// All pending calls to Accept() must immediately return errors after
	// Close is called.
	// All subsequent calls to Accept() must immediately return error.
	Close() error
}

func defaultDial(addr string) (conn io.ReadWriteCloser, err error) {
	return dialer.Dial("tcp", addr)
}

type defaultListener struct {
	L net.Listener
}

func (ln *defaultListener) Init(addr string) (err error) {
	ln.L, err = net.Listen("tcp", addr)
	return
}

func (ln *defaultListener) Accept() (conn io.ReadWriteCloser, clientAddr string, err error) {
	c, err := ln.L.Accept()
	if err != nil {
		return nil, "", err
	}
	if err = setupKeepalive(c); err != nil {
		c.Close()
		return nil, "", err
	}
	return c, c.RemoteAddr().String(), nil
}

func (ln *defaultListener) Close() error {
	return ln.L.Close()
}

func setupKeepalive(conn net.Conn) error {
	tcpConn := conn.(*net.TCPConn)
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return err
	}
	if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
		return err
	}
	return nil
}

type netListener struct {
	F func(addr string) (net.Listener, error)
	L net.Listener
}

func (ln *netListener) Init(addr string) (err error) {
	ln.L, err = ln.F(addr)
	return
}

func (ln *netListener) Accept() (conn io.ReadWriteCloser, clientAddr string, err error) {
	c, err := ln.L.Accept()
	if err != nil {
		return nil, "", err
	}
	return c, c.RemoteAddr().String(), nil
}

func (ln *netListener) Close() error {
	return ln.L.Close()
}

func unixDial(addr string) (conn io.ReadWriteCloser, err error) {
	c, err := net.Dial("unix", addr)
	if err != nil {
		return nil, err
	}
	return c, err
}

// NewTCPClient creates a client connecting over TCP to the server
// listening to the given addr.
//
// The returned client must be started after optional settings' adjustment.
//
// The corresponding server must be created with NewTCPServer().
func NewTCPClient(addr string) *Client {
	return &Client{
		Addr: addr,
		Dial: defaultDial,
	}
}

// NewTCPServer creates a server listening for TCP connections
// on the given addr and processing incoming requests
// with the given HandlerFunc.
//
// The returned server must be started after optional settings' adjustment.
//
// The corresponding client must be created with NewTCPClient().
func NewTCPServer(addr string, handler HandlerFunc) *Server {
	return &Server{
		Addr:     addr,
		Handler:  handler,
		Listener: &defaultListener{},
	}
}

// NewUnixClient creates a client connecting over unix socket
// to the server listening to the given addr.
//
// The returned client must be started after optional settings' adjustment.
//
// The corresponding server must be created with NewUnixServer().
func NewUnixClient(addr string) *Client {
	return &Client{
		Addr: addr,
		Dial: unixDial,

		// There is little sense in compressing rpc data passed
		// over local unix sockets.
		DisableCompression: true,

		// Sacrifice the number of Write() calls to the smallest
		// possible latency, since it has higher priority in local IPC.
		FlushDelay: -1,
	}
}

// NewUnixServer creates a server listening for unix connections
// on the given addr and processing incoming requests
// with the given HandlerFunc.
//
// The returned server must be started after optional settings' adjustment.
//
// The corresponding client must be created with NewUnixClient().
func NewUnixServer(addr string, handler HandlerFunc) *Server {
	return &Server{
		Addr:    addr,
		Handler: handler,
		Listener: &netListener{
			F: func(addr string) (net.Listener, error) {
				return net.Listen("unix", addr)
			},
		},

		// Sacrifice the number of Write() calls to the smallest
		// possible latency, since it has higher priority in local IPC.
		FlushDelay: -1,
	}
}

// NewTLSClient creates a client connecting over TLS (aka SSL) to the server
// listening to the given addr using the given TLS config.
//
// The returned client must be started after optional settings' adjustment.
//
// The corresponding server must be created with NewTLSServer().
func NewTLSClient(addr string, cfg *tls.Config) *Client {
	return &Client{
		Addr: addr,
		Dial: func(addr string) (conn io.ReadWriteCloser, err error) {
			c, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
			if err != nil {
				return nil, err
			}
			return c, err
		},
	}
}

// NewTLSServer creates a server listening for TLS (aka SSL) connections
// on the given addr and processing incoming requests
// with the given HandlerFunc.
// cfg must contain TLS settings for the server.
//
// The returned server must be started after optional settings' adjustment.
//
// The corresponding client must be created with NewTLSClient().
func NewTLSServer(addr string, handler HandlerFunc, cfg *tls.Config) *Server {
	return &Server{
		Addr:    addr,
		Handler: handler,
		Listener: &netListener{
			F: func(addr string) (net.Listener, error) {
				return tls.Listen("tcp", addr, cfg)
			},
		},
	}
}

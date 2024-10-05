package httputil

import (
	"net"

	"github.com/pires/go-proxyproto"
)

// TestListenProxyProto is a test utility.
func TestListenProxyProto(ls net.Listener) error {
	pl := &proxyproto.Listener{Listener: ls}
	for {
		conn, err := pl.Accept()
		if err != nil {
			return err
		}
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			return err
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			return err
		}
	}
}

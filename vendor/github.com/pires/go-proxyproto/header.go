// Package proxyproto implements Proxy Protocol (v1 and v2) parser and writer, as per specification:
// http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"time"
)

var (
	// Protocol
	SIGV1 = []byte{'\x50', '\x52', '\x4F', '\x58', '\x59'}
	SIGV2 = []byte{'\x0D', '\x0A', '\x0D', '\x0A', '\x00', '\x0D', '\x0A', '\x51', '\x55', '\x49', '\x54', '\x0A'}

	ErrCantReadProtocolVersionAndCommand    = errors.New("Can't read proxy protocol version and command")
	ErrCantReadAddressFamilyAndProtocol     = errors.New("Can't read address family or protocol")
	ErrCantReadLength                       = errors.New("Can't read length")
	ErrCantResolveSourceUnixAddress         = errors.New("Can't resolve source Unix address")
	ErrCantResolveDestinationUnixAddress    = errors.New("Can't resolve destination Unix address")
	ErrNoProxyProtocol                      = errors.New("Proxy protocol signature not present")
	ErrUnknownProxyProtocolVersion          = errors.New("Unknown proxy protocol version")
	ErrUnsupportedProtocolVersionAndCommand = errors.New("Unsupported proxy protocol version and command")
	ErrUnsupportedAddressFamilyAndProtocol  = errors.New("Unsupported address family and protocol")
	ErrInvalidLength                        = errors.New("Invalid length")
	ErrInvalidAddress                       = errors.New("Invalid address")
	ErrInvalidPortNumber                    = errors.New("Invalid port number")
)

// Header is the placeholder for proxy protocol header.
type Header struct {
	Version            byte
	Command            ProtocolVersionAndCommand
	TransportProtocol  AddressFamilyAndProtocol
	SourceAddress      net.IP
	DestinationAddress net.IP
	SourcePort         uint16
	DestinationPort    uint16
}

// RemoteAddr returns the address of the remote endpoint of the connection.
func (header *Header) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   header.SourceAddress,
		Port: int(header.SourcePort),
	}
}

// LocalAddr returns the address of the local endpoint of the connection.
func (header *Header) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   header.DestinationAddress,
		Port: int(header.DestinationPort),
	}
}

// EqualTo returns true if headers are equivalent, false otherwise.
// Deprecated: use EqualsTo instead. This method will eventually be removed.
func (header *Header) EqualTo(otherHeader *Header) bool {
	return header.EqualsTo(otherHeader)
}

// EqualsTo returns true if headers are equivalent, false otherwise.
func (header *Header) EqualsTo(otherHeader *Header) bool {
	if otherHeader == nil {
		return false
	}
	if header.Command.IsLocal() {
		return true
	}
	return header.Version == otherHeader.Version &&
		header.TransportProtocol == otherHeader.TransportProtocol &&
		header.SourceAddress.String() == otherHeader.SourceAddress.String() &&
		header.DestinationAddress.String() == otherHeader.DestinationAddress.String() &&
		header.SourcePort == otherHeader.SourcePort &&
		header.DestinationPort == otherHeader.DestinationPort
}

// WriteTo renders a proxy protocol header in a format and writes it to an io.Writer.
func (header *Header) WriteTo(w io.Writer) (int64, error) {
	buf, err := header.Format()
	if err != nil {
		return 0, err
	}

	return bytes.NewBuffer(buf).WriteTo(w)
}

// Format renders a proxy protocol header in a format to write over the wire.
func (header *Header) Format() ([]byte, error) {
	switch header.Version {
	case 1:
		return header.formatVersion1()
	case 2:
		return header.formatVersion2()
	default:
		return nil, ErrUnknownProxyProtocolVersion
	}
}

// Read identifies the proxy protocol version and reads the remaining of
// the header, accordingly.
//
// If proxy protocol header signature is not present, the reader buffer remains untouched
// and is safe for reading outside of this code.
//
// If proxy protocol header signature is present but an error is raised while processing
// the remaining header, assume the reader buffer to be in a corrupt state.
// Also, this operation will block until enough bytes are available for peeking.
func Read(reader *bufio.Reader) (*Header, error) {
	// In order to improve speed for small non-PROXYed packets, take a peek at the first byte alone.
	if b1, err := reader.Peek(1); err == nil && (bytes.Equal(b1[:1], SIGV1[:1]) || bytes.Equal(b1[:1], SIGV2[:1])) {
		if signature, err := reader.Peek(5); err == nil && bytes.Equal(signature[:5], SIGV1) {
			return parseVersion1(reader)
		} else if signature, err := reader.Peek(12); err == nil && bytes.Equal(signature[:12], SIGV2) {
			return parseVersion2(reader)
		}
	}

	return nil, ErrNoProxyProtocol
}

// ReadTimeout acts as Read but takes a timeout. If that timeout is reached, it's assumed
// there's no proxy protocol header.
func ReadTimeout(reader *bufio.Reader, timeout time.Duration) (*Header, error) {
	type header struct {
		h *Header
		e error
	}
	read := make(chan *header, 1)

	go func() {
		h := &header{}
		h.h, h.e = Read(reader)
		read <- h
	}()

	timer := time.NewTimer(timeout)
	select {
	case result := <-read:
		timer.Stop()
		return result.h, result.e
	case <-timer.C:
		return nil, ErrNoProxyProtocol
	}
}

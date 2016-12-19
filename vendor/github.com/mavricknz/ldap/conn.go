// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides LDAP client functions.
package ldap

import (
	"crypto/tls"
	"fmt"
	"github.com/mavricknz/asn1-ber"
	"net"
	"os"
	"sync"
	"time"
)

// An interface for a network dialing method compatible with net.Dial()
type Dialable interface {
	Dial(string, string) (net.Conn, error)
}

// An interface for a network dialing method compatible with net.DialTimeout()
type TimedDialable interface {
	DialTimeout(string, string, time.Duration) (net.Conn, error)
}

// Converts a net.Dial() compatible function to Dialable
type Dialer func(string, string) (net.Conn, error)

// Converts a net.DialTimeout() compatible function to TimedDialable
type TimedDialer func(string, string, time.Duration) (net.Conn, error)

func (fn Dialer) Dial(n, a string) (net.Conn, error) {
	return fn(n, a)
}

func (fn TimedDialer) Dial(n, a string) (net.Conn, error) {
	return fn(n, a, 0)
}

func (fn TimedDialer) DialTimeout(n, a string, t time.Duration) (net.Conn, error) {
	return fn(n, a, t)
}

// Conn - LDAP Connection and also pre/post connect configuation
//	IsTLS bool // default false
//	IsSSL bool // default false
//	Debug bool // default false
//	NetworkConnectTimeout time.Duration // default 0 no timeout
//	ReadTimeout    time.Duration // default 0 no timeout
//	AbandonMessageOnReadTimeout bool // send abandon on a ReadTimeout (not for searches yet)
//	Addr           string // default empty
//	Dialer         Dialable // default nil, optional network dialer to use (net.Dial()/net.DialTimeout() by default)
//
// A minimal connection...
//  ldap := NewLDAPConnection("localhost",389)
//  err := ldap.Connect() // Connects the existing connection, or returns an error
type LDAPConnection struct {
	IsTLS bool
	IsSSL bool
	Debug bool

	Addr                        string
	NetworkConnectTimeout       time.Duration
	ReadTimeout                 time.Duration
	AbandonMessageOnReadTimeout bool

	TlsConfig *tls.Config

	Dialer Dialable

	conn               net.Conn
	chanResults        map[uint64]chan *ber.Packet
	lockChanResults    sync.RWMutex
	chanProcessMessage chan *messagePacket
	closeLock          sync.RWMutex
	chanMessageID      chan uint64
	connected          bool
}

// Connect connects using information in LDAPConnection.
// LDAPConnection should be populated with connection information.
func (l *LDAPConnection) Connect() error {
	l.chanResults = map[uint64]chan *ber.Packet{}
	l.chanProcessMessage = make(chan *messagePacket)
	l.chanMessageID = make(chan uint64)

	if l.conn == nil {
		var c net.Conn
		var err error

		if l.Dialer == nil {
			if l.NetworkConnectTimeout > 0 {
				l.Dialer = TimedDialer(net.DialTimeout)
			} else {
				l.Dialer = Dialer(net.Dial)
			}
		}

		switch dialer := l.Dialer.(type) {
		case TimedDialable:
			c, err = dialer.DialTimeout("tcp", l.Addr, l.NetworkConnectTimeout)
		case Dialable:
			c, err = dialer.Dial("tcp", l.Addr)
		}

		if err != nil {
			return err
		}

		if l.IsSSL {
			tlsConn := tls.Client(c, l.TlsConfig)
			err = tlsConn.Handshake()
			if err != nil {
				return err
			}
			l.conn = tlsConn
		} else {
			l.conn = c
		}
	}
	l.start()
	l.connected = true
	if l.IsTLS {
		err := l.startTLS()
		if err != nil {
			return err
		}
	}
	return nil
}

// NewConn returns a new basic connection. Should start connection via
// Connect
func NewLDAPConnection(server string, port uint16) *LDAPConnection {
	return &LDAPConnection{
		Addr: fmt.Sprintf("%s:%d", server, port),
	}
}

func NewLDAPTLSConnection(server string, port uint16, tlsConfig *tls.Config) *LDAPConnection {
	return &LDAPConnection{
		Addr:      fmt.Sprintf("%s:%d", server, port),
		IsTLS:     true,
		TlsConfig: tlsConfig,
	}
}

func NewLDAPSSLConnection(server string, port uint16, tlsConfig *tls.Config) *LDAPConnection {
	return &LDAPConnection{
		Addr:      fmt.Sprintf("%s:%d", server, port),
		IsSSL:     true,
		TlsConfig: tlsConfig,
	}
}

func (l *LDAPConnection) start() {
	go l.reader()
	go l.processMessages()
}

// Close closes the connection.
func (l *LDAPConnection) Close() error {
	if l.Debug {
		fmt.Println("Starting Close().")
	}
	l.sendProcessMessage(&messagePacket{Op: MessageQuit})
	return nil
}

// Returns the next available messageID
func (l *LDAPConnection) nextMessageID() (messageID uint64, ok bool) {
	messageID, ok = <-l.chanMessageID
	if l.Debug {
		fmt.Printf("MessageID: %d, ok: %v\n", messageID, ok)
	}
	return
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (l *LDAPConnection) startTLS() error {
	messageID, ok := l.nextMessageID()
	if !ok {
		return NewLDAPError(ErrorClosing, "MessageID channel is closed.")
	}

	if l.IsSSL {
		return NewLDAPError(ErrorNetwork, "Already encrypted")
	}

	tlsRequest := encodeTLSRequest()
	packet, err := requestBuildPacket(messageID, tlsRequest, nil)

	if err != nil {
		return err
	}

	err = l.sendReqRespPacket(messageID, packet)
	if err != nil {
		return err
	}

	conn := tls.Client(l.conn, l.TlsConfig)
	err = conn.Handshake()
	if err != nil {
		return err
	}
	l.IsSSL = true
	l.conn = conn

	return nil
}

func encodeTLSRequest() (tlsRequest *ber.Packet) {
	tlsRequest = ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start TLS")
	tlsRequest.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	return
}

const (
	MessageQuit     = 0
	MessageRequest  = 1
	MessageResponse = 2
	MessageFinish   = 3
)

type messagePacket struct {
	Op        int
	MessageID uint64
	Packet    *ber.Packet
	Channel   chan *ber.Packet
}

func (l *LDAPConnection) getNewResultChannel(message_id uint64) (out chan *ber.Packet, err error) {
	// as soon as a channel is requested add to chanResults to never miss
	// on cleanup.
	l.lockChanResults.Lock()
	defer l.lockChanResults.Unlock()

	if l.chanResults == nil {
		return nil, NewLDAPError(ErrorClosing, "Connection closing/closed")
	}

	if _, ok := l.chanResults[message_id]; ok {
		errStr := fmt.Sprintf("chanResults already allocated, message_id: %d", message_id)
		return nil, NewLDAPError(ErrorUnknown, errStr)
	}

	out = make(chan *ber.Packet, ResultChanBufferSize)
	l.chanResults[message_id] = out
	return
}

func (l *LDAPConnection) sendMessage(p *ber.Packet) (out chan *ber.Packet, err error) {
	message_id := p.Children[0].Value.(uint64)
	// sendProcessMessage may not process a message on shutdown
	// getNewResultChannel adds id/chan to chan results
	out, err = l.getNewResultChannel(message_id)
	if err != nil {
		return
	}
	if l.Debug {
		fmt.Printf("sendMessage-> message_id: %d, out: %v\n", message_id, out)
	}

	message_packet := &messagePacket{Op: MessageRequest, MessageID: message_id, Packet: p, Channel: out}
	l.sendProcessMessage(message_packet)
	return
}

func (l *LDAPConnection) processMessages() {
	defer l.closeAllChannels()
	defer func() {
		// Close all channels, connection and quit.
		// Use closeLock to stop MessageRequests
		// and l.connected to stop any future MessageRequests.
		l.closeLock.Lock()
		defer l.closeLock.Unlock()
		l.connected = false
		// will shutdown reader.
		l.conn.Close()
	}()
	var message_id uint64 = 1
	var message_packet *messagePacket

	for {
		select {
		case l.chanMessageID <- message_id:
			message_id++
		case message_packet = <-l.chanProcessMessage:
			switch message_packet.Op {
			case MessageQuit:
				if l.Debug {
					fmt.Printf("Shutting down\n")
				}
				return
			case MessageRequest:
				// Add to message list and write to network
				if l.Debug {
					fmt.Printf("Sending message %d\n", message_packet.MessageID)
				}
				buf := message_packet.Packet.Bytes()
				for len(buf) > 0 {
					n, err := l.conn.Write(buf)
					if err != nil {
						if l.Debug {
							fmt.Printf("Error Sending Message: %s\n", err)
						}
						return
					}
					if n == len(buf) {
						break
					}
					buf = buf[n:]
				}
			case MessageFinish:
				// Remove from message list
				if l.Debug {
					fmt.Printf("Finished message %d\n", message_packet.MessageID)
				}
				l.lockChanResults.Lock()
				delete(l.chanResults, message_packet.MessageID)
				l.lockChanResults.Unlock()
			}
		}
	}
}

func (l *LDAPConnection) closeAllChannels() {
	l.lockChanResults.Lock()
	defer l.lockChanResults.Unlock()
	for MessageID, Channel := range l.chanResults {
		if l.Debug {
			fmt.Printf("Closing channel for MessageID %d\n", MessageID)
		}
		close(Channel)
		delete(l.chanResults, MessageID)
	}
	l.chanResults = nil

	close(l.chanMessageID)
	l.chanMessageID = nil

	close(l.chanProcessMessage)
	l.chanProcessMessage = nil
}

func (l *LDAPConnection) finishMessage(MessageID uint64) {
	message_packet := &messagePacket{Op: MessageFinish, MessageID: MessageID}
	l.sendProcessMessage(message_packet)
}

func (l *LDAPConnection) reader() {
	defer l.Close()
	for {
		p, err := ber.ReadPacket(l.conn)
		if err != nil {
			if l.Debug {
				fmt.Printf("ldap.reader: %s\n", err)
			}
			return
		}

		addLDAPDescriptions(p)

		message_id := p.Children[0].Value.(uint64)
		message_packet := &messagePacket{Op: MessageResponse, MessageID: message_id, Packet: p}

		l.readerToChanResults(message_packet)
	}
}

func (l *LDAPConnection) readerToChanResults(message_packet *messagePacket) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "Recovered in readerToChanResults", r)
		}
	}()
	if l.Debug {
		fmt.Printf("Receiving message %d\n", message_packet.MessageID)
	}

	// very small chance on disconnect to write to a closed channel as
	// lockChanResults is unlocked immediately hence defer above.
	// Don't lock while sending to chanResult below as that can block and hold
	// the lock.
	l.lockChanResults.RLock()
	chanResult, ok := l.chanResults[message_packet.MessageID]
	l.lockChanResults.RUnlock()

	if !ok {
		if l.Debug {
			fmt.Printf("Message Result chan not found (possible Abandon), MessageID: %d\n", message_packet.MessageID)
		}
	} else {
		// chanResult is a buffered channel of ResultChanBufferSize
		chanResult <- message_packet.Packet
	}
}

func (l *LDAPConnection) sendProcessMessage(message *messagePacket) {
	go func() {
		// multiple senders can queue on l.chanProcessMessage
		// but block on shutdown.
		l.closeLock.RLock()
		defer l.closeLock.RUnlock()
		if l.connected {
			l.chanProcessMessage <- message
		}
	}()
}

package tcp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get().WithField("prefix", "tcp-proxy")

type ConnState uint

const (
	Active ConnState = iota
	Open
	Closed
)

// Modifier define rules for tranforming incoming and outcoming TCP messages
// To filter response set data to empty
// To close connection, return error
type Modifier struct {
	ModifyRequest  func(src, dst net.Conn, data []byte) ([]byte, error)
	ModifyResponse func(src, dst net.Conn, data []byte) ([]byte, error)
}

type targetConfig struct {
	modifier *Modifier
	target   string
}

// Stat defines basic statistics about a tcp connection
type Stat struct {
	State    ConnState
	BytesIn  int64
	BytesOut int64
}

func (s *Stat) Flush() Stat {
	v := Stat{
		BytesIn:  atomic.LoadInt64(&s.BytesIn),
		BytesOut: atomic.LoadInt64(&s.BytesOut),
	}
	atomic.StoreInt64(&s.BytesIn, 0)
	atomic.StoreInt64(&s.BytesOut, 0)
	return v
}

type Proxy struct {
	sync.RWMutex

	DialTLS         func(network, addr string) (net.Conn, error)
	Dial            func(network, addr string) (net.Conn, error)
	TLSConfigTarget *tls.Config

	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// Domain to config mapping
	muxer     map[string]*targetConfig
	SyncStats func(Stat)
	// Duration in which connection stats will be flushed. Defaults to one second.
	StatsSyncInterval time.Duration
}

func (p *Proxy) AddDomainHandler(domain, target string, modifier *Modifier) {
	p.Lock()
	defer p.Unlock()

	if p.muxer == nil {
		p.muxer = make(map[string]*targetConfig)
	}

	if modifier == nil {
		modifier = &Modifier{}
	}

	p.muxer[domain] = &targetConfig{
		modifier: modifier,
		target:   target,
	}
}

func (p *Proxy) Swap(new *Proxy) {
	p.Lock()
	defer p.Unlock()

	p.muxer = new.muxer
}

func (p *Proxy) RemoveDomainHandler(domain string) {
	p.Lock()
	defer p.Unlock()

	delete(p.muxer, domain)
}

func (p *Proxy) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.WithError(err).Warning("Can't accept connection")
			return err
		}
		go func() {
			if err := p.handleConn(conn); err != nil {
				log.WithError(err).Warning("Can't handle connection")
			}
		}()
	}
}

func (p *Proxy) getTargetConfig(conn net.Conn) (*targetConfig, error) {
	p.RLock()
	defer p.RUnlock()

	if len(p.muxer) == 0 {
		return nil, errors.New("No services defined")
	}

	switch v := conn.(type) {
	case *tls.Conn:
		if err := v.Handshake(); err != nil {
			return nil, err
		}

		state := v.ConnectionState()

		if state.ServerName == "" {
			// If SNI disabled, and only 1 record defined return it
			if len(p.muxer) == 1 {
				for _, config := range p.muxer {
					return config, nil
				}
			}

			return nil, errors.New("Multiple services on different domains running on the same port, but no SNI (domain) information from client")
		}

		// If SNI supported try to match domain
		if config, ok := p.muxer[state.ServerName]; ok {
			return config, nil
		}

		// If no custom domains are used
		if config, ok := p.muxer[""]; ok {
			return config, nil
		}

		return nil, errors.New("Can't detect service based on provided SNI information: " + state.ServerName)
	default:
		if len(p.muxer) > 1 {
			return nil, errors.New("Running multiple services without TLS and SNI not supported")
		}

		for _, config := range p.muxer {
			return config, nil
		}
	}

	return nil, errors.New("Can't detect service configuration")
}

func (p *Proxy) handleConn(conn net.Conn) error {
	var connectionClosed atomic.Value
	connectionClosed.Store(false)

	stat := Stat{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if p.SyncStats != nil {
		go func() {
			duration := p.StatsSyncInterval
			if duration == 0 {
				duration = time.Second
			}
			tick := time.NewTicker(duration)
			defer tick.Stop()
			p.SyncStats(Stat{State: Open})
			for {
				select {
				case <-ctx.Done():
					s := stat.Flush()
					s.State = Closed
					p.SyncStats(s)
					return
				case <-tick.C:
					p.SyncStats(stat.Flush())
				}
			}
		}()
	}
	config, err := p.getTargetConfig(conn)
	if err != nil {
		conn.Close()
		return err
	}
	u, uErr := url.Parse(config.target)
	if uErr != nil {
		u, uErr = url.Parse("tcp://" + config.target)

		if uErr != nil {
			conn.Close()
			return uErr
		}
	}

	// connects to target server
	var rconn net.Conn
	switch u.Scheme {
	case "tcp":
		if p.Dial != nil {
			rconn, err = p.Dial("tcp", u.Host)
		} else {
			rconn, err = net.Dial("tcp", u.Host)
		}
	case "tls":
		if p.DialTLS != nil {
			rconn, err = p.DialTLS("tcp", u.Host)
		} else {
			rconn, err = tls.Dial("tcp", u.Host, p.TLSConfigTarget)
		}
	default:
		err = errors.New("Unsupported protocol. Should be empty, `tcp` or `tls`")
	}
	if err != nil {
		conn.Close()
		return err
	}
	defer func() {
		conn.Close()
		rconn.Close()
	}()
	var wg sync.WaitGroup
	wg.Add(2)

	r := pipeOpts{
		modifier: func(src, dst net.Conn, data []byte) ([]byte, error) {
			atomic.AddInt64(&stat.BytesIn, int64(len(data)))
			h := config.modifier.ModifyRequest
			if h != nil {
				return h(src, dst, data)
			}
			return data, nil
		},
		beforeExit: func() {
			wg.Done()
		},
		onReadError: func(err error) {
			if IsSocketClosed(err) && connectionClosed.Load().(bool) {
				return
			}
			if err == io.EOF {
				// End of stream from the client.
				connectionClosed.Store(true)
				log.WithField("conn", clientConn(conn)).Debug("End of client stream")
			} else {
				log.WithError(err).Error("Failed to read from client connection")
			}
		},
		onWriteError: func(err error) {
			log.WithError(err).Info("Failed to write to upstream socket")
		},
	}
	w := pipeOpts{
		modifier: func(src, dst net.Conn, data []byte) ([]byte, error) {
			atomic.AddInt64(&stat.BytesOut, int64(len(data)))
			h := config.modifier.ModifyResponse
			if h != nil {
				return h(src, dst, data)
			}
			return data, nil
		},
		beforeExit: func() {
			wg.Done()
		},
		onReadError: func(err error) {
			if IsSocketClosed(err) && connectionClosed.Load().(bool) {
				return
			}
			if err == io.EOF {
				// End of stream from upstream
				connectionClosed.Store(true)
				log.WithField("conn", upstreamConn(rconn)).Debug("End of upstream stream")
			} else {
				log.WithError(err).Error("Failed to read from upstream connection")
			}
		},
		onWriteError: func(err error) {
			log.WithError(err).Info("Failed to write to client connection")
		},
	}
	go p.pipe(conn, rconn, r)
	go p.pipe(rconn, conn, w)
	wg.Wait()
	return nil
}

func upstreamConn(c net.Conn) string {
	return formatAddress(c.LocalAddr(), c.RemoteAddr())
}

func clientConn(c net.Conn) string {
	return formatAddress(c.RemoteAddr(), c.LocalAddr())
}

func formatAddress(a, b net.Addr) string {
	return a.String() + "->" + b.String()
}

// IsSocketClosed returns true if err is a result of reading from closed network
// connection
func IsSocketClosed(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection")
}

type pipeOpts struct {
	modifier     func(net.Conn, net.Conn, []byte) ([]byte, error)
	onReadError  func(error)
	onWriteError func(error)
	beforeExit   func()
}

func (p *Proxy) pipe(src, dst net.Conn, opts pipeOpts) {
	defer func() {
		src.Close()
		dst.Close()
		if opts.beforeExit != nil {
			opts.beforeExit()
		}
	}()

	buf := make([]byte, 65535)

	for {
		var readDeadline time.Time
		if p.ReadTimeout != 0 {
			readDeadline = time.Now().Add(p.ReadTimeout)
		}
		src.SetReadDeadline(readDeadline)
		n, err := src.Read(buf)
		if err != nil {
			if opts.onReadError != nil {
				opts.onReadError(err)
			}
			return
		}
		b := buf[:n]

		if opts.modifier != nil {
			if b, err = opts.modifier(src, dst, b); err != nil {
				log.WithError(err).Warning("Closing connection")
				return
			}
		}

		if len(b) == 0 {
			continue
		}

		var writeDeadline time.Time
		if p.WriteTimeout != 0 {
			writeDeadline = time.Now().Add(p.WriteTimeout)
		}
		dst.SetWriteDeadline(writeDeadline)
		_, err = dst.Write(b)
		if err != nil {
			if opts.onWriteError != nil {
				opts.onWriteError(err)
			}
			return
		}
	}
}

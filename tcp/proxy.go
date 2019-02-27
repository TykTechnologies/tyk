package tcp

import (
    "crypto/tls"
    "errors"
    "net"
    "sync"
    "time"

    logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get().WithField("prefix", "tcp-proxy")

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

type Proxy struct {
    sync.RWMutex

    TLSConfigTarget *tls.Config

    ReadTimeout  time.Duration
    WriteTimeout time.Duration

    // Domain to config mapping
    muxer map[string]*targetConfig
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
    config, err := p.getTargetConfig(conn)
    if err != nil {
        conn.Close()
        return err
    }

    // connects to target server
    var rconn net.Conn
    if p.TLSConfigTarget == nil {
        rconn, err = net.Dial("tcp", config.target)
    } else {
        rconn, err = tls.Dial("tcp", config.target, p.TLSConfigTarget)
    }
    if err != nil {
        conn.Close()
        return err
    }

    // write to dst what it reads from src
    var pipe = func(src, dst net.Conn, modifier func(net.Conn, net.Conn, []byte) ([]byte, error)) {
        defer func() {
            conn.Close()
            rconn.Close()
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
                log.Println(err)
                return
            }
            b := buf[:n]

            if modifier != nil {
                if b, err = modifier(src, dst, b); err != nil {
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
                log.Println(err)
                return
            }
        }
    }

    go pipe(conn, rconn, config.modifier.ModifyRequest)
    go pipe(rconn, conn, config.modifier.ModifyResponse)

    return nil
}

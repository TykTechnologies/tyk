package tcp

import (
    "bytes"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "net"
    "strings"
    "testing"
    "time"
)

func TestProxyModifier(t *testing.T) {
    // Echoing
    upstream := tcpMock(func(in []byte, err error) (out []byte) {
        return in
    })
    defer upstream.Close()

    t.Run("Without modifier", func(t *testing.T) {
        proxy := &Proxy{}
        proxy.AddDomainHandler("", upstream.Addr().String(), nil)

        testRunner(t, proxy, "", false, []testCase{
            {"write", "ping", ""},
            {"read", "ping", ""},
        }...)
    })

    t.Run("Modify response", func(t *testing.T) {
        proxy := &Proxy{}
        proxy.AddDomainHandler("", upstream.Addr().String(), &Modifier{
            ModifyResponse: func(src, dst net.Conn, data []byte) ([]byte, error) {
                return []byte("pong"), nil
            },
        })

        testRunner(t, proxy, "", false, []testCase{
            {"write", "ping", ""},
            {"read", "pong", ""},
        }...)
    })

    t.Run("Mock request", func(t *testing.T) {
        proxy := &Proxy{}
        proxy.AddDomainHandler("", upstream.Addr().String(), &Modifier{
            ModifyRequest: func(src, dst net.Conn, data []byte) ([]byte, error) {
                return []byte("pong"), nil
            },
        })

        testRunner(t, proxy, "", false, []testCase{
            {"write", "ping", ""},
            {"read", "pong", ""},
        }...)
    })
}

func TestProxyMultiTarget(t *testing.T) {
    target1 := tcpMock(func(in []byte, err error) (out []byte) {
        return []byte("first")
    })
    defer target1.Close()

    target2 := tcpMock(func(in []byte, err error) (out []byte) {
        return []byte("second")
    })
    defer target2.Close()

    t.Run("Single_target, no SNI", func(t *testing.T) {
        proxy := &Proxy{}
        proxy.AddDomainHandler("", target1.Addr().String(), nil)

        testRunner(t, proxy, "", true, []testCase{
            {"write", "ping", ""},
            {"read", "first", ""},
        }...)
    })

    t.Run("Single target, SNI, without domain", func(t *testing.T) {
        proxy := &Proxy{}
        proxy.AddDomainHandler("", target1.Addr().String(), nil)

        testRunner(t, proxy, "localhost", true, []testCase{
            {"write", "ping", ""},
            {"read", "first", ""},
        }...)
    })

    t.Run("Single target, SNI, domain match", func(t *testing.T) {
        proxy := &Proxy{}
        proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)

        testRunner(t, proxy, "localhost", true, []testCase{
            {"write", "ping", ""},
            {"read", "first", ""},
        }...)
    })

    t.Run("Single target, SNI, domain not match", func(t *testing.T) {
        proxy := &Proxy{}
        proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)

        // Should cause `Can't detect service based on provided SNI information: example.com`
        testRunner(t, proxy, "example.com", true, []testCase{
            {"write", "ping", ""},
            {"read", "", "EOF"},
        }...)
    })

    t.Run("Multiple targets, No SNI", func(t *testing.T) {
        proxy := &Proxy{}
        proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)
        proxy.AddDomainHandler("example.com", target2.Addr().String(), nil)

        // Should cause `Multiple services on different domains running on the same port, but no SNI (domain) information from client
        testRunner(t, proxy, "", true, []testCase{
            {"write", "ping", ""},
            {"read", "", "EOF"},
        }...)
    })

    t.Run("Multiple targets, SNI", func(t *testing.T) {
        proxy := &Proxy{}
        proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)
        proxy.AddDomainHandler("example.com", target2.Addr().String(), nil)

        testRunner(t, proxy, "localhost", true, []testCase{
            {"write", "ping", ""},
            {"read", "first", ""},
        }...)

        testRunner(t, proxy, "example.com", true, []testCase{
            {"write", "ping", ""},
            {"read", "second", ""},
        }...)

        testRunner(t, proxy, "wrong", true, []testCase{
            {"write", "ping", ""},
            {"read", "", "EOF"},
        }...)
    })

    t.Run("Multiple targets, SNI with fallback", func(t *testing.T) {
        proxy := &Proxy{}
        proxy.AddDomainHandler("", target1.Addr().String(), nil)
        proxy.AddDomainHandler("example.com", target2.Addr().String(), nil)

        testRunner(t, proxy, "example.com", true, []testCase{
            {"write", "ping", ""},
            {"read", "second", ""},
        }...)

        // Should fallback to target defined with empty domain
        testRunner(t, proxy, "wrong", true, []testCase{
            {"write", "ping", ""},
            {"read", "first", ""},
        }...)
    })
}

func cert(t *testing.T, domain string) tls.Certificate {
    private, err := rsa.GenerateKey(rand.Reader, 512)
    if err != nil {
        t.Fatal(err)
    }
    template := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization: []string{"Test Co"},
            CommonName:   domain,
        },
        NotBefore:             time.Time{},
        NotAfter:              time.Now().Add(60 * time.Minute),
        IsCA:                  true,
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
    if err != nil {
        t.Fatal(err)
    }

    var cert, key bytes.Buffer
    pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
    pem.Encode(&key, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})

    tlscert, err := tls.X509KeyPair(cert.Bytes(), key.Bytes())
    if err != nil {
        t.Fatal(err)
    }

    return tlscert
}

func tcpMock(cb func(in []byte, err error) (out []byte)) net.Listener {
    l, _ := net.Listen("tcp", ":0")

    go func() {
        for {
            // Listen for an incoming connection.
            conn, err := l.Accept()
            if err != nil {
                log.WithError(err).Error("Mock Accept error")
                return
            }
            buf := make([]byte, 65535)
            n, err := conn.Read(buf)

            resp := cb(buf[:n], err)

            if err != nil {
                log.WithError(err).Error("Mock read error")
                return
            }

            if len(resp) > 0 {
                if n, err = conn.Write(resp); err != nil {
                    log.WithError(err).Error("Mock Conn write error")
                }
            }
        }
    }()

    return l
}

type testCase struct {
    action     string //read or write
    payload    string
    errorMatch string
}

func testRunner(t *testing.T, proxy *Proxy, hostname string, useSSL bool, testCases ...testCase) {
    var proxyLn net.Listener
    var err error

    if useSSL {
        tlsConfig := &tls.Config{
            Certificates:       []tls.Certificate{cert(t, "localhost")},
            InsecureSkipVerify: true,
        }
        tlsConfig.BuildNameToCertificate()
        proxyLn, err = tls.Listen("tcp", ":0", tlsConfig)

        if err != nil {
            t.Fatalf(err.Error())
            return
        }
    } else {
        proxyLn, _ = net.Listen("tcp", ":0")
    }
    defer proxyLn.Close()

    go proxy.Serve(proxyLn)

    buf := make([]byte, 65535)

    proxyAddr := proxyLn.Addr().String()
    var client net.Conn
    if useSSL {
        client, err = tls.Dial("tcp", proxyLn.Addr().String(), &tls.Config{
            ServerName:         hostname,
            InsecureSkipVerify: true,
        })
        if err != nil {
            t.Fatalf(err.Error())
            return
        }
    } else {
        client, err = net.Dial("tcp", proxyAddr)
        if err != nil {
            t.Fatalf(err.Error())
            return
        }
    }
    defer client.Close()

    for ti, tc := range testCases {
        var n int

        client.SetDeadline(time.Now().Add(10 * time.Millisecond))
        switch tc.action {
        case "write":
            _, err = client.Write([]byte(tc.payload))
        case "read":
            n, err = client.Read(buf)

            if err == nil {
                if string(buf[:n]) != tc.payload {
                    t.Fatalf("[%d] Expected read %s, got %v", ti, tc.payload, string(buf[:n]))
                }
            }
        }

        if tc.errorMatch != "" {
            if err == nil {
                t.Fatalf("[%d] Expected error: %s", ti, tc.errorMatch)
                break
            }

            if !strings.Contains(err.Error(), tc.errorMatch) {
                t.Fatalf("[%d] Expected error %s, got %s", ti, err.Error(), tc.errorMatch)
                break
            }
        } else {
            if err != nil {
                t.Fatalf("[%d] Unexpected error: %s", ti, err.Error())
                break
            }
        }
    }
}

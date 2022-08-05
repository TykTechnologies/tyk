package test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type TCPTestCase struct {
	Action     string //read or write
	Payload    string
	ErrorMatch string
}

type TCPTestRunner struct {
	UseSSL          bool
	Target          string
	Hostname        string
	TLSClientConfig *tls.Config
}

func (r TCPTestRunner) Run(t testing.TB, testCases ...TCPTestCase) error {
	var err error
	buf := make([]byte, 65535)

	var client net.Conn
	if r.UseSSL {
		if r.TLSClientConfig == nil {
			r.TLSClientConfig = &tls.Config{
				ServerName:         r.Hostname,
				InsecureSkipVerify: true,
				MaxVersion:         tls.VersionTLS12,
			}
		}
		client, err = tls.Dial("tcp", r.Target, r.TLSClientConfig)
		if err != nil {
			return err
		}
	} else {
		client, err = net.Dial("tcp", r.Target)
		if err != nil {
			return err
		}
	}
	defer client.Close()

	for ti, tc := range testCases {
		var n int
		client.SetDeadline(time.Now().Add(time.Second))
		switch tc.Action {
		case "write":
			_, err = client.Write([]byte(tc.Payload))
		case "read":
			n, err = client.Read(buf)

			if err == nil {
				if string(buf[:n]) != tc.Payload {
					t.Fatalf("[%d] Expected read %s, got %v", ti, tc.Payload, string(buf[:n]))
				}
			}
		}

		if tc.ErrorMatch != "" {
			if err == nil {
				t.Fatalf("[%d] Expected error: %s", ti, tc.ErrorMatch)
			}

			if !strings.Contains(err.Error(), tc.ErrorMatch) {
				t.Fatalf("[%d] Expected error %s, got %s", ti, err.Error(), tc.ErrorMatch)
			}
		} else {
			if err != nil {
				t.Fatalf("[%d] Unexpected error: %s", ti, err.Error())
			}
		}
	}

	return nil
}

func TcpMock(useSSL bool, cb func(in []byte, err error) (out []byte)) net.Listener {
	var l net.Listener

	if useSSL {
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{Cert("localhost")},
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
		}
		tlsConfig.BuildNameToCertificate()
		l, _ = tls.Listen("tcp", ":0", tlsConfig)
	} else {
		l, _ = net.Listen("tcp", ":0")
	}

	go func() {
		for {
			// Listen for an incoming connection.
			conn, err := l.Accept()
			if err != nil {
				log.Println("Mock Accept error", err.Error())
				return
			}
			buf := make([]byte, 65535)
			n, err := conn.Read(buf)

			resp := cb(buf[:n], err)

			if err != nil {
				log.Println("Mock read error", err.Error())
				return
			}

			if len(resp) > 0 {
				if n, err = conn.Write(resp); err != nil {
					log.Println("Mock Conn write error", err.Error())
				}
			}
		}
	}()

	return l
}

// Generate cert
func Cert(domain string) tls.Certificate {
	private, _ := rsa.GenerateKey(rand.Reader, 512)
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

	derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)

	var cert, key bytes.Buffer
	pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(&key, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})

	tlscert, _ := tls.X509KeyPair(cert.Bytes(), key.Bytes())

	return tlscert
}

package tcp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/test"
)

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// STK-REQ-091:STK-REQ-091-AC-01:acceptance
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:encoding_safety:nominal
// SW-REQ-166:determinism:nominal
func TestProxyModifier(t *testing.T) {
	// Echoing
	upstream := test.TcpMock(false, func(in []byte, err error) (out []byte) {
		return in
	})
	defer upstream.Close()

	t.Run("Without modifier", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", upstream.Addr().String(), nil)

		testRunner(t, proxy, "", false, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "ping"},
		}...)
	})

	t.Run("Modify response", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", upstream.Addr().String(), &Modifier{
			ModifyResponse: func(src, dst net.Conn, data []byte) ([]byte, error) {
				return []byte("pong"), nil
			},
		})

		testRunner(t, proxy, "", false, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "pong"},
		}...)
	})

	t.Run("Mock request", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", upstream.Addr().String(), &Modifier{
			ModifyRequest: func(src, dst net.Conn, data []byte) ([]byte, error) {
				return []byte("pong"), nil
			},
		})

		testRunner(t, proxy, "", false, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "pong"},
		}...)
	})
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:determinism:nominal
func TestStatFlushAndHandlerConfiguration(t *testing.T) {
	stat := &Stat{}
	atomic.StoreInt64(&stat.BytesIn, 12)
	atomic.StoreInt64(&stat.BytesOut, 34)

	if got := stat.Flush(); got.BytesIn != 12 || got.BytesOut != 34 {
		t.Fatalf("expected flushed bytes 12/34 got %#v", got)
	}
	if got := stat.Flush(); got.BytesIn != 0 || got.BytesOut != 0 {
		t.Fatalf("expected second flush to reset bytes got %#v", got)
	}

	proxy := &Proxy{}
	proxy.AddDomainHandler("first.example", "tcp://first:1234", nil)
	if proxy.muxer["first.example"].modifier == nil {
		t.Fatal("expected nil modifier to be replaced")
	}

	replacement := &Proxy{TLSConfigTarget: &tls.Config{ServerName: "replacement"}}
	replacement.AddDomainHandler("second.example", "tcp://second:1234", &Modifier{})
	proxy.Swap(replacement)
	if proxy.TLSConfigTarget.ServerName != "replacement" {
		t.Fatal("expected swapped TLS config")
	}
	if _, ok := proxy.muxer["first.example"]; ok {
		t.Fatal("expected old handler map to be replaced")
	}
	if _, ok := proxy.muxer["second.example"]; !ok {
		t.Fatal("expected replacement handler map")
	}

	proxy.RemoveDomainHandler("second.example")
	if _, ok := proxy.muxer["second.example"]; ok {
		t.Fatal("expected handler removal")
	}
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:error_handling:nominal
// SW-REQ-166:error_handling:negative
// SW-REQ-166:encoding_safety:nominal
// SW-REQ-166:determinism:nominal
// STK-REQ-091:error_handling:negative
func TestProxySyncStats(t *testing.T) {
	// Echoing
	upstream := test.TcpMock(false, func(in []byte, err error) (out []byte) {
		return in
	})
	defer upstream.Close()
	stats := make(chan Stat, 10)
	proxy := &Proxy{SyncStats: func(s Stat) {
		stats <- s
		if s.State == Closed {
			close(stats)
		}
	}}
	proxy.AddDomainHandler("", upstream.Addr().String(), nil)

	testRunner(t, proxy, "", false, []test.TCPTestCase{
		{Action: "write", Payload: "ping"},
		{Action: "read", Payload: "ping"},
	}...)
	var c []Stat
	for s := range stats {
		c = append(c, s)
	}
	if len(c) < 2 {
		t.Fatalf("expected at least open and closed stats got %#v", c)
	}
	if c[0].State != Open {
		t.Fatalf("expected first stat to be open got %#v", c[0])
	}
	last := c[len(c)-1]
	if last.State != Closed {
		t.Fatalf("expected last stat to be closed got %#v", last)
	}
	if last.BytesIn != 4 || last.BytesOut != 4 {
		t.Fatalf("expected closed byte counts 4/4 got %#v", last)
	}
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:error_handling:nominal
// SW-REQ-166:error_handling:negative
// SW-REQ-166:encoding_safety:nominal
// SW-REQ-166:determinism:nominal
func TestProxyMultiTarget(t *testing.T) {
	target1 := test.TcpMock(false, func(in []byte, err error) (out []byte) {
		return []byte("first")
	})
	defer target1.Close()

	target2 := test.TcpMock(false, func(in []byte, err error) (out []byte) {
		return []byte("second")
	})
	defer target2.Close()

	t.Run("Single_target, no SNI", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", target1.Addr().String(), nil)

		testRunner(t, proxy, "", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "first"},
		}...)
	})

	t.Run("Single target, SNI, without domain", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", target1.Addr().String(), nil)

		testRunner(t, proxy, "localhost", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "first"},
		}...)
	})

	t.Run("Single target, SNI, domain match", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)

		testRunner(t, proxy, "localhost", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "first"},
		}...)
	})

	t.Run("Single target, SNI, domain not match", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)

		// Should cause `Can't detect service based on provided SNI information: example.com`
		testRunner(t, proxy, "example.com", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", ErrorMatch: "EOF"},
		}...)
	})

	t.Run("Multiple targets, No SNI", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)
		proxy.AddDomainHandler("example.com", target2.Addr().String(), nil)

		// Should cause `Multiple services on different domains running on the same port, but no SNI (domain) information from client
		testRunner(t, proxy, "", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", ErrorMatch: "EOF"},
		}...)
	})

	t.Run("Multiple targets, SNI", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("localhost", target1.Addr().String(), nil)
		proxy.AddDomainHandler("example.com", target2.Addr().String(), nil)

		testRunner(t, proxy, "localhost", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "first"},
		}...)

		testRunner(t, proxy, "example.com", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "second"},
		}...)

		testRunner(t, proxy, "wrong", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", ErrorMatch: "EOF"},
		}...)
	})

	t.Run("Multiple targets, SNI with fallback", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.AddDomainHandler("", target1.Addr().String(), nil)
		proxy.AddDomainHandler("example.com", target2.Addr().String(), nil)

		testRunner(t, proxy, "example.com", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "second"},
		}...)

		// Should fallback to target defined with empty domain
		testRunner(t, proxy, "wrong", true, []test.TCPTestCase{
			{Action: "write", Payload: "ping"},
			{Action: "read", Payload: "first"},
		}...)
	})
}

func testRunner(t *testing.T, proxy *Proxy, hostname string, useSSL bool, testCases ...test.TCPTestCase) {
	t.Helper()

	var proxyLn net.Listener
	var err error

	if useSSL {
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{test.Cert("localhost")},
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
		}
		tlsConfig.BuildNameToCertificate()
		proxyLn, err = tls.Listen("tcp", ":0", tlsConfig)

		if err != nil {
			t.Fatal(err.Error())
			return
		}
	} else {
		proxyLn, _ = net.Listen("tcp", ":0")
	}
	defer proxyLn.Close()

	go proxy.Serve(proxyLn)

	runner := test.TCPTestRunner{
		Target:   proxyLn.Addr().String(),
		UseSSL:   useSSL,
		Hostname: hostname,
	}
	runner.Run(t, testCases...)
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:error_handling:nominal
// SW-REQ-166:error_handling:negative
// SW-REQ-166:determinism:nominal
func TestProxy_Shutdown(t *testing.T) {
	tests := []struct {
		name           string
		setupProxy     func() *Proxy
		setupContext   func() (context.Context, context.CancelFunc)
		expectError    bool
		errorType      error
		beforeShutdown func(*Proxy, net.Listener)
	}{
		{
			name: "shutdown with no active connections",
			setupProxy: func() *Proxy {
				return &Proxy{}
			},
			setupContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			expectError: false,
		},
		{
			name: "shutdown with active connections that complete quickly",
			setupProxy: func() *Proxy {
				return &Proxy{}
			},
			setupContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
			expectError: false,
			beforeShutdown: func(proxy *Proxy, _ net.Listener) {
				// Simulate active connections by calling activeConns.Add
				proxy.activeConns.Add(2)

				// Simulate connections completing
				go func() {
					time.Sleep(100 * time.Millisecond)
					proxy.activeConns.Done()
					proxy.activeConns.Done()
				}()
			},
		},
		{
			name: "shutdown timeout with slow connections",
			setupProxy: func() *Proxy {
				return &Proxy{}
			},
			setupContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 200*time.Millisecond)
			},
			expectError: true,
			errorType:   context.DeadlineExceeded,
			beforeShutdown: func(proxy *Proxy, _ net.Listener) {
				// Simulate slow connections that don't complete in time
				proxy.activeConns.Add(1)
				// Don't call Done() to simulate hanging connection
			},
		},
		{
			name: "shutdown with cancelled context",
			setupProxy: func() *Proxy {
				return &Proxy{}
			},
			setupContext: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				// Cancel immediately to test context cancellation
				cancel()
				return ctx, func() {}
			},
			expectError: true,
			errorType:   context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := tt.setupProxy()
			ctx, cancel := tt.setupContext()
			defer cancel()

			// Initialize shutdown context if not already done
			proxy.initShutdownContext()

			if tt.beforeShutdown != nil {
				tt.beforeShutdown(proxy, nil)
			}

			err := proxy.Shutdown(ctx)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Errorf("expected error type %v, got %v", tt.errorType, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:determinism:nominal
func TestProxy_SetShutdownContext(t *testing.T) {
	tests := []struct {
		name        string
		setupProxy  func() *Proxy
		setupCtx    func() context.Context
		validateCtx func(*testing.T, *Proxy, context.Context)
	}{
		{
			name: "set shutdown context",
			setupProxy: func() *Proxy {
				return &Proxy{}
			},
			setupCtx: func() context.Context {
				return context.Background()
			},
			validateCtx: func(t *testing.T, p *Proxy, _ context.Context) {
				if p.shutdownCtx == nil {
					t.Error("shutdown context should not be nil after setting")
				}
				if p.shutdown == nil {
					t.Error("shutdown cancel function should not be nil after setting")
				}
			},
		},
		{
			name: "overwrite existing shutdown context",
			setupProxy: func() *Proxy {
				p := &Proxy{}
				// Set initial context
				ctx, cancel := context.WithCancel(context.Background())
				p.shutdownCtx = ctx
				p.shutdown = cancel
				return p
			},
			setupCtx: func() context.Context {
				return context.Background()
			},
			validateCtx: func(t *testing.T, p *Proxy, _ context.Context) {
				if p.shutdownCtx == nil {
					t.Error("shutdown context should not be nil after overwriting")
				}
				if p.shutdown == nil {
					t.Error("shutdown cancel function should not be nil after overwriting")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := tt.setupProxy()
			ctx := tt.setupCtx()

			proxy.SetShutdownContext(ctx)

			tt.validateCtx(t, proxy, ctx)
		})
	}
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:determinism:nominal
func TestProxy_initShutdownContext(t *testing.T) {
	tests := []struct {
		name       string
		setupProxy func() *Proxy
		validate   func(*testing.T, *Proxy)
	}{
		{
			name: "initialize when context is nil",
			setupProxy: func() *Proxy {
				return &Proxy{}
			},
			validate: func(t *testing.T, p *Proxy) {
				if p.shutdownCtx == nil {
					t.Error("shutdown context should be initialized")
				}
				if p.shutdown == nil {
					t.Error("shutdown cancel function should be initialized")
				}
			},
		},
		{
			name: "don't reinitialize when context exists",
			setupProxy: func() *Proxy {
				p := &Proxy{}
				ctx, cancel := context.WithCancel(context.Background())
				p.shutdownCtx = ctx
				p.shutdown = cancel
				return p
			},
			validate: func(t *testing.T, p *Proxy) {
				originalCtx := p.shutdownCtx
				// Can't compare functions, just check they exist
				originalCancelExists := p.shutdown != nil

				p.initShutdownContext()

				if p.shutdownCtx != originalCtx {
					t.Error("shutdown context should not be reinitialized when it already exists")
				}
				if !originalCancelExists || p.shutdown == nil {
					t.Error("shutdown cancel function should not be reinitialized when it already exists")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := tt.setupProxy()
			proxy.initShutdownContext()
			tt.validate(t, proxy)
		})
	}
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:error_handling:nominal
// SW-REQ-166:error_handling:negative
// SW-REQ-166:determinism:nominal
func TestProxy_ServeWithGracefulShutdown(t *testing.T) {
	// Test that Serve properly tracks connections and responds to shutdown
	upstream := test.TcpMock(false, func(in []byte, _ error) (out []byte) {
		// Simulate slow response to test connection tracking
		time.Sleep(100 * time.Millisecond)
		return in
	})
	defer upstream.Close()

	proxy := &Proxy{}
	proxy.AddDomainHandler("", upstream.Addr().String(), nil)

	// Set up listener
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Start proxy in goroutine
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = proxy.Serve(listener)
	}()

	// Give proxy time to start
	time.Sleep(50 * time.Millisecond)

	// Connect client and start sending data
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}

	// Send data in background to keep connection active
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		defer conn.Close()

		// Send data
		_, err := conn.Write([]byte("test"))
		if err != nil {
			t.Logf("Client write error (expected during shutdown): %v", err)
			return
		}

		// Try to read response
		buf := make([]byte, 4)
		_, err = conn.Read(buf)
		if err != nil {
			t.Logf("Client read error (expected during shutdown): %v", err)
		}
	}()

	// Wait a bit for connection to be established
	time.Sleep(50 * time.Millisecond)

	// Set shutdown context and close listener to trigger shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	proxy.SetShutdownContext(shutdownCtx)

	// Close listener to stop accepting new connections
	listener.Close()

	// Wait for serve to complete
	select {
	case <-serveDone:
		// Expected - serve should exit after listener is closed
	case <-time.After(3 * time.Second):
		t.Error("Serve did not exit in reasonable time")
	}

	// Test graceful shutdown
	err = proxy.Shutdown(shutdownCtx)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Unexpected shutdown error: %v", err)
	}

	// Wait for client connection to finish
	select {
	case <-clientDone:
		// Client finished
	case <-time.After(1 * time.Second):
		t.Log("Client connection took longer than expected to finish")
	}
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:determinism:nominal
func TestProxy_ConcurrentConnectionTracking(t *testing.T) {
	// Test that connection tracking is thread-safe
	proxy := &Proxy{}
	proxy.initShutdownContext()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperationsPerGoroutine := 100

	// Simulate concurrent connection tracking
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperationsPerGoroutine; j++ {
				proxy.activeConns.Add(1)
				proxy.activeConns.Done()
			}
		}()
	}

	wg.Wait()

	// Test shutdown with no active connections
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := proxy.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed after concurrent operations: %v", err)
	}
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:error_handling:nominal
// SW-REQ-166:error_handling:negative
// SW-REQ-166:determinism:nominal
func TestProxy_ShutdownIntegration(t *testing.T) {
	// Test that TCP proxy properly shuts down connections when shutdown context is cancelled
	upstream := test.TcpMock(false, func(in []byte, _ error) (out []byte) {
		// Simulate slow response to test shutdown during active connection
		time.Sleep(200 * time.Millisecond)
		return in
	})
	defer upstream.Close()

	proxy := &Proxy{}
	proxy.AddDomainHandler("", upstream.Addr().String(), nil)

	// Set up listener
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	// Set shutdown context before starting
	shutdownCtx, cancel := context.WithCancel(context.Background())
	proxy.SetShutdownContext(shutdownCtx)

	// Start proxy in background
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		proxy.Serve(listener)
	}()

	// Give proxy time to start
	time.Sleep(50 * time.Millisecond)

	// Connect and start sending data
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send data to establish connection
	go func() {
		conn.Write([]byte("test"))
	}()

	// Wait for connection to be established
	time.Sleep(50 * time.Millisecond)

	// Trigger shutdown by cancelling context
	cancel()

	// Close listener to stop accepting new connections
	listener.Close()

	// Test that shutdown completes within reasonable time
	shutdownCompleted := make(chan struct{})
	go func() {
		defer close(shutdownCompleted)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		proxy.Shutdown(ctx)
	}()

	select {
	case <-shutdownCompleted:
		// Expected - shutdown should complete
	case <-time.After(2 * time.Second):
		t.Error("Shutdown did not complete in reasonable time")
	}

	// Verify that serve exits
	select {
	case <-serveDone:
		// Expected - serve should exit after listener is closed
	case <-time.After(1 * time.Second):
		t.Error("Serve did not exit after listener was closed")
	}
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:error_handling:nominal
// SW-REQ-166:error_handling:negative
// SW-REQ-166:encoding_safety:nominal
// SW-REQ-166:determinism:nominal
func TestConnectionFormattingAndSocketClosed(t *testing.T) {
	local := testAddr("local")
	remote := testAddr("remote")
	conn := &addressConn{local: local, remote: remote}

	if got := upstreamConn(conn); got != "local->remote" {
		t.Fatalf("expected upstream address got %q", got)
	}
	if got := clientConn(conn); got != "remote->local" {
		t.Fatalf("expected client address got %q", got)
	}
	if got := formatAddress(remote, local); got != "remote->local" {
		t.Fatalf("expected formatted address got %q", got)
	}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "closed socket",
			err:  errors.New("read tcp: use of closed network connection"),
			want: true,
		},
		{
			name: "different error",
			err:  io.EOF,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSocketClosed(tt.err); got != tt.want {
				t.Fatalf("expected %v got %v", tt.want, got)
			}
		})
	}
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:error_handling:nominal
// SW-REQ-166:error_handling:negative
// SW-REQ-166:encoding_safety:nominal
// SW-REQ-166:determinism:nominal
func TestProxyPipe(t *testing.T) {
	t.Run("forwards modified payload", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.initShutdownContext()
		srcClient, srcProxy := net.Pipe()
		dstProxy, dstClient := net.Pipe()
		defer srcClient.Close()
		defer dstClient.Close()

		done := make(chan struct{})
		go proxy.pipe(srcProxy, dstProxy, pipeOpts{
			modifier: func(src, dst net.Conn, data []byte) ([]byte, error) {
				return []byte("pong"), nil
			},
			beforeExit: func() {
				close(done)
			},
		})

		if _, err := srcClient.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := dstClient.Read(buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != "pong" {
			t.Fatalf("expected pong got %q", string(buf))
		}
		srcClient.Close()
		waitForPipeExit(t, done)
	})

	t.Run("drops empty modified payload then exits on read close", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.initShutdownContext()
		srcClient, srcProxy := net.Pipe()
		dstProxy, dstClient := net.Pipe()
		defer srcClient.Close()
		defer dstClient.Close()

		done := make(chan struct{})
		go proxy.pipe(srcProxy, dstProxy, pipeOpts{
			modifier: func(src, dst net.Conn, data []byte) ([]byte, error) {
				return nil, nil
			},
			beforeExit: func() {
				close(done)
			},
		})

		if _, err := srcClient.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		srcClient.Close()
		waitForPipeExit(t, done)
	})

	t.Run("exits on modifier error", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.initShutdownContext()
		srcClient, srcProxy := net.Pipe()
		dstProxy, dstClient := net.Pipe()
		defer srcClient.Close()
		defer dstClient.Close()

		done := make(chan struct{})
		go proxy.pipe(srcProxy, dstProxy, pipeOpts{
			modifier: func(src, dst net.Conn, data []byte) ([]byte, error) {
				return nil, errors.New("modifier failed")
			},
			beforeExit: func() {
				close(done)
			},
		})

		if _, err := srcClient.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		waitForPipeExit(t, done)
	})

	t.Run("reports write errors", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.initShutdownContext()
		srcClient, srcProxy := net.Pipe()
		dstProxy, dstClient := net.Pipe()
		defer srcClient.Close()
		dstClient.Close()

		writeErrors := make(chan error, 1)
		done := make(chan struct{})
		go proxy.pipe(srcProxy, dstProxy, pipeOpts{
			onWriteError: func(err error) {
				writeErrors <- err
			},
			beforeExit: func() {
				close(done)
			},
		})

		if _, err := srcClient.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		waitForPipeExit(t, done)
		select {
		case err := <-writeErrors:
			if err == nil {
				t.Fatal("expected write error")
			}
		default:
			t.Fatal("expected write error callback")
		}
	})

	t.Run("exits on shutdown context", func(t *testing.T) {
		proxy := &Proxy{}
		ctx, cancel := context.WithCancel(context.Background())
		proxy.SetShutdownContext(ctx)
		srcClient, srcProxy := net.Pipe()
		dstProxy, dstClient := net.Pipe()
		defer srcClient.Close()
		defer dstClient.Close()

		done := make(chan struct{})
		go proxy.pipe(srcProxy, dstProxy, pipeOpts{
			beforeExit: func() {
				close(done)
			},
		})

		cancel()
		waitForPipeExit(t, done)
	})
}

// Verifies: STK-REQ-091, SYS-REQ-179, SW-REQ-166
// MCDC SYS-REQ-179: tcp_proxy_operation_terminal=T => TRUE
// MCDC SW-REQ-166: tcp_proxy_operation_terminal=T => TRUE
// STK-REQ-091:STK-REQ-091-AC-01:acceptance
// STK-REQ-091:error_handling:negative
// SW-REQ-166:nominal:nominal
// SW-REQ-166:boundary:nominal
// SW-REQ-166:error_handling:nominal
// SW-REQ-166:error_handling:negative
// SW-REQ-166:encoding_safety:nominal
// SW-REQ-166:determinism:nominal
func TestTCPProxyReqProof(t *testing.T) {
	t.Run("domain handler configuration and stat flushing", func(t *testing.T) {
		stat := &Stat{}
		atomic.StoreInt64(&stat.BytesIn, 12)
		atomic.StoreInt64(&stat.BytesOut, 34)
		if got := stat.Flush(); got.BytesIn != 12 || got.BytesOut != 34 {
			t.Fatalf("flushed stat = %#v, want 12/34 bytes", got)
		}
		if got := stat.Flush(); got.BytesIn != 0 || got.BytesOut != 0 {
			t.Fatalf("second flushed stat = %#v, want reset bytes", got)
		}

		proxy := &Proxy{}
		proxy.AddDomainHandler("first.example", "tcp://first:1234", nil)
		if proxy.muxer["first.example"].modifier == nil {
			t.Fatal("expected nil modifier to be replaced")
		}

		replacement := &Proxy{TLSConfigTarget: &tls.Config{ServerName: "replacement"}}
		replacement.AddDomainHandler("second.example", "tcp://second:1234", &Modifier{})
		proxy.Swap(replacement)
		if proxy.TLSConfigTarget.ServerName != "replacement" {
			t.Fatal("expected swapped TLS config")
		}
		if _, ok := proxy.muxer["first.example"]; ok {
			t.Fatal("expected old handler map to be replaced")
		}
		if _, ok := proxy.muxer["second.example"]; !ok {
			t.Fatal("expected replacement handler map")
		}
		proxy.RemoveDomainHandler("second.example")
		if _, ok := proxy.muxer["second.example"]; ok {
			t.Fatal("expected handler removal")
		}
	})

	target1 := test.TcpMock(false, func(in []byte, _ error) []byte {
		return []byte("first")
	})
	defer target1.Close()
	target2 := test.TcpMock(false, func(in []byte, _ error) []byte {
		return []byte("second")
	})
	defer target2.Close()

	t.Run("single tls sni and fallback target selection", func(t *testing.T) {
		single := &Proxy{}
		single.AddDomainHandler("", target1.Addr().String(), nil)
		testRunner(t, single, "", false, test.TCPTestCase{Action: "write", Payload: "ping"}, test.TCPTestCase{Action: "read", Payload: "first"})

		byDomain := &Proxy{}
		byDomain.AddDomainHandler("localhost", target1.Addr().String(), nil)
		byDomain.AddDomainHandler("example.com", target2.Addr().String(), nil)
		testRunner(t, byDomain, "example.com", true, test.TCPTestCase{Action: "write", Payload: "ping"}, test.TCPTestCase{Action: "read", Payload: "second"})

		withFallback := &Proxy{}
		withFallback.AddDomainHandler("", target1.Addr().String(), nil)
		withFallback.AddDomainHandler("example.com", target2.Addr().String(), nil)
		testRunner(t, withFallback, "wrong", true, test.TCPTestCase{Action: "write", Payload: "ping"}, test.TCPTestCase{Action: "read", Payload: "first"})
	})

	t.Run("request and response modifiers plus sync stats", func(t *testing.T) {
		upstream := test.TcpMock(false, func(in []byte, _ error) []byte {
			return in
		})
		defer upstream.Close()

		stats := make(chan Stat, 10)
		proxy := &Proxy{
			SyncStats: func(s Stat) {
				stats <- s
				if s.State == Closed {
					close(stats)
				}
			},
			StatsSyncInterval: 10 * time.Millisecond,
		}
		proxy.AddDomainHandler("", upstream.Addr().String(), &Modifier{
			ModifyRequest: func(src, dst net.Conn, data []byte) ([]byte, error) {
				return []byte("modified-request"), nil
			},
			ModifyResponse: func(src, dst net.Conn, data []byte) ([]byte, error) {
				if string(data) != "modified-request" {
					t.Fatalf("upstream response = %q, want modified request echo", string(data))
				}
				return []byte("modified-response"), nil
			},
		})
		testRunner(t, proxy, "", false, test.TCPTestCase{Action: "write", Payload: "ping"}, test.TCPTestCase{Action: "read", Payload: "modified-response"})

		var observed []Stat
		for s := range stats {
			observed = append(observed, s)
		}
		if len(observed) < 2 {
			t.Fatalf("expected open and closed stats, got %#v", observed)
		}
		if observed[0].State != Open || observed[len(observed)-1].State != Closed {
			t.Fatalf("stats states = %#v, want open then closed", observed)
		}
	})

	t.Run("shutdown context and active connection completion", func(t *testing.T) {
		proxy := &Proxy{}
		proxy.initShutdownContext()
		if proxy.shutdownCtx == nil || proxy.shutdown == nil {
			t.Fatal("expected initialized shutdown context")
		}

		ctx, cancel := context.WithCancel(context.Background())
		proxy.SetShutdownContext(ctx)
		if proxy.shutdownCtx == nil || proxy.shutdown == nil {
			t.Fatal("expected caller shutdown context")
		}
		cancel()

		proxy.activeConns.Add(1)
		go proxy.activeConns.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		if err := proxy.Shutdown(shutdownCtx); err != nil {
			t.Fatalf("Shutdown returned error: %v", err)
		}
	})

	t.Run("connection formatting and closed socket classification", func(t *testing.T) {
		conn := &addressConn{local: testAddr("local"), remote: testAddr("remote")}
		if got := upstreamConn(conn); got != "local->remote" {
			t.Fatalf("upstream conn = %q, want local->remote", got)
		}
		if got := clientConn(conn); got != "remote->local" {
			t.Fatalf("client conn = %q, want remote->local", got)
		}
		if got := formatAddress(testAddr("remote"), testAddr("local")); got != "remote->local" {
			t.Fatalf("formatted address = %q, want remote->local", got)
		}
		if !IsSocketClosed(errors.New("read tcp: use of closed network connection")) {
			t.Fatal("expected closed socket classification")
		}
		if IsSocketClosed(io.EOF) {
			t.Fatal("expected EOF not to classify as closed socket")
		}
	})

	t.Run("pipe termination paths", func(t *testing.T) {
		t.Run("forwards modified payload", func(t *testing.T) {
			proxy := &Proxy{}
			proxy.initShutdownContext()
			srcClient, srcProxy := net.Pipe()
			dstProxy, dstClient := net.Pipe()
			defer srcClient.Close()
			defer dstClient.Close()

			done := make(chan struct{})
			go proxy.pipe(srcProxy, dstProxy, pipeOpts{
				modifier: func(src, dst net.Conn, data []byte) ([]byte, error) {
					return []byte("pong"), nil
				},
				beforeExit: func() {
					close(done)
				},
			})

			if _, err := srcClient.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := dstClient.Read(buf); err != nil {
				t.Fatal(err)
			}
			if string(buf) != "pong" {
				t.Fatalf("pipe output = %q, want pong", string(buf))
			}
			srcClient.Close()
			waitForPipeExit(t, done)
		})

		t.Run("empty modified payload exits after read close", func(t *testing.T) {
			proxy := &Proxy{}
			proxy.initShutdownContext()
			srcClient, srcProxy := net.Pipe()
			dstProxy, dstClient := net.Pipe()
			defer srcClient.Close()
			defer dstClient.Close()

			done := make(chan struct{})
			go proxy.pipe(srcProxy, dstProxy, pipeOpts{
				modifier: func(src, dst net.Conn, data []byte) ([]byte, error) {
					return nil, nil
				},
				beforeExit: func() {
					close(done)
				},
			})

			if _, err := srcClient.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			srcClient.Close()
			waitForPipeExit(t, done)
		})

		t.Run("exits on modifier error", func(t *testing.T) {
			proxy := &Proxy{}
			proxy.initShutdownContext()
			srcClient, srcProxy := net.Pipe()
			dstProxy, dstClient := net.Pipe()
			defer srcClient.Close()
			defer dstClient.Close()

			done := make(chan struct{})
			go proxy.pipe(srcProxy, dstProxy, pipeOpts{
				modifier: func(src, dst net.Conn, data []byte) ([]byte, error) {
					return nil, errors.New("modifier failed")
				},
				beforeExit: func() {
					close(done)
				},
			})

			if _, err := srcClient.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			waitForPipeExit(t, done)
		})

		t.Run("reports read and write errors", func(t *testing.T) {
			proxy := &Proxy{}
			proxy.initShutdownContext()
			srcClient, srcProxy := net.Pipe()
			dstProxy, dstClient := net.Pipe()
			defer srcClient.Close()
			dstClient.Close()

			writeErrors := make(chan error, 1)
			done := make(chan struct{})
			go proxy.pipe(srcProxy, dstProxy, pipeOpts{
				onWriteError: func(err error) {
					writeErrors <- err
				},
				beforeExit: func() {
					close(done)
				},
			})

			if _, err := srcClient.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			waitForPipeExit(t, done)
			select {
			case err := <-writeErrors:
				if err == nil {
					t.Fatal("expected write error")
				}
			default:
				t.Fatal("expected write error callback")
			}

			readProxy := &Proxy{}
			readProxy.initShutdownContext()
			readClient, readSrc := net.Pipe()
			readDst, readSink := net.Pipe()
			defer readClient.Close()
			defer readSink.Close()
			readErrors := make(chan error, 1)
			readDone := make(chan struct{})
			go readProxy.pipe(readSrc, readDst, pipeOpts{
				onReadError: func(err error) {
					readErrors <- err
				},
				beforeExit: func() {
					close(readDone)
				},
			})
			readClient.Close()
			waitForPipeExit(t, readDone)
			select {
			case err := <-readErrors:
				if err == nil {
					t.Fatal("expected read error")
				}
			default:
				t.Fatal("expected read error callback")
			}
		})

		t.Run("exits on shutdown context", func(t *testing.T) {
			proxy := &Proxy{}
			ctx, cancel := context.WithCancel(context.Background())
			proxy.SetShutdownContext(ctx)
			srcClient, srcProxy := net.Pipe()
			dstProxy, dstClient := net.Pipe()
			defer srcClient.Close()
			defer dstClient.Close()

			done := make(chan struct{})
			go proxy.pipe(srcProxy, dstProxy, pipeOpts{
				beforeExit: func() {
					close(done)
				},
			})
			cancel()
			waitForPipeExit(t, done)
		})
	})
}

func waitForPipeExit(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pipe did not exit")
	}
}

type testAddr string

func (a testAddr) Network() string {
	return "test"
}

func (a testAddr) String() string {
	return string(a)
}

type addressConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (c *addressConn) LocalAddr() net.Addr {
	return c.local
}

func (c *addressConn) RemoteAddr() net.Addr {
	return c.remote
}

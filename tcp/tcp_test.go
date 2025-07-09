package tcp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/test"
)

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
func TestProxySyncStats(t *testing.T) {
	t.Skip()
	// Echoing
	upstream := test.TcpMock(false, func(in []byte, err error) (out []byte) {
		return in
	})
	defer upstream.Close()
	stats := make(chan Stat)
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
	expect := []Stat{
		{State: Open},
		{State: Closed, BytesIn: 4, BytesOut: 4},
	}
	if len(c) != len(expect) {
		t.Fatalf("expected %d stats got %d stats", len(expect), len(c))
	}
	if !reflect.DeepEqual(c, expect) {
		t.Errorf("expected %#v got %#v", expect, c)
	}
}

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
			t.Fatalf(err.Error())
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

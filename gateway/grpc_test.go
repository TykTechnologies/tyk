package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"golang.org/x/net/http2/h2c"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"
)

// For gRPC, we should be sure that HTTP/2 works with Tyk in H2C configuration also for insecure grpc over http.
func TestHTTP2_h2C(t *testing.T) {
	defer ResetTestConfig()
	var port = 6666

	EnablePort(port, "h2c")
	var echo = "Hello, I am an HTTP/2 Server"
	expected := "HTTP/2.0"
	serv := &http2.Server{}
	// Upstream server supporting HTTP/2
	upstream := httptest.NewUnstartedServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actual := r.Proto
		if expected != actual {
			t.Fatalf("Tyk-Upstream connection protocol is expected %s, actual %s", expected, actual)
		}

		w.Write([]byte(echo))

	}), serv))
	upstream.Start()
	defer upstream.Close()

	// Tyk
	globalConf := config.Global()
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = upstream.URL
		spec.Protocol = "h2c"
		spec.ListenPort = port
	})
	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			// Pretend we are dialing a TLS endpoint. (Note, we ignore the passed tls.Config)
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	s := fmt.Sprintf("http://localhost:%d", port)
	w, err := client.Get(s)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Body.Close()
	b, err := ioutil.ReadAll(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	bs := string(b)
	if bs != "Hello, I am an HTTP/2 Server" {
		t.Errorf("expected %s to %s", echo, bs)
	}

	if w.ProtoMajor != 2 {
		t.Error("expected %i to %i", 2, w.ProtoMajor)
	}

}

func TestGRPC_H2C(t *testing.T) {
	defer ResetTestConfig()

	var port = 6666
	EnablePort(port, "h2c")
	// gRPC server
	target, s := startGRPCServerH2C(t, setupHelloSVC)
	defer target.Close()
	defer s.GracefulStop()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "h2c_api"
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = toTarget(t, "h2c", target)
		spec.ListenPort = port
		spec.Protocol = "h2c"
	})

	name := "Josh"

	// gRPC client
	r := sayHelloWithGRPCClientH2C(t, "localhost:6666", name)

	// Test result
	expected := "Hello " + name
	actual := r.Message

	if expected != actual {
		t.Fatalf("Expected %s, actual %s", expected, actual)
	}
}

// For gRPC, we should be sure that HTTP/2 works with Tyk.
func TestHTTP2_TLS(t *testing.T) {
	defer ResetTestConfig()

	expected := "HTTP/2.0"

	// Certificates
	_, _, _, clientCert := genCertificate(&x509.Certificate{})
	serverCertPem, _, combinedPEM, _ := genServerCertificate()
	certID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(certID, "")

	// Upstream server supporting HTTP/2
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actual := r.Proto
		if expected != actual {
			t.Fatalf("Tyk-Upstream connection protocol is expected %s, actual %s", expected, actual)
		}

		fmt.Fprintln(w, "Hello, I am an HTTP/2 Server")

	}))
	upstream.TLS = new(tls.Config)
	upstream.TLS.NextProtos = []string{"h2"}
	upstream.StartTLS()
	defer upstream.Close()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	globalConf.ProxyEnableHttp2 = true
	globalConf.HttpServerOptions.EnableHttp2 = true
	globalConf.HttpServerOptions.SSLCertificates = []string{certID}
	globalConf.HttpServerOptions.UseSSL = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = upstream.URL
	})

	// HTTP/2 client
	http2Client := GetTLSClient(&clientCert, serverCertPem)
	http2.ConfigureTransport(http2Client.Transport.(*http.Transport))

	ts.Run(t, test.TestCase{Client: http2Client, Path: "", Code: 200, Proto: "HTTP/2.0", BodyMatch: "Hello, I am an HTTP/2 Server"})
}

func TestGRPC_TLS(t *testing.T) {
	defer ResetTestConfig()

	_, _, combinedPEM, _ := genServerCertificate()
	certID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(certID, "")

	// gRPC server
	target, s := startGRPCServer(t, nil, setupHelloSVC)
	defer target.Close()
	defer s.GracefulStop()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	globalConf.ProxyEnableHttp2 = true
	globalConf.HttpServerOptions.EnableHttp2 = true
	globalConf.HttpServerOptions.SSLCertificates = []string{certID}
	globalConf.HttpServerOptions.UseSSL = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = toTarget(t, "https", target)
	})

	address := strings.TrimPrefix(ts.URL, "https://")
	name := "Furkan"

	// gRPC client
	r := sayHelloWithGRPCClient(t, nil, nil, false, "", address, name)

	// Test result
	expected := "Hello " + name
	actual := r.Message

	if expected != actual {
		t.Fatalf("Expected %s, actual %s", expected, actual)
	}
}

func TestGRPC_MutualTLS(t *testing.T) {
	// Mutual Authentication for both downstream-tyk and tyk-upstream
	defer ResetTestConfig()

	_, _, combinedClientPEM, clientCert := genCertificate(&x509.Certificate{})
	clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])
	serverCertPem, _, combinedPEM, _ := genServerCertificate()

	certID, _ := CertificateManager.Add(combinedPEM, "") // For tyk to know downstream
	defer CertificateManager.Delete(certID, "")

	clientCertID, _ := CertificateManager.Add(combinedClientPEM, "") // For upstream to know tyk
	defer CertificateManager.Delete(clientCertID, "")

	// Protected gRPC server
	target, s := startGRPCServer(t, clientCert.Leaf, setupHelloSVC)
	defer target.Close()
	defer s.GracefulStop()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	globalConf.ProxyEnableHttp2 = true
	globalConf.HttpServerOptions.EnableHttp2 = true
	globalConf.HttpServerOptions.SSLCertificates = []string{certID}
	globalConf.HttpServerOptions.UseSSL = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.UpstreamCertificates = map[string]string{
			"*": clientCertID,
		}
		spec.Proxy.TargetURL = toTarget(t, "https", target)
	})

	address := strings.TrimPrefix(ts.URL, "https://")
	name := "Furkan"

	// gRPC client
	r := sayHelloWithGRPCClient(t, &clientCert, serverCertPem, false, "", address, name)

	// Test result
	expected := "Hello " + name
	actual := r.Message

	if expected != actual {
		t.Fatalf("Expected %s, actual %s", expected, actual)
	}
}

func TestGRPC_BasicAuthentication(t *testing.T) {
	defer ResetTestConfig()
	_, _, combinedPEM, _ := genServerCertificate()
	certID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(certID, "")

	// gRPC server
	target, s := startGRPCServer(t, nil, setupHelloSVC)
	defer target.Close()
	defer s.GracefulStop()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	globalConf.ProxyEnableHttp2 = true
	globalConf.HttpServerOptions.EnableHttp2 = true
	globalConf.HttpServerOptions.SSLCertificates = []string{certID}
	globalConf.HttpServerOptions.UseSSL = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	session := CreateStandardSession()
	session.BasicAuthData.Password = "password"
	session.AccessRights = map[string]user.AccessDefinition{"test": {APIID: "test", Versions: []string{"v1"}}}
	session.OrgID = "default"

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseBasicAuth = true
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.Proxy.TargetURL = toTarget(t, "https", target)
		spec.OrgID = "default"
	})

	address := strings.TrimPrefix(ts.URL, "https://")
	name := "Furkan"
	client := GetTLSClient(nil, nil)

	// To create key
	ts.Run(t, []test.TestCase{
		{Method: "POST", Path: "/tyk/keys/defaultuser", Data: session, AdminAuth: true, Code: 200, Client: client},
	}...)

	// gRPC client
	r := sayHelloWithGRPCClient(t, nil, nil, true, "", address, name)

	// Test result
	expected := "Hello " + name
	actual := r.Message

	if expected != actual {
		t.Fatalf("Expected %s, actual %s", expected, actual)
	}
}

func TestGRPC_TokenBasedAuthentication(t *testing.T) {
	defer ResetTestConfig()
	_, _, combinedPEM, _ := genServerCertificate()
	certID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(certID, "")

	// gRPC server
	target, s := startGRPCServer(t, nil, setupHelloSVC)
	defer target.Close()
	defer s.GracefulStop()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	globalConf.ProxyEnableHttp2 = true
	globalConf.HttpServerOptions.EnableHttp2 = true
	globalConf.HttpServerOptions.SSLCertificates = []string{certID}
	globalConf.HttpServerOptions.UseSSL = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	session := CreateStandardSession()
	session.AccessRights = map[string]user.AccessDefinition{"test": {APIID: "test", Versions: []string{"v1"}}}
	session.OrgID = "default"

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.Proxy.TargetURL = toTarget(t, "https", target)
		spec.OrgID = "default"
	})

	address := strings.TrimPrefix(ts.URL, "https://")
	name := "Furkan"
	client := GetTLSClient(nil, nil)

	// To create key
	resp, _ := ts.Run(t, []test.TestCase{
		{Method: "POST", Path: "/tyk/keys/create", Data: session, AdminAuth: true, Code: 200, Client: client},
	}...)

	// Read key
	body, _ := ioutil.ReadAll(resp.Body)
	var resMap map[string]string
	err := json.Unmarshal(body, &resMap)
	if err != nil {
		t.Fatal(err)
	}

	// gRPC client
	r := sayHelloWithGRPCClient(t, nil, nil, false, resMap["key"], address, name)

	// Test result
	expected := "Hello " + name
	actual := r.Message

	if expected != actual {
		t.Fatalf("Expected %s, actual %s", expected, actual)
	}
}

// server is used to implement helloworld.GreeterServer.
type server struct{}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	log.Printf("Received: %v", in.Name)
	return &pb.HelloReply{Message: "Hello " + in.Name}, nil
}

func startGRPCServerH2C(t *testing.T, fn func(*testing.T, *grpc.Server)) (net.Listener, *grpc.Server) {
	ls := openListener(t)
	s := grpc.NewServer()
	fn(t, s)
	go func() {
		err := s.Serve(ls)
		if err != nil {
			t.Logf("failed to serve: %v", err)
		}
	}()
	return ls, s
}

func toTarget(t *testing.T, scheme string, ls net.Listener) string {
	_, port, err := net.SplitHostPort(ls.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s://localhost:%v", scheme, port)
}

func openListener(t *testing.T) net.Listener {
	ls, err := net.Listen("tcp", ":0")
	if err != nil {
		ls, err = net.Listen("tcp", ":0")
	}
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	return ls
}

func grpcServerCreds(t *testing.T, clientCert *x509.Certificate) []grpc.ServerOption {
	cert, key, _, _ := genCertificate(&x509.Certificate{})
	certificate, _ := tls.X509KeyPair(cert, key)

	pool := x509.NewCertPool()

	tlsConfig := &tls.Config{}
	if clientCert != nil {
		tlsConfig = &tls.Config{
			ClientAuth:         tls.RequireAndVerifyClientCert,
			ClientCAs:          pool,
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{certificate},
			MaxVersion:         tls.VersionTLS12,
		}
		pool.AddCert(clientCert)
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{certificate},
			MaxVersion:         tls.VersionTLS12,
		}
	}

	creds := credentials.NewTLS(tlsConfig)
	return []grpc.ServerOption{grpc.Creds(creds)}
}

func setupHelloSVC(t *testing.T, s *grpc.Server) {
	pb.RegisterGreeterServer(s, &server{})
}

func startGRPCServer(t *testing.T, clientCert *x509.Certificate, fn func(t *testing.T, s *grpc.Server)) (net.Listener, *grpc.Server) {
	// Server
	ls := openListener(t)
	opts := grpcServerCreds(t, clientCert)
	s := grpc.NewServer(opts...)
	fn(t, s)
	go func() {
		err := s.Serve(ls)
		if err != nil {
			t.Logf("failed to serve: %v", err)
		}
	}()
	return ls, s

}

func sayHelloWithGRPCClientH2C(t *testing.T, address string, name string) *pb.HelloReply {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewGreeterClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var header metadata.MD
	r, err := c.SayHello(ctx, &pb.HelloRequest{Name: name}, grpc.Header(&header))
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}

	return r
}

func grpcCreds(cert *tls.Certificate, caCert []byte, basicAuth bool, token string) []grpc.DialOption {
	tlsConfig := &tls.Config{
		MaxVersion: tls.VersionTLS12,
	}

	if cert != nil {
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}

	if len(caCert) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
		tlsConfig.BuildNameToCertificate()
	} else {
		tlsConfig.InsecureSkipVerify = true
	}
	creds := credentials.NewTLS(tlsConfig)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if basicAuth {
		opts = append(opts, grpc.WithPerRPCCredentials(&loginCredsOrToken{
			Username: "user",
			Password: "password",
		}))
	} else if token != "" { // Token Based Authentication
		opts = append(opts, grpc.WithPerRPCCredentials(&loginCredsOrToken{
			TokenBasedAuth: true,
			Token:          token,
		}))
	}
	return opts
}

func sayHelloWithGRPCClient(t *testing.T, cert *tls.Certificate, caCert []byte, basicAuth bool, token string, address string, name string) *pb.HelloReply {
	// gRPC client
	opts := grpcCreds(cert, caCert, basicAuth, token)
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewGreeterClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := c.SayHello(ctx, &pb.HelloRequest{Name: name})
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}

	return r
}

type loginCredsOrToken struct {
	Username       string
	Password       string
	TokenBasedAuth bool
	Token          string
}

func (l *loginCredsOrToken) GetRequestMetadata(context.Context, ...string) (headers map[string]string, err error) {
	auth := l.Username + ":" + l.Password
	enc := base64.StdEncoding.EncodeToString([]byte(auth))

	headers = make(map[string]string)

	if l.TokenBasedAuth {
		headers["Authorization"] = l.Token
	} else {
		headers["Authorization"] = "Basic " + enc
	}

	return
}

func (*loginCredsOrToken) RequireTransportSecurity() bool {
	return true
}

func TestGRPC_Stream_MutualTLS(t *testing.T) {
	// Mutual Authentication for both downstream-tyk and tyk-upstream
	defer ResetTestConfig()

	_, _, combinedClientPEM, clientCert := genCertificate(&x509.Certificate{})
	clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])
	serverCertPem, _, combinedPEM, _ := genServerCertificate()

	certID, _ := CertificateManager.Add(combinedPEM, "") // For tyk to know downstream
	defer CertificateManager.Delete(certID, "")

	clientCertID, _ := CertificateManager.Add(combinedClientPEM, "") // For upstream to know tyk
	defer CertificateManager.Delete(clientCertID, "")

	// Protected gRPC server
	target, s := startGRPCServer(t, clientCert.Leaf, setupStreamSVC)
	defer target.Close()
	defer s.GracefulStop()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	globalConf.ProxyEnableHttp2 = true
	globalConf.HttpServerOptions.EnableHttp2 = true
	globalConf.HttpServerOptions.SSLCertificates = []string{certID}
	globalConf.HttpServerOptions.UseSSL = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.UpstreamCertificates = map[string]string{
			"*": clientCertID,
		}
		spec.Proxy.TargetURL = toTarget(t, "https", target)
	})

	address, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	// gRPC client
	opts := grpcCreds(&clientCert, serverCertPem, false, "")
	testGRPCStreamClient(t, address.Host, opts...)
}

func TestGRPC_Stream_TokenBasedAuthentication(t *testing.T) {
	defer ResetTestConfig()
	_, _, combinedPEM, _ := genServerCertificate()
	certID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(certID, "")

	// gRPC server
	target, s := startGRPCServer(t, nil, setupStreamSVC)
	defer target.Close()
	defer s.GracefulStop()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	globalConf.ProxyEnableHttp2 = true
	globalConf.HttpServerOptions.EnableHttp2 = true
	globalConf.HttpServerOptions.SSLCertificates = []string{certID}
	globalConf.HttpServerOptions.UseSSL = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	session := CreateStandardSession()
	session.AccessRights = map[string]user.AccessDefinition{"test": {APIID: "test", Versions: []string{"v1"}}}
	session.OrgID = "default"

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.Proxy.TargetURL = toTarget(t, "https", target)
		spec.OrgID = "default"
	})

	client := GetTLSClient(nil, nil)

	// To create key
	resp, _ := ts.Run(t, []test.TestCase{
		{Method: "POST", Path: "/tyk/keys/create", Data: session, AdminAuth: true, Code: 200, Client: client},
	}...)

	// Read key
	body, _ := ioutil.ReadAll(resp.Body)
	var resMap map[string]string
	err := json.Unmarshal(body, &resMap)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	// gRPC client
	opts := grpcCreds(nil, nil, false, resMap["key"])
	testGRPCStreamClient(t, addr.Host, opts...)
}

func TestGRPC_Stream_BasicAuthentication(t *testing.T) {
	defer ResetTestConfig()
	_, _, combinedPEM, _ := genServerCertificate()
	certID, _ := CertificateManager.Add(combinedPEM, "")
	defer CertificateManager.Delete(certID, "")

	// gRPC server
	target, s := startGRPCServer(t, nil, setupStreamSVC)
	defer target.Close()
	defer s.GracefulStop()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	globalConf.ProxyEnableHttp2 = true
	globalConf.HttpServerOptions.EnableHttp2 = true
	globalConf.HttpServerOptions.SSLCertificates = []string{certID}
	globalConf.HttpServerOptions.UseSSL = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	session := CreateStandardSession()
	session.BasicAuthData.Password = "password"
	session.AccessRights = map[string]user.AccessDefinition{"test": {APIID: "test", Versions: []string{"v1"}}}
	session.OrgID = "default"

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseBasicAuth = true
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.Proxy.TargetURL = toTarget(t, "https", target)
		spec.OrgID = "default"
	})

	client := GetTLSClient(nil, nil)

	// To create key
	ts.Run(t, []test.TestCase{
		{Method: "POST", Path: "/tyk/keys/defaultuser", Data: session, AdminAuth: true, Code: 200, Client: client},
	}...)

	addr, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	// gRPC client
	opts := grpcCreds(nil, nil, true, "")
	testGRPCStreamClient(t, addr.Host, opts...)
}

func TestGRPC_Stream_H2C(t *testing.T) {
	defer ResetTestConfig()

	var port = 6666
	EnablePort(port, "h2c")
	// gRPC server
	target, s := startGRPCServerH2C(t, setupStreamSVC)
	defer target.Close()
	defer s.GracefulStop()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "h2c_api"
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = toTarget(t, "http", target)
		spec.ListenPort = port
		spec.Protocol = "h2c"
	})

	// gRPC client
	testGRPCStreamClient(t, "localhost:6666", grpc.WithInsecure())
}

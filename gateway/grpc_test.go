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
	globalConf.ProxyEnableH2c = true
	globalConf.HttpServerOptions.EnableH2c = true
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
	s := startGRPCServerH2C(t)
	defer s.GracefulStop()

	// Tyk
	globalConf := config.Global()
	globalConf.ProxySSLInsecureSkipVerify = true
	globalConf.ProxyEnableH2c = true
	globalConf.HttpServerOptions.EnableH2c = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = "http://localhost:50051"
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
	s := startGRPCServer(t, nil)
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
		spec.Proxy.TargetURL = "https://localhost:50051"
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
	s := startGRPCServer(t, clientCert.Leaf)
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
		spec.Proxy.TargetURL = "https://localhost:50051"
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
	s := startGRPCServer(t, nil)
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
		spec.Proxy.TargetURL = "https://localhost:50051"
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
	s := startGRPCServer(t, nil)
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
		spec.Proxy.TargetURL = "https://localhost:50051"
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

func startGRPCServerH2C(t *testing.T) *grpc.Server {
	// Server
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()

	pb.RegisterGreeterServer(s, &server{})

	go func() {
		err := s.Serve(lis)
		if err != nil {
			t.Fatalf("failed to serve: %v", err)
		}
	}()

	return s
}

func startGRPCServer(t *testing.T, clientCert *x509.Certificate) *grpc.Server {
	// Server
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

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
		}
		pool.AddCert(clientCert)
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{certificate},
		}
	}

	creds := credentials.NewTLS(tlsConfig)

	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(grpc.Creds(creds))

	pb.RegisterGreeterServer(s, &server{})

	go func() {
		err := s.Serve(lis)
		if err != nil {
			t.Fatalf("failed to serve: %v", err)
		}
	}()

	return s
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

func sayHelloWithGRPCClient(t *testing.T, cert *tls.Certificate, caCert []byte, basicAuth bool, token string, address string, name string) *pb.HelloReply {
	// gRPC client
	tlsConfig := &tls.Config{}

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

package gateway

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/TykTechnologies/tyk/test"

	"github.com/TykTechnologies/tyk/config"
)

func TestTCPDial_with_service_discovery(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	service1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer service1.Close()
	msg := "whois"
	go func() {
		for {
			ls, err := service1.Accept()
			if err != nil {
				break
			}
			buf := make([]byte, len(msg))
			_, err = ls.Read(buf)
			if err != nil {
				break
			}
			ls.Write([]byte("service1"))
		}
	}()
	service2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer service1.Close()
	go func() {
		for {
			ls, err := service2.Accept()
			if err != nil {
				break
			}
			buf := make([]byte, len(msg))
			_, err = ls.Read(buf)
			if err != nil {
				break
			}
			ls.Write([]byte("service2"))
		}
	}()
	var active atomic.Value
	active.Store(0)
	sds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		list := []string{
			"tcp://" + service1.Addr().String(),
			"tcp://" + service2.Addr().String(),
		}
		idx := active.Load().(int)
		if idx == 0 {
			idx = 1
		} else {
			idx = 0
		}
		active.Store(idx)
		json.NewEncoder(w).Encode([]interface{}{
			map[string]string{
				"hostname": list[idx],
			},
		})
	}))
	defer sds.Close()

	rp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(rp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	ts.EnablePort(p, "tcp")
	address := rp.Addr().String()
	rp.Close()
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Protocol = "tcp"
		spec.Proxy.ServiceDiscovery.UseDiscoveryService = true
		spec.Proxy.ServiceDiscovery.EndpointReturnsList = true
		spec.Proxy.ServiceDiscovery.QueryEndpoint = sds.URL
		spec.Proxy.ServiceDiscovery.DataPath = "hostname"
		spec.Proxy.EnableLoadBalancing = true
		spec.ListenPort = p
		spec.Proxy.TargetURL = service1.Addr().String()
	})

	e := "service1"
	var result []string

	dial := func() string {
		l, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		_, err = l.Write([]byte("whois"))
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(e))
		_, err = l.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		return string(buf)
	}
	for i := 0; i < 4; i++ {
		if ServiceCache != nil {
			ServiceCache.Flush()
		}
		result = append(result, dial())
	}
	expect := []string{"service2", "service1", "service2", "service1"}
	if !reflect.DeepEqual(result, expect) {
		t.Errorf("expected %#v got %#v", expect, result)
	}
}

func TestTCP_missing_port(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "no -listen-port"
		spec.Protocol = "tcp"
	})
	ts.Gw.apisMu.RLock()
	n := len(ts.Gw.apiSpecs)
	ts.Gw.apisMu.RUnlock()
	if n != 0 {
		t.Errorf("expected 0 apis to be loaded got %d", n)
	}
}

// getUnusedPort returns a tcp port that is a vailable for binding.
func getUnusedPort() (int, error) {
	rp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer rp.Close()
	_, port, err := net.SplitHostPort(rp.Addr().String())
	if err != nil {
		return 0, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0, err
	}
	return p, nil
}

func TestCheckPortWhiteList(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	base := ts.Gw.GetConfig()
	cases := []struct {
		name     string
		protocol string
		port     int
		fail     bool
		wls      map[string]config.PortWhiteList
	}{
		{"gw port empty protocol", "", base.ListenPort, true, nil},
		{"gw port http protocol", "http", base.ListenPort, false, map[string]config.PortWhiteList{
			"http": {
				Ports: []int{base.ListenPort},
			},
		}},
		{"unknown tls", "tls", base.ListenPort, true, nil},
		{"unknown tcp", "tls", base.ListenPort, true, nil},
		{"whitelisted tcp", "tcp", base.ListenPort, false, map[string]config.PortWhiteList{
			"tcp": {
				Ports: []int{base.ListenPort},
			},
		}},
		{"whitelisted tls", "tls", base.ListenPort, false, map[string]config.PortWhiteList{
			"tls": {
				Ports: []int{base.ListenPort},
			},
		}},
		{"black listed tcp", "tcp", base.ListenPort, true, map[string]config.PortWhiteList{
			"tls": {
				Ports: []int{base.ListenPort},
			},
		}},
		{"blacklisted tls", "tls", base.ListenPort, true, map[string]config.PortWhiteList{
			"tcp": {
				Ports: []int{base.ListenPort},
			},
		}},
		{"whitelisted tls range", "tls", base.ListenPort, false, map[string]config.PortWhiteList{
			"tls": {
				Ranges: []config.PortRange{
					{
						From: base.ListenPort - 1,
						To:   base.ListenPort + 1,
					},
				},
			},
		}},
		{"whitelisted tcp range", "tcp", base.ListenPort, false, map[string]config.PortWhiteList{
			"tcp": {
				Ranges: []config.PortRange{
					{
						From: base.ListenPort - 1,
						To:   base.ListenPort + 1,
					},
				},
			},
		}},
		{"whitelisted http range", "http", 8090, false, map[string]config.PortWhiteList{
			"http": {
				Ranges: []config.PortRange{
					{
						From: 8000,
						To:   9000,
					},
				},
			},
		}},
	}
	for i, tt := range cases {
		t.Run(tt.name, func(ts *testing.T) {
			err := CheckPortWhiteList(tt.wls, tt.port, tt.protocol)
			if tt.fail {
				if err == nil {
					ts.Error("expected an error got nil")
				}
			} else {
				if err != nil {
					ts.Errorf("%d: expected an nil got %v", i, err)
				}
			}
		})
	}
}

func TestHTTP_custom_ports(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	echo := "Hello, world"
	us := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(echo))
	}))
	defer us.Close()
	port, err := getUnusedPort()
	if err != nil {
		t.Fatal(err)
	}
	ts.EnablePort(port, "http")
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Protocol = "http"
		spec.ListenPort = port
		spec.Proxy.TargetURL = us.URL
	})
	s := fmt.Sprintf("http://localhost:%d", port)
	w, err := http.Get(s)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Body.Close()
	b, err := ioutil.ReadAll(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	bs := string(b)
	if bs != echo {
		t.Errorf("expected %s to %s", echo, bs)
	}
}

func TestHandle404(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/existing"
		spec.UseKeylessAccess = true
	})

	_, _ = g.Run(t, []test.TestCase{
		{Path: "/existing", Code: http.StatusOK},
		{Path: "/nonexisting", Code: http.StatusNotFound, BodyMatch: http.StatusText(http.StatusNotFound)},
	}...)
}

func TestHandleSubroutes(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableStrictRoutes = true
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.UseKeylessAccess = false
		},
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/apple"
			spec.UseKeylessAccess = true
		},
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/apple/bottom"
			spec.UseKeylessAccess = false
		},
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/bob/{name:.*}"
			spec.UseKeylessAccess = true
		},
		func(spec *APISpec) {
			spec.Proxy.ListenPath = "/charlie/{name:.*}/suffix"
			spec.UseKeylessAccess = true
		},
	)
	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/", Code: http.StatusUnauthorized},
		{Path: "/app", Code: http.StatusUnauthorized},
		{Path: "/apple", Code: http.StatusOK},
		{Path: "/apple/", Code: http.StatusOK},
		{Path: "/apple/bot", Code: http.StatusOK},
		{Path: "/apple/bottom", Code: http.StatusUnauthorized},
		{Path: "/apple/bottom/", Code: http.StatusUnauthorized},
		{Path: "/apple/bottom/jeans", Code: http.StatusUnauthorized},
		{Path: "/applebottomjeans", Code: http.StatusNotFound, BodyMatch: http.StatusText(http.StatusNotFound)},
		{Path: "/apple-bottom-jeans", Code: http.StatusNotFound, BodyMatch: http.StatusText(http.StatusNotFound)},
		{Path: "/apple/bottom-jeans", Code: http.StatusNotFound, BodyMatch: http.StatusText(http.StatusNotFound)},
		{Path: "/bob", Code: http.StatusUnauthorized},
		{Path: "/bob/", Code: http.StatusOK},
		{Path: "/bob/name", Code: http.StatusOK},
		{Path: "/bob/name/surname", Code: http.StatusOK},
		{Path: "/bob/name/patronym/surname", Code: http.StatusOK},

		// This one is a particular re2/gorilla implementation detail,
		// the .* regex should match "", and .+ should match length >= 1.
		// The reality doesn't reflect the route definition.
		{Path: "/charlie//suffix/", Code: http.StatusUnauthorized},

		// Regex paths will behave as they did before
		{Path: "/charlie/name/suffix", Code: http.StatusOK},
		{Path: "/charlie/name/suffix/", Code: http.StatusOK},
		{Path: "/charlie/name/suffix/foo", Code: http.StatusOK},
		{Path: "/charlie/name/suffixfoo", Code: http.StatusOK},
		{Path: "/charlie/name/name/suffix/foo", Code: http.StatusOK},
		{Path: "/charlie/name/name/name/suffix/foo", Code: http.StatusOK},
	}...)
}

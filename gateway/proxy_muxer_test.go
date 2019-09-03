package gateway

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestTCPDial_with_service_discovery(t *testing.T) {
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
	ts := StartTest()
	defer ts.Close()
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
	address := rp.Addr().String()
	rp.Close()
	BuildAndLoadAPI(func(spec *APISpec) {
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

package gateway

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/garyburd/redigo/redis"
)

func TestConnectToDashboardWithMutualTLS(t *testing.T) {
	// TODO: setup http server mock with tls for dashboard example from: TestUpstreamMutualTLS
	// _, _, combinedClientPEM, clientCert := test.GenCertificate(&x509.Certificate{})
	// clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])
	//
	// dashboard := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	if r.URL.Path == "/system/apis" {
	// 		w.Write([]byte(`{"Status": "OK", "Nonce": "1", "Message": [{"api_definition": {}}]}`))
	// 	} else {
	// 		t.Fatal("Unknown dashboard API request", r)
	// 	}
	// }))
	//
	// // Mutual TLS protected dashboard
	// pool := x509.NewCertPool()
	// dashboard.TLS = &tls.Config{
	// 	ClientAuth:         tls.RequireAndVerifyClientCert,
	// 	ClientCAs:          pool,
	// 	InsecureSkipVerify: true,
	// }
	//
	// dashboard.StartTLS()
	// defer dashboard.Close()
}

func TestSyncAPISpecsDashboardSuccess(t *testing.T) {
	// Test Dashboard
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/system/apis" {
			w.Write([]byte(`{"Status": "OK", "Nonce": "1", "Message": [{"api_definition": {}}]}`))
		} else {
			t.Fatal("Unknown dashboard API request", r)
		}
	}))
	defer ts.Close()

	apisMu.Lock()
	apisByID = make(map[string]*APISpec)
	apisMu.Unlock()

	globalConf := config.Global()
	globalConf.UseDBAppConfigs = true
	globalConf.AllowInsecureConfigs = true
	globalConf.DBAppConfOptions.ConnectionString = ts.URL
	config.SetGlobal(globalConf)

	defer ResetTestConfig()

	var wg sync.WaitGroup
	wg.Add(1)
	msg := redis.Message{Data: []byte(`{"Command": "ApiUpdated"}`)}
	handled := func(got NotificationCommand) {
		if want := NoticeApiUpdated; got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	handleRedisEvent(msg, handled, wg.Done)

	// Since we already know that reload is queued
	ReloadTick <- time.Time{}

	// Wait for the reload to finish, then check it worked
	wg.Wait()
	apisMu.RLock()
	if len(apisByID) != 1 {
		t.Error("Should return array with one spec", apisByID)
	}
	apisMu.RUnlock()
}

func TestSyncAPISpecsDashboardJSONFailure(t *testing.T) {
	// Test Dashboard
	callNum := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/system/apis" {
			if callNum == 0 {
				w.Write([]byte(`{"Status": "OK", "Nonce": "1", "Message": [{"api_definition": {}}]}`))
			} else {
				w.Write([]byte(`{"Status": "OK", "Nonce": "1", "Message": "this is a string"`))
			}

			callNum += 1
		} else {
			t.Fatal("Unknown dashboard API request", r)
		}
	}))
	defer ts.Close()

	apisMu.Lock()
	apisByID = make(map[string]*APISpec)
	apisMu.Unlock()

	globalConf := config.Global()
	globalConf.UseDBAppConfigs = true
	globalConf.AllowInsecureConfigs = true
	globalConf.DBAppConfOptions.ConnectionString = ts.URL
	config.SetGlobal(globalConf)

	defer ResetTestConfig()

	var wg sync.WaitGroup
	wg.Add(1)
	msg := redis.Message{Data: []byte(`{"Command": "ApiUpdated"}`)}
	handled := func(got NotificationCommand) {
		if want := NoticeApiUpdated; got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	handleRedisEvent(msg, handled, wg.Done)

	// Since we already know that reload is queued
	ReloadTick <- time.Time{}

	// Wait for the reload to finish, then check it worked
	wg.Wait()
	apisMu.RLock()
	if len(apisByID) != 1 {
		t.Error("should return array with one spec", apisByID)
	}
	apisMu.RUnlock()

	// Second call

	var wg2 sync.WaitGroup
	wg2.Add(1)
	handleRedisEvent(msg, handled, wg2.Done)

	// Since we already know that reload is queued
	ReloadTick <- time.Time{}

	// Wait for the reload to finish, then check it worked
	wg2.Wait()
	apisMu.RLock()
	if len(apisByID) != 1 {
		t.Error("second call should return array with one spec", apisByID)
	}
	apisMu.RUnlock()
}

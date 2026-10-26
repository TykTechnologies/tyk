package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/model"
)

// certReportStub is a Dashboard that records the certificate reports it receives.
type certReportStub struct {
	*httptest.Server

	mu      sync.Mutex
	reports []model.CertificateReport
	headers []http.Header
	status  int
}

func newCertReportStub(t *testing.T, status int) *certReportStub {
	t.Helper()
	s := &certReportStub{status: status}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/system/node/certificates" {
			writeJSON(t, w, okResponse("node-1", "nonce-register"))
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		if s.status != http.StatusOK {
			w.WriteHeader(s.status)
			return
		}

		var report model.CertificateReport
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&report))
		s.reports = append(s.reports, report)
		s.headers = append(s.headers, r.Header.Clone())
		writeJSON(t, w, NodeResponse{Status: "OK", Nonce: "nonce-report"})
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *certReportStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reports)
}

func (s *certReportStub) last(t *testing.T) (model.CertificateReport, http.Header) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.reports)
	return s.reports[len(s.reports)-1], s.headers[len(s.headers)-1]
}

// newCertReportFixture is newTestDashboardFixture with certificate reports sent to the stub.
func newCertReportFixture(t *testing.T, dash *certReportStub, extraConf func(c *config.Config)) (*HTTPDashboardHandler, *Test) {
	t.Helper()
	h, ts := newTestDashboardFixture(t, dash.URL, extraConf)
	h.CertificatesEndpoint = dash.URL + "/system/node/certificates"
	return h, ts
}

func TestReportCertificates(t *testing.T) {
	const upstreamCertID = "5f0c1a2b3c4d5e6f708192a3" + "1111111111111111111111111111111111111111111111111111111111111111"

	t.Run("sends the certificates in use with the node's credentials", func(t *testing.T) {
		dash := newCertReportStub(t, http.StatusOK)
		h, ts := newCertReportFixture(t, dash, func(c *config.Config) {
			c.Security.Certificates.Upstream = map[string]string{"*": upstreamCertID}
		})
		defer ts.Close()

		ts.Gw.updateCertUsage(nil)
		ts.Gw.SetNodeID("node-1")
		ts.Gw.ServiceNonceMutex.Lock()
		ts.Gw.ServiceNonce = "nonce-before"
		ts.Gw.ServiceNonceMutex.Unlock()

		require.NoError(t, h.ReportCertificates())

		report, headers := dash.last(t)
		assert.Equal(t, []model.CertificateUsage{{CertID: upstreamCertID, GatewayConfig: []string{certSettingUpstream}}}, report.Certificates)
		assert.Equal(t, "test-secret", headers.Get("authorization"))
		assert.Equal(t, "node-1", headers.Get(header.XTykNodeID))
		assert.Equal(t, "nonce-before", headers.Get(header.XTykNonce))

		ts.Gw.ServiceNonceMutex.RLock()
		defer ts.Gw.ServiceNonceMutex.RUnlock()
		assert.Equal(t, "nonce-report", ts.Gw.ServiceNonce)
	})

	t.Run("sends an empty list when no certificate is used", func(t *testing.T) {
		dash := newCertReportStub(t, http.StatusOK)
		h, ts := newCertReportFixture(t, dash, nil)
		defer ts.Close()

		require.NoError(t, h.ReportCertificates())

		report, _ := dash.last(t)
		assert.NotNil(t, report.Certificates)
		assert.Empty(t, report.Certificates)
	})

	t.Run("older Dashboard: stops reporting until the Gateway registers again", func(t *testing.T) {
		dash := newCertReportStub(t, http.StatusNotFound)
		h, ts := newCertReportFixture(t, dash, nil)
		defer ts.Close()

		require.NoError(t, h.ReportCertificates(), "a 404 isn't an error")
		assert.True(t, h.certReportUnsupported.Load())

		dash.mu.Lock()
		dash.status = http.StatusOK
		dash.mu.Unlock()

		require.NoError(t, h.ReportCertificates())
		assert.Equal(t, 0, dash.count(), "no report is sent again before registering")

		require.NoError(t, h.Register(context.Background()))
		assert.Eventually(t, func() bool { return dash.count() == 1 }, 2*time.Second, 10*time.Millisecond,
			"registering clears the flag and sends a report")
		assert.False(t, h.certReportUnsupported.Load())
	})

	t.Run("other errors are returned", func(t *testing.T) {
		dash := newCertReportStub(t, http.StatusInternalServerError)
		h, ts := newCertReportFixture(t, dash, nil)
		defer ts.Close()

		assert.Error(t, h.ReportCertificates())
		assert.False(t, h.certReportUnsupported.Load())
	})
}

func TestReportCertificatesToDashboard(t *testing.T) {
	t.Run("reports after a reload when connected directly to the Dashboard", func(t *testing.T) {
		dash := newCertReportStub(t, http.StatusOK)
		_, ts := newCertReportFixture(t, dash, nil)
		defer ts.Close()

		conf := ts.Gw.GetConfig()
		conf.UseDBAppConfigs = true
		ts.Gw.SetConfig(conf)

		ts.Gw.reportCertificatesToDashboard()
		assert.Eventually(t, func() bool { return dash.count() == 1 }, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("Data Plane Gateways report through MDCB instead", func(t *testing.T) {
		dash := newCertReportStub(t, http.StatusOK)
		_, ts := newCertReportFixture(t, dash, nil)
		defer ts.Close()

		conf := ts.Gw.GetConfig()
		conf.UseDBAppConfigs = true
		conf.SlaveOptions.UseRPC = true
		ts.Gw.SetConfig(conf)

		ts.Gw.reportCertificatesToDashboard()
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, 0, dash.count())
	})

	t.Run("not connected to the Dashboard", func(t *testing.T) {
		dash := newCertReportStub(t, http.StatusOK)
		_, ts := newCertReportFixture(t, dash, nil)
		defer ts.Close()

		ts.Gw.reportCertificatesToDashboard()
		time.Sleep(200 * time.Millisecond)
		assert.Equal(t, 0, dash.count())
	})
}

func TestQueueCertificateReport_Coalesces(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			<-release // the Dashboard is slow to answer the first report
		}
		writeJSON(t, w, NodeResponse{Status: "OK"})
	}))
	defer srv.Close()

	h, ts := newTestDashboardFixture(t, srv.URL, nil)
	defer ts.Close()
	h.CertificatesEndpoint = srv.URL + "/system/node/certificates"

	h.queueCertificateReport()
	assert.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return calls == 1 }, 2*time.Second, 5*time.Millisecond)

	// Reloads while the first report is in flight queue a single report.
	for i := 0; i < 10; i++ {
		h.queueCertificateReport()
	}
	close(release)

	assert.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return calls == 2 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, calls)
}

func TestReportCertificates_NoEndpoint(t *testing.T) {
	h := &HTTPDashboardHandler{}
	assert.NoError(t, h.ReportCertificates(), "a handler without the endpoint sends nothing")
}

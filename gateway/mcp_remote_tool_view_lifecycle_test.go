package gateway

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func waitClosed(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not finish", what)
	}
}

func TestRemoteMCPToolView_CheckLifecycle(t *testing.T) {
	t.Run("processing the same spec again cancels the running check, which never overwrites the newer view", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-recheck"
		logs := recordRemoteMCPLogs(t, apiID)

		fake, _ := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`)
		var blockNext atomic.Bool
		arrived := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if blockNext.CompareAndSwap(true, false) {
				close(arrived)
				<-release
			}
			fake.ServeHTTP(w, r)
		}))
		t.Cleanup(upstream.Close)
		t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

		spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{
			annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		})
		waitForRemoteMCPToolViewCheck(t, spec)
		require.NotNil(t, spec.MCPToolView())

		blockNext.Store(true)
		ts.Gw.loadRemoteMCPToolView(spec, log.NewEntry().WithField("api_id", apiID))
		firstDone := spec.remoteMCPToolViewCheckDone()
		waitClosed(t, arrived, "first check reaching the upstream")

		ts.Gw.loadRemoteMCPToolView(spec, log.NewEntry().WithField("api_id", apiID))
		secondDone := spec.remoteMCPToolViewCheckDone()
		waitClosed(t, secondDone, "second check")
		admitted := spec.MCPToolView()
		require.NotNil(t, admitted)

		waitClosed(t, firstDone, "superseded check")
		releaseOnce.Do(func() { close(release) })
		assert.Same(t, admitted, spec.MCPToolView(), "the superseded check must not overwrite the view")
		assert.Nil(t, logs.find(logrus.WarnLevel, "applying them unchecked"), "a cancelled check is not an unreachable upstream")
	})

	t.Run("unloading the API stops a pending check without admitting the view", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-unload-pending"
		logs := recordRemoteMCPLogs(t, apiID)
		fake, upstream := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`)
		fake.block = make(chan struct{})
		t.Cleanup(func() { close(fake.block) })

		spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, []oas.TykMCPServerPrimitive{
			annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		})
		done := spec.remoteMCPToolViewCheckDone()
		require.NotNil(t, done)

		ts.Gw.BuildAndLoadAPI(func(other *APISpec) {
			other.APIID = "unrelated-api"
			other.Proxy.ListenPath = "/unrelated/"
		})
		require.Nil(t, ts.Gw.getApiSpec(apiID))

		waitClosed(t, done, "check of the unloaded API")
		assert.Nil(t, spec.MCPToolView())
		assert.Nil(t, logs.find(logrus.WarnLevel, "applying them unchecked"))
	})
}

package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

// A valid key that cannot be checked because the session store is down is
// answered with 503, not with the 403 meant for a key that does not exist.
// See https://github.com/TykTechnologies/tyk/issues/8916.
func TestAuthKey_SessionStoreUnavailable(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})

	key := CreateSession(ts.Gw)
	unknown := map[string]string{"authorization": "a-key-that-was-never-created"}
	valid := map[string]string{"authorization": key}

	t.Run("store up", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
			{Headers: valid, Code: http.StatusOK},
			{Headers: unknown, Code: http.StatusForbidden},
		}...)
	})

	t.Run("store down", func(t *testing.T) {
		// The key must not come from the local session cache, which would
		// answer without the store.
		ts.Gw.SessionCache.Flush()
		ts.Gw.StorageConnectionHandler.DisableStorage(true)
		defer ts.Gw.StorageConnectionHandler.DisableStorage(false)

		_, _ = ts.Run(t, []test.TestCase{
			{Headers: valid, Code: http.StatusServiceUnavailable, BodyNotMatch: "Access to this API has been disallowed"},
			{Headers: unknown, Code: http.StatusServiceUnavailable},
		}...)
	})

	t.Run("store back", func(t *testing.T) {
		_, _ = ts.Run(t, []test.TestCase{
			{Headers: valid, Code: http.StatusOK},
			{Headers: unknown, Code: http.StatusForbidden},
		}...)
	})
}

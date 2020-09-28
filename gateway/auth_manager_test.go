package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/v3/storage"

	"github.com/TykTechnologies/tyk/v3/config"
	"github.com/TykTechnologies/tyk/v3/test"
	"github.com/TykTechnologies/tyk/v3/user"
)

func TestAuthenticationAfterDeleteKey(t *testing.T) {
	assert := func(hashKeys bool) {
		globalConf := config.Global()
		globalConf.HashKeys = hashKeys
		config.SetGlobal(globalConf)

		ts := StartTest()
		defer ts.Close()

		api := BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})[0]

		key := CreateSession(func(s *user.SessionState) {
			s.SetAccessRights(map[string]user.AccessDefinition{api.APIID: {
				APIID: api.APIID,
			}})
		})
		deletePath := "/tyk/keys/" + key
		authHeader := map[string]string{
			"authorization": key,
		}

		ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: authHeader, Code: http.StatusOK},
			{Method: http.MethodDelete, Path: deletePath, AdminAuth: true, Code: http.StatusOK, BodyMatch: `"action":"deleted"`},
			{Path: "/get", Headers: authHeader, Code: http.StatusForbidden},
		}...)
	}

	t.Run("HashKeys=false", func(t *testing.T) {
		assert(false)
	})

	t.Run("HashKeys=true", func(t *testing.T) {
		assert(true)
	})
}

func TestAuthenticationAfterUpdateKey(t *testing.T) {
	assert := func(hashKeys bool) {
		globalConf := config.Global()
		globalConf.HashKeys = hashKeys
		config.SetGlobal(globalConf)

		ts := StartTest()
		defer ts.Close()

		api := BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})[0]

		key := generateToken("", "")

		session := CreateStandardSession()
		session.SetAccessRights(map[string]user.AccessDefinition{api.APIID: {
			APIID: api.APIID,
		}})

		GlobalSessionManager.UpdateSession(storage.HashKey(key), session, 0, config.Global().HashKeys)

		authHeader := map[string]string{
			"authorization": key,
		}

		ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: authHeader, Code: http.StatusOK},
		}...)

		session.SetAccessRights(map[string]user.AccessDefinition{"dummy": {
			APIID: "dummy",
		}})

		GlobalSessionManager.UpdateSession(storage.HashKey(key), session, 0, config.Global().HashKeys)

		ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: authHeader, Code: http.StatusForbidden},
		}...)

	}

	t.Run("HashKeys=false", func(t *testing.T) {
		assert(false)
	})

	t.Run("HashKeys=true", func(t *testing.T) {
		assert(true)
	})
}

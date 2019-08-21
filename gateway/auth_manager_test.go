package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/storage"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
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
			s.AccessRights = map[string]user.AccessDefinition{api.APIID: {
				APIID: api.APIID,
			}}
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
		session.AccessRights = map[string]user.AccessDefinition{api.APIID: {
			APIID: api.APIID,
		}}

		FallbackKeySesionManager.UpdateSession(storage.HashKey(key), session, 0, config.Global().HashKeys)

		authHeader := map[string]string{
			"authorization": key,
		}

		ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: authHeader, Code: http.StatusOK},
		}...)

		session.AccessRights = map[string]user.AccessDefinition{"dummy": {
			APIID: "dummy",
		}}

		FallbackKeySesionManager.UpdateSession(storage.HashKey(key), session, 0, config.Global().HashKeys)

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

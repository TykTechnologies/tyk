package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/storage"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestAuthenticationAfterDeleteKey(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	assert := func(hashKeys bool) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HashKeys = hashKeys
		ts.Gw.SetConfig(globalConf)

		ts := StartTest(nil)
		defer ts.Close()

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})[0]

		key := CreateSession(ts.Gw, func(s *user.SessionState) {
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
	ts := StartTest(nil)
	defer ts.Close()

	assert := func(hashKeys bool) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HashKeys = hashKeys
		ts.Gw.SetConfig(globalConf)

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})[0]

		key := ts.Gw.generateToken("", "")

		session := CreateStandardSession()
		session.SetAccessRights(map[string]user.AccessDefinition{api.APIID: {
			APIID: api.APIID,
		}})

		err := ts.Gw.GlobalSessionManager.UpdateSession(storage.HashKey(key, ts.Gw.GetConfig().HashKeys), session, 0, ts.Gw.GetConfig().HashKeys)
		if err != nil {
			t.Error("could not update session in Session Manager. " + err.Error())
		}

		authHeader := map[string]string{
			"authorization": key,
		}

		ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: authHeader, Code: http.StatusOK},
		}...)

		session.SetAccessRights(map[string]user.AccessDefinition{"dummy": {
			APIID: "dummy",
		}})

		err = ts.Gw.GlobalSessionManager.UpdateSession(storage.HashKey(key, ts.Gw.GetConfig().HashKeys), session, 0, ts.Gw.GetConfig().HashKeys)
		if err != nil {
			t.Error("could not update session in Session Manager. " + err.Error())
		}

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

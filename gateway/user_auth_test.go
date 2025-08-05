package gateway

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestBasicAuth_StandardConfiguration_Should_Work(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a simple basic auth test first - no MultiAuth, just basic auth
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "BasicAuthTest"
		spec.APIID = "basic-auth-test"
		spec.Proxy.ListenPath = "/basic-test/"
		spec.Proxy.StripListenPath = true
		spec.Proxy.TargetURL = TestHttpAny
		spec.UseBasicAuth = true
		spec.BasicAuth.DisableCaching = true
		spec.UseKeylessAccess = false // This is crucial!
		spec.OrgID = "default"
		spec.DisableRateLimit = true
		spec.DisableQuota = true
		spec.BaseIdentityProvidedBy = apidef.BasicAuthUser
	})

	// Create basic auth session - following the working test pattern
	username := "testuser"
	password := "password123"
	session := CreateStandardSession()
	session.BasicAuthData.Password = password
	session.AccessRights = map[string]user.AccessDefinition{"basic-auth-test": {APIID: "basic-auth-test", Versions: []string{"v1"}}}
	session.OrgID = "default"

	keyName := ts.Gw.generateToken("default", username)
	err := ts.Gw.GlobalSessionManager.UpdateSession(keyName, session, 60, false)
	if err != nil {
		t.Fatal("Could not update session:", err)
	}

	// Test 1: No auth headers - should fail
	ts.Run(t, test.TestCase{
		Path: "/basic-test/",
		Code: http.StatusUnauthorized,
	})

	// Test 2: Valid basic auth - should succeed
	toEncode := strings.Join([]string{username, password}, ":")
	basicAuth := base64.StdEncoding.EncodeToString([]byte(toEncode))
	ts.Run(t, test.TestCase{
		Path:    "/basic-test/",
		Code:    http.StatusOK,
		Headers: map[string]string{"Authorization": "Basic " + basicAuth},
	})

	t.Logf("✅ Basic auth working! Now let's build up to MultiAuth")
}

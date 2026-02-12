package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

import (
	"github.com/stretchr/testify/assert"
)

import (
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

type hashKeyFunction struct {
	value string
}

func (hfn hashKeyFunction) name() string {
	if hfn.value == "" {
		return "none"
	}

	return hfn.value
}

var (
	hashKeyFunctionNone      = hashKeyFunction{""}
	hashKeyFunctionMurmur64  = hashKeyFunction{"murmur64"}
	hashKeyFunctionMurmur128 = hashKeyFunction{"murmur128"}
	hashKeyFunctionSha256    = hashKeyFunction{"sha256"}
)

func TestKeyHandlerHandler(t *testing.T) {
	for _, tc := range []hashKeyFunction{
		hashKeyFunctionNone,
		hashKeyFunctionMurmur64,
		hashKeyFunctionMurmur128,
		hashKeyFunctionSha256,
	} {
		t.Run(tc.name(), func(t *testing.T) {
			runTestKeyHandler(t, tc)
		})
	}
}

func runTestKeyHandler(t *testing.T, hashFunc hashKeyFunction) {
	t.Helper()

	ts := StartTest(func(cnf *config.Config) {
		cnf.HashKeys = hashFunc != hashKeyFunctionNone
		cnf.HashKeyFunction = hashFunc.value
	})

	t.Cleanup(ts.Close)

	const keyId = "my-proper-id"
	const orgId = "some-org"

	keyDto := createKey(t, ts, keyId, orgId)

	t.Run("direct get works if provided proper org id", func(t *testing.T) {
		_, err := ts.Run(t, test.TestCase{
			Path:      fmt.Sprintf("/tyk/keys/%s?org_id=%s", keyId, orgId),
			Method:    http.MethodGet,
			Code:      http.StatusOK,
			AdminAuth: true,
		})
		assert.NoError(t, err)
	})

	t.Run("access with responded does not work if wrong org_id provided", func(t *testing.T) {
		_, err := ts.Run(t, test.TestCase{
			Path:      fmt.Sprintf("/tyk/keys/%s?org_id=%s", keyId, ""),
			Method:    http.MethodGet,
			Code:      http.StatusNotFound,
			AdminAuth: true,
		})
		assert.NoError(t, err)

		_, err = ts.Run(t, test.TestCase{
			Path:      fmt.Sprintf("/tyk/keys/%s?org_id=%s", keyId, "wrong-org-id"),
			Method:    http.MethodGet,
			Code:      http.StatusNotFound,
			AdminAuth: true,
		})
		assert.NoError(t, err)
	})

	t.Run("access with responded key works without passing org_id", func(t *testing.T) {
		_, err := ts.Run(t, test.TestCase{
			Path:      fmt.Sprintf("/tyk/keys/%s", keyDto.Key),
			Method:    http.MethodGet,
			Code:      http.StatusOK,
			AdminAuth: true,
		})
		assert.NoError(t, err)
	})
}

func createKey(t *testing.T, ts *Test, rawKey string, orgId string) *apiModifyKeySuccess {
	t.Helper()

	res, err := ts.Run(t, test.TestCase{
		Path:      fmt.Sprintf("/tyk/keys/%s", rawKey),
		Method:    http.MethodPost,
		Code:      http.StatusOK,
		AdminAuth: true,
		Data: &user.SessionState{
			OrgID: orgId,
			AccessRights: map[string]user.AccessDefinition{
				"fake_api_id": {
					APIID:   "fake_ip_id",
					APIName: "fake_api_name",
				},
			},
		},
	})

	assert.NoError(t, err)

	bData, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	defer func() {
		err := res.Body.Close()
		assert.NoError(t, err)
	}()

	var responseDto = new(apiModifyKeySuccess)

	err = json.Unmarshal(bData, responseDto)
	assert.NoError(t, err)

	return responseDto
}

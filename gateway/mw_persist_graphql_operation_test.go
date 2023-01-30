package gateway

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

const testGQLQueryCountries = `
{
  countries{
    code
  }
}
`

const testGQLQueryCountry = `
query country($code: ID!){
  country(code: $code){
    code
  }
}`

const testGQLQueryCountryCode = `
query country($countryCode: ID!){
  country(code: $countryCode){
    code
  }
}`

const testQueryContinentCode = `
query continent($code: ID!) {
  continent(code: $code){
    code
  }
}`

func TestGraphqlPersist_MatchPathInfo(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(func() {
		ts.Close()
	})

	gqlRequestCountries, err := json.Marshal(GraphQLRequest{
		Query: testGQLQueryCountries,
	})
	if err != nil {
		t.Fatal(err)
	}

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "rest-graph"
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = TestHttpAny
		spec.VersionData.NotVersioned = false
		spec.VersionData.Versions["Default"] = apidef.VersionInfo{
			Name:             "Default",
			Expires:          "3000-01-02 00:00",
			UseExtendedPaths: true,
			ExtendedPaths: apidef.ExtendedPathsSet{
				PersistGraphQL: []apidef.PersistGraphQLMeta{
					{
						Path:      "/countries",
						Operation: testGQLQueryCountries,
						Method:    "GET",
					},
					{
						Path:      "continent",
						Operation: testQueryContinentCode,
						Method:    "POST",
						Variables: map[string]interface{}{
							"code": "AF",
						},
					},
				},
			},
		}
	})

	_, err = ts.Run(
		t,
		test.TestCase{Path: "/countries", Method: "GET", BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			err := json.Unmarshal(bytes, &testResp)
			if err != nil {
				return false
			}
			return testResp.Method == "POST" && testResp.Body == string(gqlRequestCountries) && testResp.URI == "/countries"
		}},
		test.TestCase{Path: "/countries", Method: "GET", Headers: map[string]string{
			"Test-Header": "value",
		}, BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			err := json.Unmarshal(bytes, &testResp)
			if err != nil {
				return false
			}
			v, ok := testResp.Headers["Test-Header"]
			return testResp.Method == "POST" && testResp.Body == string(gqlRequestCountries) && testResp.URI == "/countries" && ok && v == "value"
		}},
		test.TestCase{Path: "/countries", Method: "POST", BodyMatchFunc: func(bytes []byte) bool {
			// graphql request shouldn't be sent due to mismatched method
			var testResp TestHttpResponse
			err := json.Unmarshal(bytes, &testResp)
			if err != nil {
				return false
			}
			return testResp.Body == ""
		}},
		test.TestCase{Path: "/continent", Method: "POST", BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			if err := json.Unmarshal(bytes, &testResp); err != nil {
				return false
			}
			// Get query and variables
			var q GraphQLRequest
			if err := json.Unmarshal([]byte(testResp.Body), &q); err != nil {
				return false
			}
			return q.Query == testQueryContinentCode && string(q.Variables) == `{"code":"AF"}` && testResp.Method == "POST"
		}},
	)
	assert.NoError(t, err)
}

func TestGraphqlPersist_Variables(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(func() {
		ts.Close()
	})
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "rest-graph"
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = TestHttpAny
		spec.EnableContextVars = true
		spec.VersionData.NotVersioned = false
		spec.VersionData.Versions["Default"] = apidef.VersionInfo{
			Name:             "Default",
			Expires:          "3000-01-02 00:00",
			UseExtendedPaths: true,
			ExtendedPaths: apidef.ExtendedPathsSet{
				PersistGraphQL: []apidef.PersistGraphQLMeta{
					{
						Path:      "/country",
						Operation: testGQLQueryCountry,
						Method:    "GET",
						Variables: map[string]interface{}{
							"code": "NG",
						},
					},
					{
						Path:      "/continent/{code}",
						Operation: testQueryContinentCode,
						Method:    "GET",
						Variables: map[string]interface{}{
							"code": "$path.code",
						},
					},
					{
						Path:      "/continent",
						Operation: testQueryContinentCode,
						Method:    "GET",
						Variables: map[string]interface{}{
							"code": "$tyk_context.headers_Code",
						},
					},
				},
			},
		}
	})

	_, err := ts.Run(t,
		test.TestCase{Path: "/country", Method: "GET", BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			if err := json.Unmarshal(bytes, &testResp); err != nil {
				return false
			}
			// Get query and variables
			var q GraphQLRequest
			if err := json.Unmarshal([]byte(testResp.Body), &q); err != nil {
				return false
			}
			return q.Query == testGQLQueryCountry && string(q.Variables) == `{"code":"NG"}` && testResp.URI == "/"
		}},
		test.TestCase{Path: "/continent", Method: "GET",
			Headers: map[string]string{
				"Code": "AF",
			},
			BodyMatchFunc: func(bytes []byte) bool {
				var testResp TestHttpResponse
				if err := json.Unmarshal(bytes, &testResp); err != nil {
					return false
				}
				// Get query and variables
				var q GraphQLRequest
				if err := json.Unmarshal([]byte(testResp.Body), &q); err != nil {
					return false
				}
				return q.Query == testQueryContinentCode && string(q.Variables) == `{"code":"AF"}` && testResp.URI == "/"
			},
		},
		test.TestCase{Path: "/continent", Method: "GET", BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			if err := json.Unmarshal(bytes, &testResp); err != nil {
				return false
			}
			// Get query and variables
			var q GraphQLRequest
			if err := json.Unmarshal([]byte(testResp.Body), &q); err != nil {
				return false
			}
			return q.Query == testQueryContinentCode && string(q.Variables) == `{"code":""}` && testResp.URI == "/"
		}},
		test.TestCase{Path: "/continent/AF", Method: "GET", BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			if err := json.Unmarshal(bytes, &testResp); err != nil {
				return false
			}
			// Get query and variables
			var q GraphQLRequest
			if err := json.Unmarshal([]byte(testResp.Body), &q); err != nil {
				return false
			}
			return q.Query == testQueryContinentCode && string(q.Variables) == `{"code":"AF"}` && testResp.URI == "/"
		}},
	)
	assert.NoError(t, err)
}

func TestGraphQLPersist_VariablesListenPath(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(func() {
		ts.Close()
	})
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "rest-graph-listen-path"
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/test/"
		spec.Proxy.TargetURL = TestHttpAny
		spec.EnableContextVars = true
		spec.VersionData.NotVersioned = false
		spec.VersionData.Versions["Default"] = apidef.VersionInfo{
			Name:             "Default",
			Expires:          "3000-01-02 00:00",
			UseExtendedPaths: true,
			ExtendedPaths: apidef.ExtendedPathsSet{
				PersistGraphQL: []apidef.PersistGraphQLMeta{
					{
						Path:      "/getCountryByCode/{countryCode}",
						Method:    "GET",
						Operation: testGQLQueryCountryCode,
						Variables: map[string]interface{}{
							"countryCode": "$path.countryCode",
						},
					},
				},
			},
		}
	})

	_, err := ts.Run(t,
		test.TestCase{Path: "/test/getCountryByCode/NG", Method: "GET", BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			if err := json.Unmarshal(bytes, &testResp); err != nil {
				return false
			}
			// Get query and variables
			var q GraphQLRequest
			if err := json.Unmarshal([]byte(testResp.Body), &q); err != nil {
				return false
			}
			return q.Query == testGQLQueryCountryCode && string(q.Variables) == `{"countryCode":"NG"}`
		}},
	)

	assert.NoError(t, err)
}

func TestGraphqlPersist_MultipleVersions(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(func() {
		ts.Close()
	})
	gqlRequestCountries, err := json.Marshal(GraphQLRequest{
		Query: testGQLQueryCountries,
	})
	assert.NoError(t, err)
	gqlRequestContinent, err := json.Marshal(GraphQLRequest{
		Query:     testQueryContinentCode,
		Variables: json.RawMessage(`{"code":"AF"}`),
	})
	assert.NoError(t, err)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "rest-graph"
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = TestHttpAny
		spec.VersionDefinition.Location = "header"
		spec.VersionDefinition.Key = "Api-Version"
		spec.EnableContextVars = true
		spec.VersionData.NotVersioned = false
		spec.VersionData.DefaultVersion = "Default"
		spec.VersionData.Versions["Default"] = apidef.VersionInfo{
			Name:    "Default",
			Expires: "3000-01-02 00:00",
		}
		spec.VersionData.Versions["version2"] = apidef.VersionInfo{
			Name:             "version_two",
			UseExtendedPaths: true,
			ExtendedPaths: apidef.ExtendedPathsSet{
				PersistGraphQL: []apidef.PersistGraphQLMeta{
					{
						Path:      "/countries",
						Method:    "GET",
						Operation: testGQLQueryCountries,
					},
				},
			},
		}
		spec.VersionData.Versions["version3"] = apidef.VersionInfo{
			Name:             "version_three",
			UseExtendedPaths: true,
			ExtendedPaths: apidef.ExtendedPathsSet{PersistGraphQL: []apidef.PersistGraphQLMeta{
				{
					Path:      "/continent",
					Method:    "GET",
					Operation: testQueryContinentCode,
					Variables: map[string]interface{}{
						"code": "AF",
					},
				},
			}},
		}
	})

	_, err = ts.Run(
		t,
		test.TestCase{Path: "/countries", Method: "GET", BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			err := json.Unmarshal(bytes, &testResp)
			if err != nil {
				return false
			}
			return testResp.Body == ""
		}},
		test.TestCase{Path: "/countries", Method: "GET", Headers: map[string]string{
			"Api-Version": "version2",
		}, BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			err := json.Unmarshal(bytes, &testResp)
			if err != nil {
				return false
			}
			return testResp.Body == string(gqlRequestCountries)
		}},
		test.TestCase{Path: "/continent", Method: "GET", Headers: map[string]string{
			"Api-Version": "version2",
		}, BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			err := json.Unmarshal(bytes, &testResp)
			if err != nil {
				return false
			}
			return testResp.Body == ""
		}},
		test.TestCase{Path: "/continent", Method: "GET", Headers: map[string]string{
			"Api-Version": "version3",
		}, BodyMatchFunc: func(bytes []byte) bool {
			var testResp TestHttpResponse
			err := json.Unmarshal(bytes, &testResp)
			if err != nil {
				return false
			}
			return testResp.Body == string(gqlRequestContinent)
		}},
	)
	assert.NoError(t, err)
}

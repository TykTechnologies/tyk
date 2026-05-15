package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

func BenchmarkProtoSessionState(b *testing.B) {
	emptySession := &user.SessionState{}
	
	largeSession := &user.SessionState{
		MetaData: map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		},
		AccessRights: map[string]user.AccessDefinition{
			"api1": {
				APIID: "api1",
				Versions: []string{"Default"},
				AllowedURLs: []user.AccessSpec{
					{URL: "/path1", Methods: []string{"GET"}},
					{URL: "/path2", Methods: []string{"POST"}},
				},
			},
		},
	}

	b.Run("Empty Session", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ProtoSessionState(emptySession)
		}
	})

	b.Run("Large Session", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ProtoSessionState(largeSession)
		}
	})
}

func BenchmarkBuildObject(b *testing.B) {
	c := &CoProcessor{
		Middleware: &CoProcessMiddleware{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
			},
		},
	}
	req, _ := http.NewRequest("GET", "http://example.com/path?query=1", nil)
	req.Header.Set("Authorization", "token")
	
	b.Run("BuildObject", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c.BuildObject(req, nil, &APISpec{APIDefinition: &apidef.APIDefinition{}})
		}
	})
}

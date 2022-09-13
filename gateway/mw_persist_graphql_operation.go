package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

// PersistGraphQLOperationMiddleware lets you convert any HTTP request into a GraphQL Operation
type PersistGraphQLOperationMiddleware struct {
	BaseMiddleware
}

func (i *PersistGraphQLOperationMiddleware) Name() string {
	return "PersistGraphQLOperationMiddleware"
}

func (i *PersistGraphQLOperationMiddleware) EnabledForSpec() bool {
	return true
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (i *PersistGraphQLOperationMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	vInfo, _ := i.Spec.Version(r)
	versionPaths := i.Spec.RxPaths[vInfo.Name]
	found, meta := i.Spec.CheckSpecMatchesStatus(r, versionPaths, PersistGraphQL)
	if !found {
		// PersistGraphQLOperationMiddleware not enabled for this endpoint
		return nil, http.StatusOK
	}
	mwSpec, _ := meta.(*apidef.PersistGraphQLMeta)
	r.Method = http.MethodPost

	_, _ = io.ReadAll(r.Body)
	defer r.Body.Close()

	type GraphQLRequest struct {
		Query     string          `json:"query"`
		Variables json.RawMessage `json:"variables"`
	}

	contextData := ctxGetData(r)
	_ = contextData

	varBytes, _ := json.Marshal(mwSpec.Variables)
	//varString := string(varBytes)

	replacers := make(map[string]int)
	paths := strings.Split(mwSpec.Path, "/")
	for i, part := range paths {
		println(i, part)
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			key := "$path." + strings.Replace(part, "{", "", -1)
			key = strings.Replace(key, "}", "", -1)
			replacers[key] = i
		}
	}

	variablesStr := i.Gw.replaceTykVariables(r, string(varBytes), false)

	requestPathParts := strings.Split(r.RequestURI, "/")
	for replacer, pathIndex := range replacers {
		variablesStr = strings.ReplaceAll(variablesStr, replacer, requestPathParts[pathIndex+1])
	}

	graphqlQuery := GraphQLRequest{
		Query:     mwSpec.Operation,
		Variables: []byte(variablesStr),
	}

	graphQLQueryBytes, _ := json.Marshal(graphqlQuery)
	newBuf := bytes.NewBuffer(graphQLQueryBytes)

	r.Body = io.NopCloser(newBuf)
	r.ContentLength = int64(newBuf.Len())
	nopCloseRequestBody(r)

	r.Header.Set("Content-Type", "application/json")

	return nil, http.StatusOK
}

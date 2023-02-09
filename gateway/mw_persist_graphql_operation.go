package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

type GraphQLRequest struct {
	Query     string          `json:"query"`
	Variables json.RawMessage `json:"variables"`
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

	_, err := io.ReadAll(r.Body)
	if err != nil {
		i.Logger().WithError(err).Error("error reading request")
		return errors.New("error reading the request"), http.StatusBadRequest
	}
	defer r.Body.Close()

	replacers := make(map[string]int)
	fullPath := fmt.Sprintf("%s/%s", strings.TrimRight(i.Spec.Proxy.ListenPath, "/"), strings.TrimLeft(mwSpec.Path, "/"))
	paths := strings.Split(fullPath, "/")
	for i, part := range paths {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			key := "$path." + strings.Replace(part, "{", "", -1)
			key = strings.Replace(key, "}", "", -1)
			replacers[key] = i
		}
	}

	varBytes, err := json.Marshal(mwSpec.Variables)
	if err != nil {
		i.Logger().WithError(err).Error("error proxying request")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	variablesStr := i.Gw.replaceTykVariables(r, string(varBytes), false)

	requestPathParts := strings.Split(r.RequestURI, "/")
	for replacer, pathIndex := range replacers {
		variablesStr = strings.ReplaceAll(variablesStr, replacer, requestPathParts[pathIndex])
	}

	graphqlQuery := GraphQLRequest{
		Query:     mwSpec.Operation,
		Variables: []byte(variablesStr),
	}

	graphQLQueryBytes, err := json.Marshal(graphqlQuery)
	if err != nil {
		i.Logger().WithError(err).Error("error proxying request")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}
	newBuf := bytes.NewBuffer(graphQLQueryBytes)

	r.Body = io.NopCloser(newBuf)
	r.ContentLength = int64(newBuf.Len())
	nopCloseRequestBody(r)

	r.Header.Set("Content-Type", "application/json")
	r.URL.Path = "/"

	return nil, http.StatusOK
}

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/pkg/astparser"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

// PersistGraphQLOperationMiddleware lets you convert any HTTP request into a GraphQL Operation
type PersistGraphQLOperationMiddleware struct {
	*BaseMiddleware
}

func (i *PersistGraphQLOperationMiddleware) Name() string {
	return "PersistGraphQLOperationMiddleware"
}

func (i *PersistGraphQLOperationMiddleware) EnabledForSpec() bool {
	for _, v := range i.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.PersistGraphQL) > 0 {
			return true
		}
	}

	return false
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

	ctxSetRequestMethod(r, r.Method)
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

	// PoC for TT-7856 starts here.
	// See TestGraphQLPersist_TT_7856.

	// 1- Parse the operation
	doc, _ := astparser.ParseGraphqlDocumentString(mwSpec.Operation)

	// 2- Parse the variables object into a map.
	variables := make(map[string]interface{})
	err = json.Unmarshal([]byte(variablesStr), &variables)
	if err != nil {
		i.Logger().WithError(err).Error("error proxying request", err)
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	// 3- Iterate over the variables, assume that the values are always in string type.
	for variable, variableValue := range variables {
		// 4- Infer the variable type from the parsed operation.
		variableType, err := inferVariableType(&doc, variable)
		if err != nil {
			i.Logger().WithError(err).Error("error proxying request", err)
			return ProxyingRequestFailedErr, http.StatusInternalServerError
		}

		// 5- Get the variable type and cast the variable value to the inferred type.
		variableTypeStr := doc.Input.ByteSliceString(variableType.Name)
		if variableTypeStr == "Int" {
			newValue, err := strconv.Atoi(variableValue.(string))
			if err != nil {
				i.Logger().WithError(err).Error("error proxying request", err)
				return ProxyingRequestFailedErr, http.StatusInternalServerError
			}
			variables[variable] = newValue
		}
	}

	// 6- Marshal the variables again
	variablesData, err := json.Marshal(variables)
	if err != nil {
		i.Logger().WithError(err).Error("error proxying request", err)
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	// PoC for TT-7856 ends here.

	graphqlQuery := GraphQLRequest{
		Query:     mwSpec.Operation,
		Variables: variablesData,
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

	ctxSetUrlRewritePath(r, r.URL.Path)
	r.URL.Path = "/"

	return nil, http.StatusOK
}

func inferVariableType(document *ast.Document, name string) (*ast.Type, error) {
	for _, variableDefinition := range document.VariableDefinitions {
		variableValue := document.VariableValues[variableDefinition.VariableValue.Ref]
		if document.Input.ByteSliceString(variableValue.Name) != name {
			continue
		}
		return &document.Types[variableDefinition.Type], nil
	}
	return nil, errors.New("variable type cannot be inferred")
}

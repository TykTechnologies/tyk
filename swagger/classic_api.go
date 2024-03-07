package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
)

func APIS(r *openapi3.Reflector) error {
	err := GetClassicApiRequest(r)
	return err
}

func GetClassicApiRequest(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/apis/{apiID}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(apidef.APIDefinition))
	oc.AddRespStructure(new(apidef.APIDefinition))
	oc.SetTags("APIs")
	oc.SetID("getApi")
	err = r.AddOperation(oc)
	return err
}

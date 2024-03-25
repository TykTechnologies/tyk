package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"
)

const reloadTag = "Hot Reload"

func ReloadApi(r *openapi3.Reflector) error {
	return addOperations(r, groupReload, singleNodeReload)
}

// Done
func groupReload(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/reload/group")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(apiStatusMessage), func(cu *openapi.ContentUnit) {
		cu.Description = "Reload the Tyk Gateway"
	})
	forbidden(oc)
	oc.SetTags(reloadTag)
	oc.SetID("hotReloadGroup")
	oc.SetSummary("Hot-reload a Tyk group")
	oc.SetDescription("To reload a whole group of Tyk nodes (without using the Dashboard or host manager). You can send an API request to a single node, this node will then send a notification through the pub/sub infrastructure to all other listening nodes (including the host manager if it is being used to manage NginX) which will then trigger a global reload.")
	return r.AddOperation(oc)
}

// Done
func singleNodeReload(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/reload")
	if err != nil {
		return err
	}
	oc.SetTags(reloadTag)
	oc.SetSummary("Hot-reload a single node")
	oc.SetDescription("Tyk is capable of reloading configurations without having to stop serving requests. This means that API configurations can be added at runtime, or even modified at runtime and those rules applied immediately without any downtime.")
	oc.SetID("hotReload")
	oc.AddRespStructure(new(apiStatusMessage), func(cu *openapi.ContentUnit) {
		cu.Description = "Reload gateway"
	})
	forbidden(oc)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{blockQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func blockQuery(description ...string) openapi3.ParameterOrRef {
	desc := "Block a response until the reload is performed. This can be useful in scripting environments like CI/CD workflows"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "block", Required: &isOptional, Description: &desc, Schema: blockSchema()}.ToParameterOrRef()
}

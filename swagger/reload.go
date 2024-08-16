package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"
)

const (
	reloadTag     = "Hot Reload"
	reloadTagDesc = `Force restart of the Gateway or whole cluster.
`
)

func ReloadApi(r *openapi3.Reflector) error {
	addTag(reloadTag, reloadTagDesc, optionalTagParameters{})
	return addOperations(r, groupReload, singleNodeReload)
}

// Done
func groupReload(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/reload/group",
		OperationID: "hotReloadGroup",
		Tag:         reloadTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.AddRespWithExample(apiStatusMessage{
		Status: "ok",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Reload the Tyk Gateway."
	})
	oc.SetID("hotReloadGroup")
	oc.SetSummary("Hot-reload a group of Tyk nodes.")
	oc.SetDescription("To reload a whole group of Tyk nodes (without using the Dashboard or host manager). You can send an API request to a single node, this node will then send a notification through the pub/sub infrastructure to all other listening nodes (including the host manager if it is being used to manage Nginx) which will then trigger a global reload.")
	return op.AddOperation()
}

// Done
func singleNodeReload(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/reload",
		OperationID: "hotReload",
		Tag:         reloadTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Hot-reload a single node.")
	oc.SetDescription("Tyk is capable of reloading configurations without having to stop serving requests. This means that API configurations can be added at runtime, or even modified at runtime and those rules applied immediately without any downtime.")
	oc.SetID("hotReload")
	op.AddRespWithExample(apiStatusMessage{
		Status: "ok",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Reload gateway."
	})
	op.AddQueryParameter("block", "Block a response until the reload is performed. This can be useful in scripting environments like CI/CD workflows.", OptionalParameterValues{
		Example: valueToInterface(false),
		Type:    openapi3.SchemaTypeBoolean,
		Enum:    []interface{}{true, false},
	})
	return op.AddOperation()
}

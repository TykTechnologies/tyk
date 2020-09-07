package datasource

import (
	"net/http"
)

type HookContext struct {
	TypeName  string
	FieldName string
}

type Hooks struct {
	PreSendHttpHook     PreSendHttpHook
	PostReceiveHttpHook PostReceiveHttpHook
}

type PreSendHttpHook interface {
	Execute(ctx HookContext, req *http.Request)
}

type PostReceiveHttpHook interface {
	Execute(ctx HookContext, resp *http.Response, body []byte)
}

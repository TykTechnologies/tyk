package apidef

// All the following symbols exists as a refactoring shim.
// They should be removed with a future release of tyk-sink
// that doesn't use the symbols anymore.

type InboundData struct {
	KeyName      string
	Value        string
	SessionState string
	Timeout      int64
	Per          int64
	Expire       int64
}

type DefRequest struct {
	OrgId   string
	Tags    []string
	LoadOAS bool
}

type GroupLoginRequest struct {
	UserKey   string
	GroupID   string
	ForceSync bool
	Node      []byte
}

type GroupKeySpaceRequest struct {
	OrgID   string
	GroupID string
}

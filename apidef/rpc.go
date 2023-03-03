package apidef

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

type NodeData struct {
	NodeID      string
	NodeVersion string
	Tags        []string
	Health      map[string]HealthCheckItem
}

type GroupKeySpaceRequest struct {
	OrgID   string
	GroupID string
}

type KeysValuesPair struct {
	Keys   []string
	Values []string
}

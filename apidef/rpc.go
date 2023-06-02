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
	NodeID      string                     `json:"node_id"`
	GroupName   string                     `json:"group_name"`
	NodeVersion string                     `json:"node_version"`
	TTL         int64                      `json:"ttl"`
	Tags        []string                   `json:"tags"`
	Health      map[string]HealthCheckItem `json:"health"`
	Stats       GWStats                    `json:"stats"`
}

type GWStats struct {
	APIsCount     int `json:"apis_count"`
	PoliciesCount int `json:"policies_count"`
}

type GroupKeySpaceRequest struct {
	OrgID   string
	GroupID string
}

type KeysValuesPair struct {
	Keys   []string
	Values []string
}

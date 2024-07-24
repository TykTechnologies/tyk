package apidef

<<<<<<< HEAD
=======
import (
	internalmodel "github.com/TykTechnologies/tyk/internal/model"
)

>>>>>>> 2ceb9d0fc... [TT-12698] Add linter to gateway to check for named scope conflicts (#6409)
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
<<<<<<< HEAD
	NodeID      string                     `json:"node_id"`
	APIKey      string                     `json:"api_key"`
	GroupID     string                     `json:"group_id"`
	NodeVersion string                     `json:"node_version"`
	TTL         int64                      `json:"ttl"`
	Tags        []string                   `json:"tags"`
	Health      map[string]HealthCheckItem `json:"health"`
	Stats       GWStats                    `json:"stats"`
=======
	NodeID          string                     `json:"node_id"`
	APIKey          string                     `json:"api_key"`
	GroupID         string                     `json:"group_id"`
	NodeVersion     string                     `json:"node_version"`
	TTL             int64                      `json:"ttl"`
	NodeIsSegmented bool                       `json:"node_is_segmented"`
	Tags            []string                   `json:"tags"`
	Health          map[string]HealthCheckItem `json:"health"`
	Stats           GWStats                    `json:"stats"`
	HostDetails     internalmodel.HostDetails  `json:"host_details"`
>>>>>>> 2ceb9d0fc... [TT-12698] Add linter to gateway to check for named scope conflicts (#6409)
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

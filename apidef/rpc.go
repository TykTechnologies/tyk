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

// HostDetails contains information about a host machine,
// including its hostname, process ID (PID), and IP address.
type HostDetails struct {
	Hostname string
	PID      int
	Address  string
}

type NodeData struct {
	NodeID          string                     `json:"node_id"`
	APIKey          string                     `json:"api_key"`
	GroupID         string                     `json:"group_id"`
	NodeVersion     string                     `json:"node_version"`
	TTL             int64                      `json:"ttl"`
	NodeIsSegmented bool                       `json:"node_is_segmented"`
	Tags            []string                   `json:"tags"`
	Health          map[string]HealthCheckItem `json:"health"`
	Stats           GWStats                    `json:"stats"`
	HostDetails     HostDetails                `json:"host_details"`
	// SyncStatus carries fingerprints of the configuration this node is
	// actually running so the control plane (MDCB) can verify data-plane
	// sync state. Nil when the node does not report sync status (older
	// gateways, or non-RPC deployments), which downstream consumers must
	// treat as "sync state unknown".
	SyncStatus *SyncStatus `json:"sync_status,omitempty"`
}

// Payload kinds used as SyncStatus.Hashes keys — one per configuration
// payload a gateway fetches over RPC and the control plane can verify.
const (
	PayloadAPIs     = "apis"
	PayloadPolicies = "policies"
)

// SyncStatus is the gateway-reported proof of which configuration payloads a
// node has fetched and applied. Hashes maps payload kind (PayloadAPIs, ...)
// to the hex-encoded SHA-256 of the exact payload bytes received over RPC, so
// the control plane can compare them against the payloads it served without
// shipping the content around. Keying by kind lets new payloads (e.g. client
// IdPs) join verification without another wire-format change.
type SyncStatus struct {
	Hashes        map[string]string `json:"hashes,omitempty"`
	LastReloadAt  int64             `json:"last_reload_at,omitempty"`
	LastReloadOK  bool              `json:"last_reload_ok,omitempty"`
	EmergencyMode bool              `json:"emergency_mode,omitempty"`
}

// LoadedAPIInfo represents a loaded API with its metadata.
type LoadedAPIInfo struct {
	APIID string `json:"api_id"`
}

// LoadedPolicyInfo represents a loaded policy with its metadata.
type LoadedPolicyInfo struct {
	PolicyID string `json:"policy_id"`
}

type GWStats struct {
	APIsCount      int                `json:"apis_count"`
	PoliciesCount  int                `json:"policies_count"`
	LoadedAPIs     []LoadedAPIInfo    `json:"loaded_apis,omitempty"`
	LoadedPolicies []LoadedPolicyInfo `json:"loaded_policies,omitempty"`
}

type GroupKeySpaceRequest struct {
	OrgID   string
	GroupID string
}

type KeysValuesPair struct {
	Keys   []string
	Values []string
}

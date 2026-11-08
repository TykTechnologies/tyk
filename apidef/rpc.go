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
	// Certificates lists the certificates the Gateway uses. Unlike LoadedAPIs it is always sent,
	// as an empty list when the Gateway uses none, so the control plane can tell such a Gateway
	// apart from one on an older version that doesn't report certificates.
	Certificates []CertificateUsage `json:"certificates"`
}

// CertificateUsage is one certificate a Gateway uses, as reported to the control plane.
type CertificateUsage struct {
	// CertID is the certificate store ID. Certificates set by file path or inline are
	// reported by their SHA-256 fingerprint (for public keys, the public key's fingerprint),
	// which is the certificate store ID without the org prefix.
	CertID string `json:"cert_id"`
	// GatewayConfig lists the Gateway configuration settings that use the certificate.
	GatewayConfig []string `json:"gateway_config,omitempty"`
	// APIIDs lists the loaded APIs that actively use the certificate.
	APIIDs []string `json:"api_ids,omitempty"`
}

// CertificateReport is the list of certificates a Gateway connected directly to the Dashboard
// sends to POST /system/node/certificates.
type CertificateReport struct {
	Certificates []CertificateUsage `json:"certificates"`
}

type GroupKeySpaceRequest struct {
	OrgID   string
	GroupID string
}

type KeysValuesPair struct {
	Keys   []string
	Values []string
}

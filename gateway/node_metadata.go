package gateway

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/model"
)

// nodeMetadata is the node description shared by the MDCB NodeData body
// (buildNodeInfo) and the Dashboard x-tyk-* registration headers
// (setHeaders), so both control planes describe the node identically.
type nodeMetadata struct {
	Version       string
	IsSegmented   bool
	Tags          []string
	APIsCount     int
	PoliciesCount int
	HostDetails   model.HostDetails
}

// nodeMetadata snapshots the current node state. HostDetails is populated by
// getHostDetails in initSystem, before any registration path runs, and
// refreshed by buildNodeInfo.
func (gw *Gateway) nodeMetadata() nodeMetadata {
	conf := gw.GetConfig()
	return nodeMetadata{
		Version:       VERSION,
		IsSegmented:   conf.DBAppConfOptions.NodeIsSegmented,
		Tags:          conf.DBAppConfOptions.Tags,
		APIsCount:     gw.apisByIDLen(),
		PoliciesCount: gw.policies.PolicyCount(),
		HostDetails:   gw.hostDetails,
	}
}

// setHeaders writes the Dashboard node metadata headers onto h. It is safe to
// call repeatedly on a reused request: values are replaced and the tags header
// is removed when there are no tags.
func (m nodeMetadata) setHeaders(h http.Header) {
	h.Set(header.XTykNodeVersion, m.Version)
	h.Set(header.XTykNodeSegmented, strconv.FormatBool(m.IsSegmented))
	if tags := strings.Join(m.Tags, ","); tags != "" {
		h.Set(header.XTykNodeTags, tags)
	} else {
		h.Del(header.XTykNodeTags)
	}
	h.Set(header.XTykAPIsCount, strconv.Itoa(m.APIsCount))
	h.Set(header.XTykPoliciesCount, strconv.Itoa(m.PoliciesCount))
	h.Set(header.XTykNodePID, strconv.Itoa(m.HostDetails.PID))
	h.Set(header.XTykNodeAddress, m.HostDetails.Address)
}

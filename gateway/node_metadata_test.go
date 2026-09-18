package gateway

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/model"
)

// nodeMetadataHeaderNames is the full set of headers this feature adds.
var nodeMetadataHeaderNames = []string{
	header.XTykNodeVersion,
	header.XTykNodeSegmented,
	header.XTykNodeTags,
	header.XTykAPIsCount,
	header.XTykPoliciesCount,
	header.XTykNodePID,
	header.XTykNodeAddress,
}

// withoutDRLNotifier disables the DRL, so StartTest's startServer does not
// launch the rate-limit notifier goroutine that reads hostDetails.Hostname
// every 2s (a test gateway always has a node ID). Tests that rewrite
// hostDetails after start, via buildNodeInfo, use it to stay race-free.
func withoutDRLNotifier(c *config.Config) {
	c.EnableRedisRollingLimiter = true
}

func TestNodeMetadata_HeaderNames(t *testing.T) {
	assert.Equal(t, "x-tyk-node-version", header.XTykNodeVersion)
	assert.Equal(t, "x-tyk-node-segmented", header.XTykNodeSegmented)
	assert.Equal(t, "x-tyk-node-tags", header.XTykNodeTags)
	assert.Equal(t, "x-tyk-apis-count", header.XTykAPIsCount)
	assert.Equal(t, "x-tyk-policies-count", header.XTykPoliciesCount)
	assert.Equal(t, "x-tyk-node-pid", header.XTykNodePID)
	assert.Equal(t, "x-tyk-node-address", header.XTykNodeAddress)
}

func TestNodeMetadata_SetHeaders(t *testing.T) {
	h := http.Header{}
	nodeMetadata{
		Version:       "v9.9.9-test",
		IsSegmented:   true,
		Tags:          []string{"a", "b"},
		APIsCount:     2,
		PoliciesCount: 1,
		HostDetails:   model.HostDetails{PID: 42, Address: "192.0.2.1"},
	}.setHeaders(h)

	assert.Equal(t, "v9.9.9-test", h.Get(header.XTykNodeVersion))
	assert.Equal(t, "true", h.Get(header.XTykNodeSegmented))
	assert.Equal(t, "a,b", h.Get(header.XTykNodeTags))
	assert.Equal(t, "2", h.Get(header.XTykAPIsCount))
	assert.Equal(t, "1", h.Get(header.XTykPoliciesCount))
	assert.Equal(t, "42", h.Get(header.XTykNodePID))
	assert.Equal(t, "192.0.2.1", h.Get(header.XTykNodeAddress))

	// The heartbeat request is reused; an empty tag set must clear the stale header.
	nodeMetadata{}.setHeaders(h)
	assert.Equal(t, "false", h.Get(header.XTykNodeSegmented))
	assert.NotContains(t, h, http.CanonicalHeaderKey(header.XTykNodeTags))
}

func TestNodeMetadata_SegmentedAndTagsFromEnv(t *testing.T) {
	// No file/genConf entry: only the env var sets these, as in the e2e profile.
	t.Setenv("TYK_GW_DBAPPCONFOPTIONS_NODEISSEGMENTED", "true")
	t.Setenv("TYK_GW_DBAPPCONFOPTIONS_TAGS", "env-a,env-b")

	ts := StartTest(nil)
	defer ts.Close()

	h := http.Header{}
	ts.Gw.nodeMetadata().setHeaders(h)
	assert.Equal(t, "true", h.Get(header.XTykNodeSegmented))
	assert.Equal(t, "env-a,env-b", h.Get(header.XTykNodeTags))
}

func TestNodeMetadata_AddressFollowsGetHostDetails(t *testing.T) {
	// A bare gateway has no listeners or goroutines, so getHostDetails can be re-run freely.
	gw := newMinimalGateway(t, config.Config{ListenAddress: "10.1.2.3"})
	gw.policies = model.NewPolicies()

	t.Run("listen address set", func(t *testing.T) {
		gw.getHostDetails()
		assert.Equal(t, "10.1.2.3", gw.nodeMetadata().HostDetails.Address)
	})

	t.Run("listen address empty falls back to first non-loopback IP", func(t *testing.T) {
		orig := getIpAddress
		t.Cleanup(func() { getIpAddress = orig })
		getIpAddress = func() ([]string, error) { return []string{"192.0.2.10", "192.0.2.11"}, nil }

		gw.SetConfig(config.Config{})
		gw.getHostDetails()
		assert.Equal(t, "192.0.2.10", gw.nodeMetadata().HostDetails.Address)
	})
}

func TestNodeMetadata_TagsHeaderBoundedSize(t *testing.T) {
	tags := make([]string, 50)
	for i := range tags {
		tags[i] = strings.Repeat("t", 32)
	}
	h := http.Header{}
	nodeMetadata{Tags: tags}.setHeaders(h)

	assert.Less(t, len(h.Get(header.XTykNodeTags)), 2048, "50 tags of 32 bytes: 1600 bytes plus 49 commas")
}

func TestNodeMetadata_ParityWithBuildNodeInfo(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		withoutDRLNotifier(globalConf)
		globalConf.DBAppConfOptions.Tags = []string{"parity-1", "parity-2"}
		globalConf.DBAppConfOptions.NodeIsSegmented = true
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) { spec.Proxy.ListenPath = "/parity/" })
	ts.CreatePolicy()

	r := &RPCStorageHandler{Gw: ts.Gw}
	var node model.NodeData
	require.NoError(t, json.Unmarshal(r.buildNodeInfo(), &node))

	h := http.Header{}
	ts.Gw.nodeMetadata().setHeaders(h)

	assert.Equal(t, node.NodeVersion, h.Get(header.XTykNodeVersion))
	assert.Equal(t, strconv.FormatBool(node.NodeIsSegmented), h.Get(header.XTykNodeSegmented))
	assert.Equal(t, strings.Join(node.Tags, ","), h.Get(header.XTykNodeTags))
	assert.Equal(t, strconv.Itoa(node.Stats.APIsCount), h.Get(header.XTykAPIsCount))
	assert.Equal(t, strconv.Itoa(node.Stats.PoliciesCount), h.Get(header.XTykPoliciesCount))
	assert.Equal(t, strconv.Itoa(node.HostDetails.PID), h.Get(header.XTykNodePID))
	assert.Equal(t, node.HostDetails.Address, h.Get(header.XTykNodeAddress))

	// Sanity: the fixture exercised real, non-zero values.
	assert.Equal(t, VERSION, h.Get(header.XTykNodeVersion))
	assert.Equal(t, strconv.Itoa(os.Getpid()), h.Get(header.XTykNodePID))
	assert.Equal(t, "1", h.Get(header.XTykAPIsCount))
	assert.Equal(t, "1", h.Get(header.XTykPoliciesCount))
	assert.Equal(t, "true", h.Get(header.XTykNodeSegmented))
	assert.Equal(t, "parity-1,parity-2", h.Get(header.XTykNodeTags))
}

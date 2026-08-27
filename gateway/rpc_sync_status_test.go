//nolint:revive
package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/TykTechnologies/gorpc"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/test"
)

func TestPayloadHashDeterministic(t *testing.T) {
	payload := `[{"api_id":"a1"}]`

	sum := sha256.Sum256([]byte(payload))
	if got := payloadHash(payload); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("payloadHash mismatch: got %s", got)
	}

	if payloadHash(payload) != payloadHash(payload) {
		t.Fatal("payloadHash must be deterministic")
	}
	if payloadHash(payload) == payloadHash(payload+" ") {
		t.Fatal("payloadHash must change when the payload changes")
	}
}

func TestRPCSyncStatusSnapshot(t *testing.T) {
	status := rpcSyncStatus{}

	// Nothing fetched yet: nothing to report.
	if status.snapshot() != nil {
		t.Fatal("snapshot must be nil before any payload is recorded")
	}

	apisPayload := `[{"api_id":"a1"}]`
	policiesPayload := `[{"_id":"p1"}]`

	status.setPayload(apidef.PayloadAPIs, apisPayload)
	status.setPayload(apidef.PayloadPolicies, policiesPayload)
	status.markReload(true)

	snap := status.snapshot()
	if snap == nil {
		t.Fatal("snapshot must not be nil after payloads are recorded")
	}
	if snap.Hashes[apidef.PayloadAPIs] != payloadHash(apisPayload) {
		t.Errorf("wrong APIs hash: %s", snap.Hashes[apidef.PayloadAPIs])
	}
	if snap.Hashes[apidef.PayloadPolicies] != payloadHash(policiesPayload) {
		t.Errorf("wrong policies hash: %s", snap.Hashes[apidef.PayloadPolicies])
	}
	if !snap.LastReloadOK || snap.LastReloadAt == 0 {
		t.Errorf("reload marker not recorded: %+v", snap)
	}
}

func TestIsUnknownRPCMethodErr(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		// Exact shapes gorpc's dispatcher returns for unregistered calls.
		{"unknown method", errors.New("gorpc.Dispatcher: unknown method [.UpdateNodeStatus]"), true},
		{"unknown service", errors.New("gorpc.Dispatcher: unknown service name [foo]"), true},
		{"unrelated error", errors.New("Cannot obtain response during timeout"), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUnknownRPCMethodErr(tc.err); got != tc.expected {
				t.Errorf("got %v, expected %v", got, tc.expected)
			}
		})
	}
}

// Old MDCB payloads have no sync_status field and new gateway payloads must
// not emit one before anything was fetched — both directions of the
// backward-compatibility contract.
func TestNodeDataSyncStatusJSONCompat(t *testing.T) {
	t.Run("legacy payload decodes with nil SyncStatus", func(t *testing.T) {
		legacy := `{"node_id":"n1","group_id":"g1"}`
		node := apidef.NodeData{}
		if err := json.Unmarshal([]byte(legacy), &node); err != nil {
			t.Fatal(err)
		}
		if node.SyncStatus != nil {
			t.Fatal("legacy payload must decode with nil SyncStatus")
		}
	})

	t.Run("sync_status omitted when not reported", func(t *testing.T) {
		data, err := json.Marshal(apidef.NodeData{NodeID: "n1"})
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		if _, present := raw["sync_status"]; present {
			t.Fatal("sync_status must be omitted when nil")
		}
	})
}

func TestDispatcherFuncs_RegistersUpdateNodeStatus(t *testing.T) {
	if _, ok := dispatcherFuncs["UpdateNodeStatus"]; !ok {
		t.Fatal("dispatcherFuncs must register UpdateNodeStatus so the gorpc client can call it")
	}
}

// TestRPCSyncStatusReportedToMDCB drives a slave gateway against a mock MDCB
// and asserts that (1) the payload fingerprints recorded during the RPC sync
// match what the mock served, and (2) the gateway reports them upstream via
// UpdateNodeStatus as a slim payload carrying the node identity.
func TestRPCSyncStatusReportedToMDCB(t *testing.T) {
	test.Flaky(t) // relies on the RPC mock harness, same as TestSyncAPISpecsRPCSuccess

	// Async login: the synchronous variant blocks gateway boot until the
	// mock answers Login, which deadlocks the harness on some hosts.
	rpc.UseSyncLoginRPC = false

	// MDCB serves APIs as MergedAPI envelopes: {"api_definition": {...}}.
	builtSpecs := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
	})
	apisPayload := jsonMarshalString([]model.MergedAPI{{APIDefinition: builtSpecs[0].APIDefinition}})
	policiesPayload := `[{"_id":"507f191e810c19729de860ea", "rate":1, "per":1}]`

	reported := make(chan []byte, 8)

	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *model.DefRequest) (string, error) {
		return apisPayload, nil
	})
	dispatcher.AddFunc("GetPolicies", func(clientAddr string, orgid string) (string, error) {
		return policiesPayload, nil
	})
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})
	dispatcher.AddFunc("UpdateNodeStatus", func(clientAddr string, nodeData []byte) error {
		select {
		case reported <- nodeData:
		default:
		}
		return nil
	})

	rpcMock, connectionString := startRPCMock(dispatcher)
	defer stopRPCMock(rpcMock)

	ts := StartSlaveGw(connectionString, "")
	defer ts.Close()

	// Login runs asynchronously; wait for it to clear emergency mode before
	// syncing, otherwise the fetch falls back to the redis backup path.
	deadline := time.Now().Add(10 * time.Second)
	for rpc.IsEmergencyMode() {
		if time.Now().After(deadline) {
			t.Fatal("RPC login never completed against the mock")
		}
		time.Sleep(50 * time.Millisecond)
	}

	if _, err := ts.Gw.syncAPISpecs(); err != nil {
		t.Fatalf("syncAPISpecs failed: %v", err)
	}
	if _, err := ts.Gw.syncPolicies(); err != nil {
		t.Fatalf("syncPolicies failed: %v", err)
	}

	snap := ts.Gw.rpcSyncStatus.snapshot()
	if snap == nil {
		t.Fatal("sync status must be recorded after RPC sync")
	}
	if snap.Hashes[apidef.PayloadAPIs] != payloadHash(apisPayload) {
		t.Errorf("APIs hash does not match served payload: %s", snap.Hashes[apidef.PayloadAPIs])
	}
	if snap.Hashes[apidef.PayloadPolicies] != payloadHash(policiesPayload) {
		t.Errorf("policies hash does not match served payload: %s", snap.Hashes[apidef.PayloadPolicies])
	}

	// Trigger the report exactly as DoReloadWithError does after a reload,
	// but synchronously so the test does not race the goroutine used in
	// production.
	handler := &RPCStorageHandler{Gw: ts.Gw}
	handler.reportNodeSyncStatus()

	select {
	case nodeData := <-reported:
		node := apidef.NodeData{}
		if err := json.Unmarshal(nodeData, &node); err != nil {
			t.Fatalf("reported node data is not valid JSON: %v", err)
		}
		if node.NodeID == "" || node.GroupID != "" && node.GroupID != ts.Gw.GetConfig().SlaveOptions.GroupID {
			t.Fatalf("report must carry the node identity, got %+v", node)
		}
		if node.SyncStatus == nil {
			t.Fatal("reported node data must include sync_status")
		}
		if node.SyncStatus.Hashes[apidef.PayloadAPIs] != payloadHash(apisPayload) {
			t.Errorf("reported APIs hash mismatch: %s", node.SyncStatus.Hashes[apidef.PayloadAPIs])
		}
		if node.SyncStatus.Hashes[apidef.PayloadPolicies] != payloadHash(policiesPayload) {
			t.Errorf("reported policies hash mismatch: %s", node.SyncStatus.Hashes[apidef.PayloadPolicies])
		}
	default:
		t.Fatal("UpdateNodeStatus was never called on the mock MDCB")
	}
}

// TestRPCSyncStatusFeatureDetection proves a new gateway stays quiet against
// an old MDCB: the first "unknown method" dispatcher error disables reporting
// for that gateway instead of surfacing errors.
func TestRPCSyncStatusFeatureDetection(t *testing.T) {
	test.Flaky(t) // relies on the RPC mock harness, same as TestSyncAPISpecsRPCSuccess

	// Async login: see TestRPCSyncStatusReportedToMDCB.
	rpc.UseSyncLoginRPC = false

	// An "old MDCB": no UpdateNodeStatus registered.
	dispatcher := gorpc.NewDispatcher()
	dispatcher.AddFunc("Login", func(clientAddr, userKey string) bool {
		return true
	})
	dispatcher.AddFunc("GetApiDefinitions", func(clientAddr string, dr *model.DefRequest) (string, error) {
		return "[]", nil
	})
	dispatcher.AddFunc("GetPolicies", func(clientAddr string, orgid string) (string, error) {
		return "[]", nil
	})

	rpcMock, connectionString := startRPCMock(dispatcher)
	defer stopRPCMock(rpcMock)

	ts := StartSlaveGw(connectionString, "")
	defer ts.Close()

	// Record something so there is a status to report.
	ts.Gw.rpcSyncStatus.setPayload(apidef.PayloadAPIs, "[]")

	handler := &RPCStorageHandler{Gw: ts.Gw}
	handler.reportNodeSyncStatus()

	if !ts.Gw.rpcSyncStatus.isReportUnsupported() {
		t.Fatal("reporting must be disabled after the old MDCB rejects UpdateNodeStatus")
	}
}

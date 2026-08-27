package gateway

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/rpc"
)

// rpcSyncStatus tracks fingerprints of the config payloads most recently
// fetched over RPC, keyed by payload kind (model.PayloadAPIs, ...). After
// each reload the gateway reports them to MDCB via the UpdateNodeStatus RPC
// so the control plane can verify this node is running the configuration it
// served.
type rpcSyncStatus struct {
	mu           sync.Mutex
	hashes       map[string]string
	lastReloadAt int64
	lastReloadOK bool
	// reportUnsupported flips to true the first time MDCB answers
	// UpdateNodeStatus with an "unknown method" dispatcher error, i.e. we
	// are talking to an MDCB that predates sync-status reporting. Reporting
	// is then skipped for the lifetime of this gateway so mixed-version
	// fleets stay quiet.
	reportUnsupported bool
}

// payloadHash returns the hex-encoded SHA-256 of a configuration payload
// exactly as received over RPC, before any decoding. Hashing the raw bytes
// avoids re-serialization ambiguity: MDCB hashes the same bytes on its side.
func payloadHash(payload string) string {
	return crypto.HashStr(payload, crypto.HashSha256)
}

func (s *rpcSyncStatus) setPayload(kind, payload string) {
	h := payloadHash(payload)
	s.mu.Lock()
	if s.hashes == nil {
		s.hashes = make(map[string]string)
	}
	s.hashes[kind] = h
	s.mu.Unlock()
}

func (s *rpcSyncStatus) markReload(ok bool) {
	s.mu.Lock()
	s.lastReloadAt = time.Now().Unix()
	s.lastReloadOK = ok
	s.mu.Unlock()
}

func (s *rpcSyncStatus) setReportUnsupported() {
	s.mu.Lock()
	s.reportUnsupported = true
	s.mu.Unlock()
}

func (s *rpcSyncStatus) isReportUnsupported() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reportUnsupported
}

// snapshot returns the current sync state as the wire model, or nil when
// nothing has been fetched over RPC yet (nothing meaningful to report).
func (s *rpcSyncStatus) snapshot() *model.SyncStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hashes) == 0 {
		return nil
	}
	hashes := make(map[string]string, len(s.hashes))
	for kind, hash := range s.hashes {
		hashes[kind] = hash
	}
	return &model.SyncStatus{
		Hashes:        hashes,
		LastReloadAt:  s.lastReloadAt,
		LastReloadOK:  s.lastReloadOK,
		EmergencyMode: rpc.IsEmergencyMode(),
	}
}

// isUnknownRPCMethodErr detects the gorpc dispatcher errors returned when the
// server has no handler registered for the requested function. The strings
// mirror gorpc dispatcher.go:342 ("unknown service name") and :349 ("unknown
// method") — the only two shapes the library produces.
func isUnknownRPCMethodErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unknown method") ||
		strings.Contains(msg, "unknown service name")
}

// buildSyncReport returns a minimal NodeData payload for UpdateNodeStatus:
// node identity plus sync status. The full stats/health blob already travels
// with every group login and MDCB patches the sync fields into its stored
// record, so re-sending everything on every reload would be wasted work.
// Returns nil when there is nothing to report yet.
func (r *RPCStorageHandler) buildSyncReport() []byte {
	status := r.Gw.rpcSyncStatus.snapshot()
	if status == nil {
		return nil
	}

	node := model.NodeData{
		NodeID:  r.Gw.GetNodeID(),
		GroupID: r.Gw.GetConfig().SlaveOptions.GroupID,
		// Counts only: the per-API/policy ID lists are the expensive part
		// of the stats blob and still refresh with every login.
		Stats: model.GWStats{
			APIsCount:     r.Gw.apisByIDLen(),
			PoliciesCount: r.Gw.policies.PolicyCount(),
		},
		SyncStatus: status,
	}

	data, err := json.Marshal(node)
	if err != nil {
		log.Error("Error marshalling sync report", err)
		return nil
	}
	return data
}

// reportNodeSyncStatus sends the node's config fingerprints to MDCB. It is
// fire-and-forget by design: failures are logged and never affect the reload
// that triggered the report.
func (r *RPCStorageHandler) reportNodeSyncStatus() {
	if r.Gw.rpcSyncStatus.isReportUnsupported() {
		return
	}

	report := r.buildSyncReport()
	if report == nil {
		return
	}

	if _, err := rpc.FuncClientSingleton("UpdateNodeStatus", report); err != nil {
		if isUnknownRPCMethodErr(err) {
			r.Gw.rpcSyncStatus.setReportUnsupported()
			log.Debug("MDCB does not support UpdateNodeStatus, disabling sync status reporting")
			return
		}
		log.WithError(err).Debug("Failed to report node sync status to MDCB")
	}
}

// reportNodeSyncStatus is deferred by DoReloadWithError so every reload —
// successful or not — reports its outcome when running as an RPC slave. The
// report runs in its own goroutine so an unreachable MDCB can never slow
// down or block a reload.
func (gw *Gateway) reportNodeSyncStatus(reloadOK bool) {
	if !gw.GetConfig().SlaveOptions.UseRPC {
		return
	}
	gw.rpcSyncStatus.markReload(reloadOK)
	go (&RPCStorageHandler{Gw: gw}).reportNodeSyncStatus()
}

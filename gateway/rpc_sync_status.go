package gateway

import (
	"github.com/sirupsen/logrus"

	"encoding/json"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/rpc"
)

// rpcSyncStatus tracks fingerprints of config payloads fetched over RPC,
// keyed by payload kind (model.PayloadAPIs, ...). Fingerprints are STAGED
// at fetch time and COMMITTED only when the reload that consumed them
// succeeds, so a payload that was fetched but never applied (parse error,
// emergency fallback to the Redis backup) is never reported as running.
type rpcSyncStatus struct {
	mu           sync.Mutex
	staged       map[string]string
	committed    map[string]string
	lastReloadAt int64
	lastReloadOK bool
	// attempted turns true on the first reload; before that there is
	// nothing meaningful to report.
	attempted bool
}

// payloadHash returns the hex-encoded SHA-256 of a configuration payload
// exactly as received over RPC, before any decoding. Hashing the raw bytes
// avoids re-serialization ambiguity: MDCB hashes the same bytes on its side.
func payloadHash(payload string) string {
	return crypto.HashStr(payload, crypto.HashSha256)
}

// setPayload stages the fingerprint of a payload as received; it becomes
// reportable only once markReload(true) commits it.
func (s *rpcSyncStatus) setPayload(kind, payload string) {
	h := payloadHash(payload)
	s.mu.Lock()
	if s.staged == nil {
		s.staged = make(map[string]string)
	}
	s.staged[kind] = h
	s.mu.Unlock()
}

// markReload records a reload outcome. On success the staged fingerprints
// are promoted to committed — they now describe the running configuration.
func (s *rpcSyncStatus) markReload(ok bool) {
	s.mu.Lock()
	s.attempted = true
	s.lastReloadAt = time.Now().Unix()
	s.lastReloadOK = ok
	if ok {
		if s.committed == nil {
			s.committed = make(map[string]string)
		}
		for kind, hash := range s.staged {
			s.committed[kind] = hash
		}
	}
	s.mu.Unlock()
}

// snapshot returns the reportable sync state — committed fingerprints only —
// or nil before the first reload attempt.
func (s *rpcSyncStatus) snapshot() *model.SyncStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.attempted {
		return nil
	}
	hashes := make(map[string]string, len(s.committed))
	for kind, hash := range s.committed {
		hashes[kind] = hash
	}
	return &model.SyncStatus{
		Hashes:        hashes,
		LastReloadAt:  s.lastReloadAt,
		LastReloadOK:  s.lastReloadOK,
		EmergencyMode: rpc.IsEmergencyMode(),
	}
}

// buildSyncReport returns a minimal NodeData payload for UpdateNodeStatus:
// node identity plus sync status. MDCB validates the identity against the
// connection's group-login binding and keeps stats/health from the login
// blob, so nothing else needs to travel here. Returns nil when there is
// nothing to report yet.
func (r *RPCStorageHandler) buildSyncReport() []byte {
	status := r.Gw.rpcSyncStatus.snapshot()
	if status == nil {
		return nil
	}

	node := model.NodeData{
		NodeID:     r.Gw.GetNodeID(),
		GroupID:    r.Gw.GetConfig().SlaveOptions.GroupID,
		SyncStatus: status,
	}

	data, err := json.Marshal(node)
	if err != nil {
		log.Error("Error marshalling sync report", err)
		return nil
	}
	return data
}

// reportNodeSyncStatus sends the node's sync report to MDCB. It is
// fire-and-forget by design: failures — including MDCBs that predate the
// UpdateNodeStatus RPC — are debug-logged and never affect the reload that
// triggered the report.
func (r *RPCStorageHandler) reportNodeSyncStatus() {
	report := r.buildSyncReport()
	if report == nil {
		return
	}

	if _, err := rpc.FuncClientSingleton("UpdateNodeStatus", report); err != nil {
		log.WithError(err).Debug("Failed to report node sync status to MDCB")
		return
	}

	status := r.Gw.rpcSyncStatus.snapshot()
	log.WithFields(logrus.Fields{
		"reload_ok":      status.LastReloadOK,
		"emergency_mode": status.EmergencyMode,
		"hashes":         status.Hashes,
	}).Info("Reported sync status to MDCB")
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

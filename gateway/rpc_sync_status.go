package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/rpc"
)

// rpcSyncStatus tracks fingerprints of the API and policy payloads most
// recently fetched over RPC. After each successful reload the gateway reports
// them to MDCB via the UpdateNodeStatus RPC so the control plane can verify
// this node is running the configuration it served.
type rpcSyncStatus struct {
	mu           sync.Mutex
	apisHash     string
	policiesHash string
	lastReloadAt int64
	lastReloadOK bool
}

// payloadHash returns the hex-encoded SHA-256 of a configuration payload
// exactly as received over RPC, before any decoding. Hashing the raw bytes
// avoids re-serialization ambiguity: MDCB hashes the same bytes on its side.
func payloadHash(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func (s *rpcSyncStatus) setAPIsPayload(payload string) {
	h := payloadHash(payload)
	s.mu.Lock()
	s.apisHash = h
	s.mu.Unlock()
}

func (s *rpcSyncStatus) setPoliciesPayload(payload string) {
	h := payloadHash(payload)
	s.mu.Lock()
	s.policiesHash = h
	s.mu.Unlock()
}

func (s *rpcSyncStatus) markReload(ok bool) {
	s.mu.Lock()
	s.lastReloadAt = time.Now().Unix()
	s.lastReloadOK = ok
	s.mu.Unlock()
}

// snapshot returns the current sync state as the wire model, or nil when
// nothing has been fetched over RPC yet (nothing meaningful to report).
func (s *rpcSyncStatus) snapshot() *model.SyncStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.apisHash == "" && s.policiesHash == "" {
		return nil
	}
	return &model.SyncStatus{
		APIsHash:      s.apisHash,
		PoliciesHash:  s.policiesHash,
		LastReloadAt:  s.lastReloadAt,
		LastReloadOK:  s.lastReloadOK,
		EmergencyMode: rpc.IsEmergencyMode(),
	}
}

// updateNodeStatusUnsupported flips to true the first time MDCB answers
// UpdateNodeStatus with an "unknown method" dispatcher error, i.e. we are
// talking to an MDCB that predates sync-status reporting. Reporting is then
// skipped for the lifetime of the process so mixed-version fleets stay quiet.
var updateNodeStatusUnsupported atomic.Bool

// isUnknownRPCMethodErr detects the gorpc dispatcher errors returned when the
// server has no handler registered for the requested function.
func isUnknownRPCMethodErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unknown method") ||
		strings.Contains(msg, "unknown function") ||
		strings.Contains(msg, "unknown service name")
}

// reportNodeSyncStatus sends the node's current state (including config
// fingerprints) to MDCB. It is fire-and-forget by design: failures are logged
// and never affect the reload that triggered the report.
func (r *RPCStorageHandler) reportNodeSyncStatus() {
	if updateNodeStatusUnsupported.Load() {
		return
	}

	nodeData := r.buildNodeInfo()
	if nodeData == nil {
		return
	}

	if _, err := rpc.FuncClientSingleton("UpdateNodeStatus", nodeData); err != nil {
		if isUnknownRPCMethodErr(err) {
			updateNodeStatusUnsupported.Store(true)
			log.Debug("MDCB does not support UpdateNodeStatus, disabling sync status reporting")
			return
		}
		log.WithError(err).Debug("Failed to report node sync status to MDCB")
	}
}

// reportNodeSyncStatus is called by the gateway after every reload when
// running as an RPC slave. The report runs in its own goroutine so an
// unreachable MDCB can never slow down or block a reload.
func (gw *Gateway) reportNodeSyncStatus(reloadOK bool) {
	if !gw.GetConfig().SlaveOptions.UseRPC {
		return
	}
	gw.rpcSyncStatus.markReload(reloadOK)
	handler := &RPCStorageHandler{Gw: gw, DoReload: gw.DoReload}
	go handler.reportNodeSyncStatus()
}

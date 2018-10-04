// Separate implementation for 386, since it has broken support for atomics.
// See https://github.com/valyala/gorpc/issues/5 for details.

// +build 386

package gorpc

import (
	"sync"
)

// Snapshot returns connection statistics' snapshot.
//
// Use stats returned from ConnStats.Snapshot() on live Client and / or Server,
// since the original stats can be updated by concurrently running goroutines.
func (cs *ConnStats) Snapshot() *ConnStats {
	cs.lock.Lock()
	snapshot := *cs
	cs.lock.Unlock()

	snapshot.lock = sync.Mutex{}
	return &snapshot
}

// Reset resets all the stats counters.
func (cs *ConnStats) Reset() {
	cs.lock.Lock()
	cs.RPCCalls = 0
	cs.RPCTime = 0
	cs.BytesWritten = 0
	cs.BytesRead = 0
	cs.WriteCalls = 0
	cs.WriteErrors = 0
	cs.ReadCalls = 0
	cs.ReadErrors = 0
	cs.DialCalls = 0
	cs.DialErrors = 0
	cs.AcceptCalls = 0
	cs.AcceptErrors = 0
	cs.lock.Unlock()
}

func (cs *ConnStats) incRPCCalls() {
	cs.lock.Lock()
	cs.RPCCalls++
	cs.lock.Unlock()
}

func (cs *ConnStats) incRPCTime(dt uint64) {
	cs.lock.Lock()
	cs.RPCTime += dt
	cs.lock.Unlock()
}

func (cs *ConnStats) addBytesWritten(n uint64) {
	cs.lock.Lock()
	cs.BytesWritten += n
	cs.lock.Unlock()
}

func (cs *ConnStats) addBytesRead(n uint64) {
	cs.lock.Lock()
	cs.BytesRead += n
	cs.lock.Unlock()
}

func (cs *ConnStats) incReadCalls() {
	cs.lock.Lock()
	cs.ReadCalls++
	cs.lock.Unlock()
}

func (cs *ConnStats) incReadErrors() {
	cs.lock.Lock()
	cs.ReadErrors++
	cs.lock.Unlock()
}

func (cs *ConnStats) incWriteCalls() {
	cs.lock.Lock()
	cs.WriteCalls++
	cs.lock.Unlock()
}

func (cs *ConnStats) incWriteErrors() {
	cs.lock.Lock()
	cs.WriteErrors++
	cs.lock.Unlock()
}

func (cs *ConnStats) incDialCalls() {
	cs.lock.Lock()
	cs.DialCalls++
	cs.lock.Unlock()
}

func (cs *ConnStats) incDialErrors() {
	cs.lock.Lock()
	cs.DialErrors++
	cs.lock.Unlock()
}

func (cs *ConnStats) incAcceptCalls() {
	cs.lock.Lock()
	cs.AcceptCalls++
	cs.lock.Unlock()
}

func (cs *ConnStats) incAcceptErrors() {
	cs.lock.Lock()
	cs.AcceptErrors++
	cs.lock.Unlock()
}

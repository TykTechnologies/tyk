package gorpc

import (
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

const (
	// DefaultConcurrency is the default number of concurrent rpc calls
	// the server can process.
	DefaultConcurrency = 8 * 1024

	// DefaultRequestTimeout is the default timeout for client request.
	DefaultRequestTimeout = 20 * time.Second

	// DefaultPendingMessages is the default number of pending messages
	// handled by Client and Server.
	DefaultPendingMessages = 32 * 1024

	// DefaultFlushDelay is the default delay between message flushes
	// on Client and Server.
	DefaultFlushDelay = -1

	// DefaultBufferSize is the default size for Client and Server buffers.
	DefaultBufferSize = 64 * 1024
)

// OnConnectFunc is a callback, which may be called by both Client and Server
// on every connection creation if assigned
// to Client.OnConnect / Server.OnConnect.
//
// remoteAddr is the address of the remote end for the established
// connection rwc.
//
// The callback must return either rwc itself or a rwc wrapper.
// The returned connection wrapper MUST send all the data to the underlying
// rwc on every Write() call, otherwise the connection will hang forever.
//
// The callback may be used for authentication/authorization and/or custom
// transport wrapping.
type OnConnectFunc func(remoteAddr string, rwc io.ReadWriteCloser) (io.ReadWriteCloser, error)

// LoggerFunc is an error logging function to pass to gorpc.SetErrorLogger().
type LoggerFunc func(format string, args ...interface{})

var errorLogger = LoggerFunc(log.Printf)

// SetErrorLogger sets the given error logger to use in gorpc.
//
// By default log.Printf is used for error logging.
func SetErrorLogger(f LoggerFunc) {
	errorLogger = f
}

// NilErrorLogger discards all error messages.
//
// Pass NilErrorLogger to SetErrorLogger() in order to suppress error log generated
// by gorpc.
func NilErrorLogger(format string, args ...interface{}) {}

func logPanic(format string, args ...interface{}) {
	errorLogger(format, args...)
	s := fmt.Sprintf(format, args...)
	panic(s)
}

var timerPool sync.Pool

func acquireTimer(timeout time.Duration) *time.Timer {
	tv := timerPool.Get()
	if tv == nil {
		return time.NewTimer(timeout)
	}

	t := tv.(*time.Timer)
	if t.Reset(timeout) {
		panic("BUG: Active timer trapped into acquireTimer()")
	}
	return t
}

func releaseTimer(t *time.Timer) {
	if !t.Stop() {
		// Collect possibly added time from the channel
		// if timer has been stopped and nobody collected its' value.
		select {
		case <-t.C:
		default:
		}
	}

	timerPool.Put(t)
}

var closedFlushChan = make(chan time.Time)

func init() {
	close(closedFlushChan)
}

func getFlushChan(t *time.Timer, flushDelay time.Duration) <-chan time.Time {
	if flushDelay <= 0 {
		return closedFlushChan
	}

	if !t.Stop() {
		// Exhaust expired timer's chan.
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(flushDelay)
	return t.C
}

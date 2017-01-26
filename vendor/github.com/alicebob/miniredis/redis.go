package miniredis

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/bsm/redeo"
)

const (
	msgWrongType        = "WRONGTYPE Operation against a key holding the wrong kind of value"
	msgInvalidInt       = "ERR value is not an integer or out of range"
	msgInvalidFloat     = "ERR value is not a valid float"
	msgInvalidMinMax    = "ERR min or max is not a float"
	msgInvalidRangeItem = "ERR min or max not valid string range item"
	msgInvalidTimeout   = "ERR timeout is not an integer or out of range"
	msgSyntaxError      = "ERR syntax error"
	msgKeyNotFound      = "ERR no such key"
	msgOutOfRange       = "ERR index out of range"
	msgInvalidCursor    = "ERR invalid cursor"
	msgXXandNX          = "ERR XX and NX options at the same time are not compatible"
	msgNegTimeout       = "ERR timeout is negative"
)

// withTx wraps the non-argument-checking part of command handling code in
// transaction logic.
func withTx(
	m *Miniredis,
	out *redeo.Responder,
	r *redeo.Request,
	cb txCmd,
) error {
	ctx := getCtx(r.Client())
	if inTx(ctx) {
		addTxCmd(ctx, cb)
		out.WriteInlineString("QUEUED")
		return nil
	}
	m.Lock()
	cb(out, ctx)
	// done, wake up anyone who waits on anything.
	m.signal.Broadcast()
	m.Unlock()
	return nil
}

// blockCmd is executed returns whether it is done
type blockCmd func(*redeo.Responder, *connCtx) bool

// blocking keeps trying a command until the callback returns true. Calls
// onTimeout after the timeout (or when we call this in a transaction).
func blocking(
	m *Miniredis,
	out *redeo.Responder,
	r *redeo.Request,
	timeout time.Duration,
	cb blockCmd,
	onTimeout func(out *redeo.Responder),
) {
	var (
		ctx = getCtx(r.Client())
		dl  *time.Timer
		dlc <-chan time.Time
	)
	if inTx(ctx) {
		addTxCmd(ctx, func(out *redeo.Responder, ctx *connCtx) {
			if !cb(out, ctx) {
				onTimeout(out)
			}
		})
		out.WriteInlineString("QUEUED")
		return
	}
	if timeout != 0 {
		dl = time.NewTimer(timeout)
		defer dl.Stop()
		dlc = dl.C
	}

	m.Lock()
	defer m.Unlock()
	for {
		done := cb(out, ctx)
		if done {
			return
		}
		// there is no cond.WaitTimeout(), so hence the the goroutine to wait
		// for a timeout
		var (
			wg     sync.WaitGroup
			wakeup = make(chan struct{}, 1)
		)
		wg.Add(1)
		go func() {
			m.signal.Wait()
			wakeup <- struct{}{}
			wg.Done()
		}()
		select {
		case <-wakeup:
		case <-dlc:
			onTimeout(out)
			m.signal.Broadcast() // to kill the wakeup go routine
			wg.Wait()
			return
		}
		wg.Wait()
	}
}

// formatFloat formats a float the way redis does (sort-of)
func formatFloat(v float64) string {
	// Format with %f and strip trailing 0s. This is the most like Redis does
	// it :(
	// .12 is the magic number where most output is the same as Redis.
	if math.IsInf(v, +1) {
		return "inf"
	}
	if math.IsInf(v, -1) {
		return "-inf"
	}
	sv := fmt.Sprintf("%.12f", v)
	for strings.Contains(sv, ".") {
		if sv[len(sv)-1] != '0' {
			break
		}
		// Remove trailing 0s.
		sv = sv[:len(sv)-1]
		// Ends with a '.'.
		if sv[len(sv)-1] == '.' {
			sv = sv[:len(sv)-1]
			break
		}
	}
	return sv
}

// redisRange gives Go offsets for something l long with start/end in
// Redis semantics. Both start and end can be negative.
// Used for string range and list range things.
// The results can be used as: v[start:end]
// Note that GETRANGE (on a string key) never returns an empty string when end
// is a large negative number.
func redisRange(l, start, end int, stringSymantics bool) (int, int) {
	if start < 0 {
		start = l + start
		if start < 0 {
			start = 0
		}
	}
	if start > l {
		start = l
	}

	if end < 0 {
		end = l + end
		if end < 0 {
			end = -1
			if stringSymantics {
				end = 0
			}
		}
	}
	end++ // end argument is inclusive in Redis.
	if end > l {
		end = l
	}

	if end < start {
		return 0, 0
	}
	return start, end
}

// matchKeys filters only matching keys.
// Will return an empty list on invalid match expression.
func matchKeys(keys []string, match string) []string {
	re := patternRE(match)
	if re == nil {
		// Special case, the given pattern won't match anything / is
		// invalid.
		return nil
	}
	res := []string{}
	for _, k := range keys {
		if !re.MatchString(k) {
			continue
		}
		res = append(res, k)
	}
	return res
}

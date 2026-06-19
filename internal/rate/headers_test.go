package rate

import (
	"math"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"
)

// Verifies: SW-REQ-011
// SW-REQ-011:nominal:nominal
func Test_HeaderSender(t *testing.T) {
	t.Run("NewSenderFactory", func(t *testing.T) {
		t.Run("create quota sender", func(t *testing.T) {
			s := NewSenderFactory("")(http.Header{})
			assert.IsType(t, &quotaSender{}, s)

			s = NewSenderFactory("dummy data")(http.Header{})
			assert.IsType(t, &quotaSender{}, s)

			s = NewSenderFactory("quotas")(http.Header{})
			assert.IsType(t, &quotaSender{}, s)
		})

		t.Run("create rate limit sender", func(t *testing.T) {
			s := NewSenderFactory("rate_limits")(http.Header{})
			assert.IsType(t, &rateLimitSender{}, s)
		})
	})
}

// Verifies: SW-REQ-011
// SW-REQ-011:error_handling:negative
func Test_quotaSender(t *testing.T) {
	t.Run("SendRateLimits", func(t *testing.T) {
		t.Run("does nothing and dont fails", func(t *testing.T) {
			assert.NotPanics(t, func() {
				dst := http.Response{}
				qs := &quotaSender{hdr: dst.Header}
				qs.SendRateLimits(Stats{})
			})
		})
	})

	t.Run("SendQuotas", func(t *testing.T) {
		t.Run("sends zero quota headers for nil session", func(t *testing.T) {
			hdr := http.Header{}
			qs := &quotaSender{hdr: hdr}

			qs.SendQuotas(nil, "")

			assert.Equal(t, "0", hdr.Get(header.XRateLimitLimit))
			assert.Equal(t, "0", hdr.Get(header.XRateLimitRemaining))
			assert.Equal(t, "0", hdr.Get(header.XRateLimitReset))
		})

		t.Run("preserves int64 quota values without native int narrowing", func(t *testing.T) {
			hdr := http.Header{}
			qs := &quotaSender{hdr: hdr}
			session := &user.SessionState{
				QuotaMax:       math.MaxInt64,
				QuotaRemaining: math.MaxInt64 - 1,
				QuotaRenews:    math.MaxInt64 - 2,
			}

			qs.SendQuotas(session, "")

			assert.Equal(t, strconv.FormatInt(math.MaxInt64, 10), hdr.Get(header.XRateLimitLimit))
			assert.Equal(t, strconv.FormatInt(math.MaxInt64-1, 10), hdr.Get(header.XRateLimitRemaining))
			assert.Equal(t, strconv.FormatInt(math.MaxInt64-2, 10), hdr.Get(header.XRateLimitReset))
		})
	})
}

// Verifies: SW-REQ-011
// SW-REQ-011:nominal:nominal
// SW-REQ-011:boundary:boundary
func Test_rateLimitSender(t *testing.T) {
	t.Run("SendQuotas", func(t *testing.T) {
		t.Run("clears quota headers", func(t *testing.T) {
			hdr := http.Header{}
			hdr.Set(header.XRateLimitLimit, "100")
			hdr.Set(header.XRateLimitRemaining, "50")
			hdr.Set(header.XRateLimitReset, "123")
			rls := &rateLimitSender{hdr: hdr}

			rls.SendQuotas(nil, "")

			assert.Empty(t, hdr.Get(header.XRateLimitLimit))
			assert.Empty(t, hdr.Get(header.XRateLimitRemaining))
			assert.Empty(t, hdr.Get(header.XRateLimitReset))
		})
	})

	t.Run("SendRateLimits", func(t *testing.T) {
		t.Run("sends rate limits and formats reset as unix timestamp", func(t *testing.T) {
			assert.NotPanics(t, func() {
				hdr := http.Header{}
				rls := &rateLimitSender{hdr: hdr}

				rls.SendRateLimits(Stats{
					Limit:     200,
					Remaining: 100,
					Reset:     5 * time.Second,
				})

				assert.Equal(t, "200", hdr.Get(header.XRateLimitLimit))
				assert.Equal(t, "100", hdr.Get(header.XRateLimitRemaining))

				resetStr := hdr.Get(header.XRateLimitReset)
				resetInt, err := strconv.ParseInt(resetStr, 10, 64)
				require.NoError(t, err)

				expectedReset := time.Now().Add(time.Second * 5).Unix()
				assert.InDelta(t, expectedReset, resetInt, 1)
			})
		})

		t.Run("updates remaining header to 0 if value is negative number", func(t *testing.T) {
			assert.NotPanics(t, func() {
				hdr := http.Header{}
				rls := &rateLimitSender{hdr: hdr}

				rls.SendRateLimits(Stats{
					Limit:     200,
					Remaining: -1,
					Reset:     5 * time.Second,
				})

				assert.Equal(t, "200", hdr.Get(header.XRateLimitLimit))
				assert.Equal(t, "0", hdr.Get(header.XRateLimitRemaining))
			})
		})
	})
}

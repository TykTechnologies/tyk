package rate

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/header"
)

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
}

func Test_rateLimitSender(t *testing.T) {
	t.Run("SendQuotas", func(t *testing.T) {
		t.Run("sends quotas and creates headers map headers", func(t *testing.T) {
			assert.NotPanics(t, func() {
				dst := http.Response{}
				qs := &rateLimitSender{hdr: dst.Header}
				qs.SendQuotas(nil, "")
				assert.Nil(t, dst.Header)
			})
		})
	})

	t.Run("SendRateLimits", func(t *testing.T) {
		t.Run("sends quotas and creates headers map headers", func(t *testing.T) {
			assert.NotPanics(t, func() {
				hdr := http.Header{}
				rls := &rateLimitSender{hdr: hdr}

				rls.SendRateLimits(Stats{
					Limit:     200,
					Remaining: 100,
					Reset:     time.Second,
				})

				assert.Equal(t, "200", hdr.Get(header.XRateLimitLimit))
				assert.Equal(t, "100", hdr.Get(header.XRateLimitRemaining))
				assert.Equal(t, "1", hdr.Get(header.XRateLimitReset))
			})
		})
	})
}

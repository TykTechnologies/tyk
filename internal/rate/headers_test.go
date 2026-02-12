package rate

import (
	"net/http"
	"net/textproto"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/header"
)

func Test_HeaderSender(t *testing.T) {
	t.Run("NewSender", func(t *testing.T) {
		t.Run("create quota sender", func(t *testing.T) {
			s := NewSender("")
			assert.IsType(t, &quotaSender{}, s)

			s = NewSender("dummy data")
			assert.IsType(t, &quotaSender{}, s)

			s = NewSender("quotas")
			assert.IsType(t, &quotaSender{}, s)
		})

		t.Run("create rate limit sender", func(t *testing.T) {
			s := NewSender("rate_limits")
			assert.IsType(t, &rateLimitSender{}, s)
		})
	})
}

func Test_quotaSender(t *testing.T) {
	t.Run("SendQuotas", func(t *testing.T) {
		t.Run("sends quotas and creates headers map headers", func(t *testing.T) {
			dst := http.Response{}
			qs := &quotaSender{}
			qs.SendQuotas(&dst, nil, "")

			assert.NotNil(t, dst.Header)
			assert.Contains(t, dst.Header, textproto.CanonicalMIMEHeaderKey(header.XRateLimitLimit))
			assert.Contains(t, dst.Header, textproto.CanonicalMIMEHeaderKey(header.XRateLimitRemaining))
			assert.Contains(t, dst.Header, textproto.CanonicalMIMEHeaderKey(header.XRateLimitReset))
		})
	})

	t.Run("SendRateLimits", func(t *testing.T) {
		t.Run("does nothing and dont fails", func(t *testing.T) {
			assert.NotPanics(t, func() {
				qs := &quotaSender{}
				qs.SendRateLimits(nil, Limits{})
			})
		})
	})
}

func Test_rateLimitSender(t *testing.T) {
	t.Run("SendQuotas", func(t *testing.T) {
		t.Run("sends quotas and creates headers map headers", func(t *testing.T) {
			assert.NotPanics(t, func() {
				dst := http.Response{}
				qs := &rateLimitSender{}
				qs.SendQuotas(&dst, nil, "")
				assert.Nil(t, dst.Header)
			})
		})
	})

	t.Run("SendRateLimits", func(t *testing.T) {
		t.Run("sends quotas and creates headers map headers", func(t *testing.T) {
			assert.NotPanics(t, func() {
				rls := &rateLimitSender{}

				hdr := http.Header{}

				rls.SendRateLimits(hdr, Limits{
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

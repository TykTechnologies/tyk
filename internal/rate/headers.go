package rate

import (
	"net/http"
	"strconv"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"
)

//go:generate go tool mockgen -typed -source=./headers.go -destination=headers_mock.gen.go -package rate HeaderSender

type (
	HeaderSender interface {
		SendQuotas(response *http.Response, session *user.SessionState, apiId string)
		SendRateLimits(http.Header, Limits)
	}

	Limits struct {
		Reset     time.Duration
		Limit     uint
		Per       uint
		Remaining uint
	}

	quotaSender struct{}

	rateLimitSender struct{}
)

func NewSender(typ config.RateLimitHeadersSource) HeaderSender {
	switch typ {
	case config.RateLimitHeadersSourceRateLimit:
		return &rateLimitSender{}
	case config.RateLimitHeadersSourceQuota:
		fallthrough
	default:
		return &quotaSender{}
	}
}

func (q *quotaSender) SendRateLimits(_ http.Header, _ Limits) {}
func (q *quotaSender) SendQuotas(dst *http.Response, session *user.SessionState, apiId string) {
	quotaMax, quotaRemaining, quotaRenews := int64(0), int64(0), int64(0)

	if session != nil {
		quotaMax, quotaRemaining, _, quotaRenews = session.GetQuotaLimitByAPIID(apiId)
	}

	if dst.Header == nil {
		dst.Header = http.Header{}
	}

	dst.Header.Set(header.XRateLimitLimit, strconv.Itoa(int(quotaMax)))
	dst.Header.Set(header.XRateLimitRemaining, strconv.Itoa(int(quotaRemaining)))
	dst.Header.Set(header.XRateLimitReset, strconv.Itoa(int(quotaRenews)))
}

func (r *rateLimitSender) SendQuotas(_ *http.Response, _ *user.SessionState, _ string) {}
func (r *rateLimitSender) SendRateLimits(hdr http.Header, limits Limits) {
	hdr.Set(header.XRateLimitLimit, strconv.Itoa(int(limits.Limit)))
	hdr.Set(header.XRateLimitRemaining, strconv.Itoa(int(limits.Remaining)))
	hdr.Set(header.XRateLimitReset, strconv.Itoa(int(limits.Reset.Seconds())))
}

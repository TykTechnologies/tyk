package rate

import (
	"net/http"
	"strconv"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"
)

///go:generate go tool mockgen -typed -source=./headers.go -destination=headers_mock.gen.go -package rate HeaderSender

type (
	HeaderSenderFactory func(http.Header) HeaderSender

	HeaderSender interface {
		SendQuotas(session *user.SessionState, apiId string)
		SendRateLimits(stats Stats)
	}

	quotaSender struct {
		hdr http.Header
	}

	rateLimitSender struct {
		hdr http.Header
	}
)

func NewSenderFactory(typ config.RateLimitHeadersSource) HeaderSenderFactory {
	return func(hdr http.Header) HeaderSender {
		switch typ {
		case config.RateLimitHeadersSourceRateLimit:
			return &rateLimitSender{hdr: hdr}
		case config.RateLimitHeadersSourceQuota:
			fallthrough
		default:
			return &quotaSender{hdr: hdr}
		}
	}
}

func (q *quotaSender) SendRateLimits(_ Stats) {}
func (q *quotaSender) SendQuotas(session *user.SessionState, apiId string) {
	quotaMax, quotaRemaining, quotaRenews := int64(0), int64(0), int64(0)

	if session != nil {
		quotaMax, quotaRemaining, _, quotaRenews = session.GetQuotaLimitByAPIID(apiId)
	}

	q.hdr.Set(header.XRateLimitLimit, strconv.Itoa(int(quotaMax)))
	q.hdr.Set(header.XRateLimitRemaining, strconv.Itoa(int(quotaRemaining)))
	q.hdr.Set(header.XRateLimitReset, strconv.Itoa(int(quotaRenews)))
}

func (r *rateLimitSender) SendQuotas(_ *user.SessionState, _ string) {}
func (r *rateLimitSender) SendRateLimits(limits Stats) {
	r.hdr.Set(header.XRateLimitLimit, strconv.Itoa(limits.Limit))
	r.hdr.Set(header.XRateLimitRemaining, strconv.Itoa(limits.Remaining))
	r.hdr.Set(header.XRateLimitReset, strconv.Itoa(int(limits.Reset.Seconds())))
}

func NewFakeHeaderSender() *FakeHeaderSender {
	return &FakeHeaderSender{}
}

type FakeHeaderSender struct{}

func (r *FakeHeaderSender) SendQuotas(_ *user.SessionState, _ string) {}
func (r *FakeHeaderSender) SendRateLimits(_ Stats)                    {}

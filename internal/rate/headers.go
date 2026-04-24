package rate

import (
	"net/http"
	"strconv"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/user"
)

type (
	HeaderSenderFactory func(http.Header) HeaderSender

	// HeaderSender handles the injection of rate limit and quota headers into HTTP responses.
	//
	// The injection of these headers happens at two different points in the request lifecycle
	// to preserve backward compatibility:
	//
	// 1. SendRateLimits is called early in the middleware chain (e.g., SessionLimiter.ForwardMessage).
	//    This ensures that rate limit headers are included even on blocked requests (429 Too Many Requests),
	//    which is the correct and expected behavior for rate limiting.
	//
	// 2. SendQuotas is called late in the middleware chain (e.g., ReverseProxy.HandleResponse, mw_redis_cache.go).
	//    Historically, quota headers were only injected after a successful proxy to the upstream.
	//    To maintain strict backward compatibility, we preserve this legacy behavior so that blocked requests
	//    (e.g., 403 Quota Exceeded) do not receive quota headers.
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

func NewSenderFactory(typ config.RateLimitSource) HeaderSenderFactory {
	return func(hdr http.Header) HeaderSender {
		switch typ {
		case config.SourceRateLimits:
			return &rateLimitSender{hdr: hdr}
		case config.SourceQuotas:
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

// SendQuotas clears any rate limit headers that may have been injected by the upstream.
func (r *rateLimitSender) SendQuotas(_ *user.SessionState, _ string) {
	r.hdr.Del(header.XRateLimitLimit)
	r.hdr.Del(header.XRateLimitRemaining)
	r.hdr.Del(header.XRateLimitReset)
}
func (r *rateLimitSender) SendRateLimits(limits Stats) {
	r.hdr.Set(header.XRateLimitLimit, strconv.Itoa(limits.Limit))

	// The value of the Remaining header must be a non-negative integer.
	// Some rate limiters (like the Sentinel rate limiter) do not track exact remaining
	// tokens and return -1. To ensure the header is always present and valid for clients,
	// we default any negative values to 0.
	remaining := limits.Remaining
	if remaining < 0 {
		remaining = 0
	}
	r.hdr.Set(header.XRateLimitRemaining, strconv.Itoa(remaining))

	// HTTP rate limit standards expect UNIX timestamps (seconds since epoch)
	// for client compatibility and to match industry conventions.
	resetTime := time.Now().Add(limits.Reset).Unix()
	r.hdr.Set(header.XRateLimitReset, strconv.FormatInt(resetTime, 10))
}

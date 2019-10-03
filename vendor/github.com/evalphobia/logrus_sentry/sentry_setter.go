package logrus_sentry

import (
	"github.com/getsentry/raven-go"
)

// SetDefaultLoggerName sets default logger name tag.
func (hook *SentryHook) SetDefaultLoggerName(name string) {
	hook.client.SetDefaultLoggerName(name)
}

// SetEnvironment sets environment tag.
func (hook *SentryHook) SetEnvironment(environment string) {
	hook.client.SetEnvironment(environment)
}

// SetHttpContext sets http client.
func (hook *SentryHook) SetHttpContext(h *raven.Http) {
	hook.client.SetHttpContext(h)
}

// SetIgnoreErrors sets ignoreErrorsRegexp.
func (hook *SentryHook) SetIgnoreErrors(errs ...string) error {
	return hook.client.SetIgnoreErrors(errs)
}

// SetIncludePaths sets includePaths.
func (hook *SentryHook) SetIncludePaths(p []string) {
	hook.client.SetIncludePaths(p)
}

// SetRelease sets release tag.
func (hook *SentryHook) SetRelease(release string) {
	hook.client.SetRelease(release)
}

// SetSampleRate sets sampling rate.
func (hook *SentryHook) SetSampleRate(rate float32) error {
	return hook.client.SetSampleRate(rate)
}

// SetTagsContext sets tags.
func (hook *SentryHook) SetTagsContext(t map[string]string) {
	hook.client.SetTagsContext(t)
}

// SetUserContext sets user.
func (hook *SentryHook) SetUserContext(u *raven.User) {
	hook.client.SetUserContext(u)
}

// SetServerName sets server_name tag.
func (hook *SentryHook) SetServerName(serverName string) {
	hook.serverName = serverName
}

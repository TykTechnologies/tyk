# Sentry Hook for Logrus <img src="http://i.imgur.com/hTeVwmJ.png" width="40" height="40" alt=":walrus:" class="emoji" title=":walrus:" />


[![Build Status](https://travis-ci.org/evalphobia/logrus_sentry.svg?branch=master)](https://travis-ci.org/evalphobia/logrus_sentry)  [![Coverage Status](https://coveralls.io/repos/evalphobia/logrus_sentry/badge.svg?branch=master&service=github)](https://coveralls.io/github/evalphobia/logrus_sentry?branch=master) [![GoDoc](https://godoc.org/github.com/evalphobia/logrus_sentry?status.svg)](https://godoc.org/github.com/evalphobia/logrus_sentry)

[Sentry](https://getsentry.com) provides both self-hosted and hosted
solutions for exception tracking.
Both client and server are
[open source](https://github.com/getsentry/sentry).

## Usage

Every sentry application defined on the server gets a different
[DSN](https://www.getsentry.com/docs/). In the example below replace
`YOUR_DSN` with the one created for your application.

```go
import (
  "github.com/sirupsen/logrus"
  "github.com/evalphobia/logrus_sentry"
)

func main() {
  log       := logrus.New()
  hook, err := logrus_sentry.NewSentryHook(YOUR_DSN, []logrus.Level{
    logrus.PanicLevel,
    logrus.FatalLevel,
    logrus.ErrorLevel,
  })

  if err == nil {
    log.Hooks.Add(hook)
  }
}
```

If you wish to initialize a SentryHook with tags, you can use the `NewWithTagsSentryHook` constructor to provide default tags:

```go
tags := map[string]string{
  "site": "example.com",
}
levels := []logrus.Level{
  logrus.PanicLevel,
  logrus.FatalLevel,
  logrus.ErrorLevel,
}
hook, err := logrus_sentry.NewWithTagsSentryHook(YOUR_DSN, tags, levels)

```

If you wish to initialize a SentryHook with an already initialized raven client, you can use
the `NewWithClientSentryHook` constructor:

```go
import (
  "github.com/sirupsen/logrus"
  "github.com/evalphobia/logrus_sentry"
  "github.com/getsentry/raven-go"
)

func main() {
  log := logrus.New()

  client, err := raven.New(YOUR_DSN)
  if err != nil {
      log.Fatal(err)
  }

  hook, err := logrus_sentry.NewWithClientSentryHook(client, []logrus.Level{
    logrus.PanicLevel,
    logrus.FatalLevel,
    logrus.ErrorLevel,
  })

  if err == nil {
    log.Hooks.Add(hook)
  }
}

hook, err := NewWithClientSentryHook(client, []logrus.Level{
	logrus.ErrorLevel,
})
```

## Special fields

Some logrus fields have a special meaning in this hook, and they will be especially processed by Sentry.


| Field key  | Description |
| ------------- | ------------- |
| `event_id`  | Each logged event is identified by the `event_id`, which is hexadecimal string representing a UUID4 value. You can manually specify the identifier of a log event by supplying this field.  The `event_id` string should be in one of the following UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` and `urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)|
| `user_name`  | Name of the user who is in the context of the event  |
| `user_email`  | Email of the user who is in the context of the event |
| `user_id`  | ID of the user who is in the context of the event |
| `user_ip`  | IP of the user who is in the context of the event |
| `server_name`  | Also known as hostname, it is the name of the server which is logging the event (hostname.example.com)  |
| `tags`  | `tags` are `raven.Tags` struct from `github.com/getsentry/raven-go` and override default tags data |
| `fingerprint`  | `fingerprint` is an string array, that allows you to affect sentry's grouping of events as detailed in the [sentry documentation](https://docs.sentry.io/learn/rollups/#customize-grouping-with-fingerprints) |
| `logger`  | `logger` is the part of the application which is logging the event. In go this usually means setting it to the name of the package. |
| `http_request`  | `http_request` is the in-coming request(*http.Request). The detailed request data are sent to Sentry. |

## Timeout

`Timeout` is the time the sentry hook will wait for a response
from the sentry server.

If this time elapses with no response from
the server an error will be returned.

If `Timeout` is set to 0 the SentryHook will not wait for a reply
and will assume a correct delivery.

The SentryHook has a default timeout of `100 milliseconds` when created
with a call to `NewSentryHook`. This can be changed by assigning a value to the `Timeout` field:

```go
hook, _ := logrus_sentry.NewSentryHook(...)
hook.Timeout = 20*time.Second
```

## Enabling Stacktraces

By default the hook will not send any stacktraces. However, this can be enabled
with:

```go
hook, _ := logrus_sentry.NewSentryHook(...)
hook.StacktraceConfiguration.Enable = true
```

Subsequent calls to `logger.Error` and above will create a stacktrace.

Other configuration options are:
- `StacktraceConfiguration.Level` the logrus level at which to start capturing stacktraces.
- `StacktraceConfiguration.Skip` how many stack frames to skip before stacktrace starts recording.
- `StacktraceConfiguration.Context` the number of lines to include around a stack frame for context.
- `StacktraceConfiguration.InAppPrefixes` the prefixes that will be matched against the stack frame to identify it as in_app

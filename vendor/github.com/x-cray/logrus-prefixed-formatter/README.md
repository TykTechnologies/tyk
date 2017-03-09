# Logrus Prefixed Log Formatter
[Logrus](https://github.com/Sirupsen/logrus) formatter mainly based on original `logrus.TextFormatter` but with slightly
modified colored output and support for log entry prefixes, e.g. message source followed by a colon.

![Formatter screenshot](http://cl.ly/image/1w0B3F233F3z/formatter-screenshot@2x.png)

Just like with the original `logrus.TextFormatter` when a TTY is not attached, the output is compatible with the
[logfmt](http://godoc.org/github.com/kr/logfmt) format:

```text
time="Oct 27 00:44:26" level=debug msg="Started observing beach" animal=walrus number=8
time="Oct 27 00:44:26" level=info msg="A group of walrus emerges from the ocean" animal=walrus size=10
time="Oct 27 00:44:26" level=warning msg="The group's number increased tremendously!" number=122 omg=true
time="Oct 27 00:44:26" level=debug msg="Temperature changes" temperature=-4
time="Oct 27 00:44:26" level=panic msg="It's over 9000!" animal=orca size=9009
time="Oct 27 00:44:26" level=fatal msg="The ice breaks!" number=100 omg=true
exit status 1
```

## Installation
To install formatter, use `go get`:

```sh
$ go get github.com/x-cray/logrus-prefixed-formatter
```

## Usage
Here is how it should be used:

```go
package main

import (
	"github.com/Sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var log = logrus.New()

func init() {
	log.Formatter = new(prefixed.TextFormatter)
	log.Level = logrus.DebugLevel
}

func main() {
	log.WithFields(logrus.Fields{
		"prefix": "main",
		"animal": "walrus",
		"number": 8,
	}).Debug("Started observing beach")

	log.WithFields(logrus.Fields{
		"prefix":      "sensor",
		"temperature": -4,
	}).Info("Temperature changes")
}
```

## API
`prefixed.TextFormatter` exposes the following fields:

* `ForceColors bool` — set to true to bypass checking for a TTY before outputting colors.
* `DisableColors bool` — force disabling colors.
* `DisableTimestamp bool` — disable timestamp logging. useful when output is redirected to logging system that already adds timestamps.
* `ShortTimestamp bool` — enable logging of just the time passed since beginning of execution.
* `TimestampFormat string` — timestamp format to use for display when a full timestamp is printed.
* `DisableSorting bool` — the fields are sorted by default for a consistent output. For applications that log extremely frequently and don't use the JSON formatter this may not be desired.
* `SpacePadding int` — Pad msg field with spaces on the right for display. The value for this parameter will be the size of padding. Its default value is zero, which means no padding will be applied.

# License
MIT

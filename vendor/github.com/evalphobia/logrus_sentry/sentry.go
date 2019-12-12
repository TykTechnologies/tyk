package logrus_sentry

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"

	raven "github.com/getsentry/raven-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	severityMap = map[logrus.Level]raven.Severity{
		logrus.TraceLevel: raven.DEBUG,
		logrus.DebugLevel: raven.DEBUG,
		logrus.InfoLevel:  raven.INFO,
		logrus.WarnLevel:  raven.WARNING,
		logrus.ErrorLevel: raven.ERROR,
		logrus.FatalLevel: raven.FATAL,
		logrus.PanicLevel: raven.FATAL,
	}
)

// SentryHook delivers logs to a sentry server.
type SentryHook struct {
	// Timeout sets the time to wait for a delivery error from the sentry server.
	// If this is set to zero the server will not wait for any response and will
	// consider the message correctly sent.
	//
	// This is ignored for asynchronous hooks. If you want to set a timeout when
	// using an async hook (to bound the length of time that hook.Flush can take),
	// you probably want to create your own raven.Client and set
	// ravenClient.Transport.(*raven.HTTPTransport).Client.Timeout to set a
	// timeout on the underlying HTTP request instead.
	Timeout                 time.Duration
	StacktraceConfiguration StackTraceConfiguration

	client *raven.Client
	levels []logrus.Level

	serverName    string
	ignoreFields  map[string]struct{}
	extraFilters  map[string]func(interface{}) interface{}
	errorHandlers []func(entry *logrus.Entry, err error)

	asynchronous bool

	mu sync.RWMutex
	wg sync.WaitGroup
}

// The Stacktracer interface allows an error type to return a raven.Stacktrace.
type Stacktracer interface {
	GetStacktrace() *raven.Stacktrace
}

type causer interface {
	Cause() error
}

type pkgErrorStackTracer interface {
	StackTrace() errors.StackTrace
}

// StackTraceConfiguration allows for configuring stacktraces
type StackTraceConfiguration struct {
	// whether stacktraces should be enabled
	Enable bool
	// the level at which to start capturing stacktraces
	Level logrus.Level
	// how many stack frames to skip before stacktrace starts recording
	Skip int
	// the number of lines to include around a stack frame for context
	Context int
	// the prefixes that will be matched against the stack frame.
	// if the stack frame's package matches one of these prefixes
	// sentry will identify the stack frame as "in_app"
	InAppPrefixes []string
	// whether sending exception type should be enabled.
	SendExceptionType bool
	// whether the exception type and message should be switched.
	SwitchExceptionTypeAndMessage bool
	// whether to include a breadcrumb with the full error stack
	IncludeErrorBreadcrumb bool
}

// NewSentryHook creates a hook to be added to an instance of logger
// and initializes the raven client.
// This method sets the timeout to 100 milliseconds.
func NewSentryHook(DSN string, levels []logrus.Level) (*SentryHook, error) {
	client, err := raven.New(DSN)
	if err != nil {
		return nil, err
	}
	return NewWithClientSentryHook(client, levels)
}

// NewWithTagsSentryHook creates a hook with tags to be added to an instance
// of logger and initializes the raven client. This method sets the timeout to
// 100 milliseconds.
func NewWithTagsSentryHook(DSN string, tags map[string]string, levels []logrus.Level) (*SentryHook, error) {
	client, err := raven.NewWithTags(DSN, tags)
	if err != nil {
		return nil, err
	}
	return NewWithClientSentryHook(client, levels)
}

// NewWithClientSentryHook creates a hook using an initialized raven client.
// This method sets the timeout to 100 milliseconds.
func NewWithClientSentryHook(client *raven.Client, levels []logrus.Level) (*SentryHook, error) {
	return &SentryHook{
		Timeout: 100 * time.Millisecond,
		StacktraceConfiguration: StackTraceConfiguration{
			Enable:            false,
			Level:             logrus.ErrorLevel,
			Skip:              6,
			Context:           0,
			InAppPrefixes:     nil,
			SendExceptionType: true,
		},
		client:       client,
		levels:       levels,
		ignoreFields: make(map[string]struct{}),
		extraFilters: make(map[string]func(interface{}) interface{}),
	}, nil
}

// NewAsyncSentryHook creates a hook same as NewSentryHook, but in asynchronous
// mode.
func NewAsyncSentryHook(DSN string, levels []logrus.Level) (*SentryHook, error) {
	hook, err := NewSentryHook(DSN, levels)
	return setAsync(hook), err
}

// NewAsyncWithTagsSentryHook creates a hook same as NewWithTagsSentryHook, but
// in asynchronous mode.
func NewAsyncWithTagsSentryHook(DSN string, tags map[string]string, levels []logrus.Level) (*SentryHook, error) {
	hook, err := NewWithTagsSentryHook(DSN, tags, levels)
	return setAsync(hook), err
}

// NewAsyncWithClientSentryHook creates a hook same as NewWithClientSentryHook,
// but in asynchronous mode.
func NewAsyncWithClientSentryHook(client *raven.Client, levels []logrus.Level) (*SentryHook, error) {
	hook, err := NewWithClientSentryHook(client, levels)
	return setAsync(hook), err
}

func setAsync(hook *SentryHook) *SentryHook {
	if hook == nil {
		return nil
	}
	hook.asynchronous = true
	return hook
}

// Fire is called when an event should be sent to sentry
// Special fields that sentry uses to give more information to the server
// are extracted from entry.Data (if they are found)
// These fields are: error, logger, server_name, http_request, tags
func (hook *SentryHook) Fire(entry *logrus.Entry) error {
	hook.mu.RLock() // Allow multiple go routines to log simultaneously
	defer hook.mu.RUnlock()

	df := newDataField(entry.Data)

	err, hasError := df.getError()
	var crumbs *Breadcrumbs
	if hasError && hook.StacktraceConfiguration.IncludeErrorBreadcrumb {
		crumbs = &Breadcrumbs{
			Values: []Value{{
				Timestamp: int64(time.Now().Unix()),
				Type:      "error",
				Message:   fmt.Sprintf("%+v", err),
			}},
		}
	}

	packet := raven.NewPacketWithExtra(entry.Message, nil, crumbs)
	packet.Timestamp = raven.Timestamp(entry.Time)
	packet.Level = severityMap[entry.Level]
	packet.Platform = "go"

	// set special fields
	if hook.serverName != "" {
		packet.ServerName = hook.serverName
	}
	if logger, ok := df.getLogger(); ok {
		packet.Logger = logger
	}
	if serverName, ok := df.getServerName(); ok {
		packet.ServerName = serverName
	}
	if eventID, ok := df.getEventID(); ok {
		packet.EventID = eventID
	}
	if tags, ok := df.getTags(); ok {
		packet.Tags = tags
	}
	if fingerprint, ok := df.getFingerprint(); ok {
		packet.Fingerprint = fingerprint
	}
	if req, ok := df.getHTTPRequest(); ok {
		packet.Interfaces = append(packet.Interfaces, req)
	}
	if user, ok := df.getUser(); ok {
		packet.Interfaces = append(packet.Interfaces, user)
	}

	// set stacktrace data
	stConfig := &hook.StacktraceConfiguration
	if stConfig.Enable && entry.Level <= stConfig.Level {
		if err, ok := df.getError(); ok {
			var currentStacktrace *raven.Stacktrace
			currentStacktrace = hook.findStacktrace(err)
			if currentStacktrace == nil {
				currentStacktrace = raven.NewStacktrace(stConfig.Skip, stConfig.Context, stConfig.InAppPrefixes)
			}
			cause := errors.Cause(err)
			if cause == nil {
				cause = err
			}
			exc := raven.NewException(cause, currentStacktrace)
			if !stConfig.SendExceptionType {
				exc.Type = ""
			}
			if stConfig.SwitchExceptionTypeAndMessage {
				packet.Interfaces = append(packet.Interfaces, currentStacktrace)
				packet.Culprit = exc.Type + ": " + currentStacktrace.Culprit()
			} else {
				packet.Interfaces = append(packet.Interfaces, exc)
				packet.Culprit = err.Error()
			}
		} else {
			currentStacktrace := raven.NewStacktrace(stConfig.Skip, stConfig.Context, stConfig.InAppPrefixes)
			if currentStacktrace != nil {
				packet.Interfaces = append(packet.Interfaces, currentStacktrace)
			}
		}
	} else {
		// set the culprit even when the stack trace is disabled, as long as we have an error
		if err, ok := df.getError(); ok {
			packet.Culprit = err.Error()
		}
	}

	// set other fields
	dataExtra := hook.formatExtraData(df)
	if packet.Extra == nil {
		packet.Extra = dataExtra
	} else {
		for k, v := range dataExtra {
			packet.Extra[k] = v
		}
	}

	_, errCh := hook.client.Capture(packet, nil)

	switch {
	case hook.asynchronous:
		// Our use of hook.mu guarantees that we are following the WaitGroup rule of
		// not calling Add in parallel with Wait.
		hook.wg.Add(1)
		go func() {
			if err := <-errCh; err != nil {
				for _, handlerFn := range hook.errorHandlers {
					handlerFn(entry, err)
				}
			}
			hook.wg.Done()
		}()
		return nil
	case hook.Timeout == 0:
		return nil
	default:
		timeout := hook.Timeout
		timeoutCh := time.After(timeout)
		select {
		case err := <-errCh:
			for _, handlerFn := range hook.errorHandlers {
				handlerFn(entry, err)
			}
			return err
		case <-timeoutCh:
			return fmt.Errorf("no response from sentry server in %s", timeout)
		}
	}
}

// Flush waits for the log queue to empty. This function only does anything in
// asynchronous mode.
func (hook *SentryHook) Flush() {
	if !hook.asynchronous {
		return
	}
	hook.mu.Lock() // Claim exclusive access; any logging goroutines will block until the flush completes
	defer hook.mu.Unlock()

	hook.wg.Wait()
}

func (hook *SentryHook) findStacktrace(err error) *raven.Stacktrace {
	var stacktrace *raven.Stacktrace
	var stackErr errors.StackTrace
	for err != nil {
		// Find the earliest *raven.Stacktrace, or error.StackTrace
		if tracer, ok := err.(Stacktracer); ok {
			stacktrace = tracer.GetStacktrace()
			stackErr = nil
		} else if tracer, ok := err.(pkgErrorStackTracer); ok {
			stacktrace = nil
			stackErr = tracer.StackTrace()
		}
		if cause, ok := err.(causer); ok {
			err = cause.Cause()
		} else {
			break
		}
	}
	if stackErr != nil {
		stacktrace = hook.convertStackTrace(stackErr)
	}
	return stacktrace
}

// convertStackTrace converts an errors.StackTrace into a natively consumable
// *raven.Stacktrace
func (hook *SentryHook) convertStackTrace(st errors.StackTrace) *raven.Stacktrace {
	stConfig := &hook.StacktraceConfiguration
	stFrames := []errors.Frame(st)
	frames := make([]*raven.StacktraceFrame, 0, len(stFrames))
	for i := range stFrames {
		pc := uintptr(stFrames[i])
		fn := runtime.FuncForPC(pc)
		file, line := fn.FileLine(pc)
		frame := raven.NewStacktraceFrame(pc, fn.Name(), file, line, stConfig.Context, stConfig.InAppPrefixes)
		if frame != nil {
			frames = append(frames, frame)
		}
	}

	// Sentry wants the frames with the oldest first, so reverse them
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}
	return &raven.Stacktrace{Frames: frames}
}

// Levels returns the available logging levels.
func (hook *SentryHook) Levels() []logrus.Level {
	return hook.levels
}

// AddIgnore adds field name to ignore.
func (hook *SentryHook) AddIgnore(name string) {
	hook.ignoreFields[name] = struct{}{}
}

// AddExtraFilter adds a custom filter function.
func (hook *SentryHook) AddExtraFilter(name string, fn func(interface{}) interface{}) {
	hook.extraFilters[name] = fn
}

// AddErrorHandler adds a error handler function used when Sentry returns error.
func (hook *SentryHook) AddErrorHandler(fn func(entry *logrus.Entry, err error)) {
	hook.errorHandlers = append(hook.errorHandlers, fn)
}

func (hook *SentryHook) formatExtraData(df *dataField) (result map[string]interface{}) {
	// create a map for passing to Sentry's extra data
	result = make(map[string]interface{}, df.len())
	for k, v := range df.data {
		if df.isOmit(k) {
			continue // skip already used special fields
		}
		if _, ok := hook.ignoreFields[k]; ok {
			continue
		}

		if fn, ok := hook.extraFilters[k]; ok {
			v = fn(v) // apply custom filter
		} else {
			v = formatData(v) // use default formatter
		}
		result[k] = v
	}
	return result
}

// formatData returns value as a suitable format.
func formatData(value interface{}) (formatted interface{}) {
	switch value := value.(type) {
	case json.Marshaler:
		return value
	case error:
		return value.Error()
	case fmt.Stringer:
		return value.String()
	default:
		return value
	}
}

// utility classes for breadcrumb support
type Breadcrumbs struct {
	Values []Value `json:"values"`
}

type Value struct {
	Timestamp int64       `json:"timestamp"`
	Type      string      `json:"type"`
	Message   string      `json:"message"`
	Category  string      `json:"category"`
	Level     string      `json:"string"`
	Data      interface{} `json:"data"`
}

func (b *Breadcrumbs) Class() string {
	return "breadcrumbs"
}

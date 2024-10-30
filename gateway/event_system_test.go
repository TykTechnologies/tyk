package gateway

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

var (
	handlerTypes = []apidef.TykEventHandlerName{
		EH_LogHandler,
		EH_WebHook,
	}
)

func (ts *Test) prepareSpecWithEvents(logger *logrus.Logger) (spec *APISpec) {

	if logger == nil {
		logger = log
	}
	def := &apidef.APIDefinition{
		EventHandlers: apidef.EventHandlerMetaConfig{
			Events: map[apidef.TykEvent][]apidef.EventHandlerTriggerConfig{
				EventAuthFailure: {
					{
						Handler: EH_LogHandler,
						HandlerMeta: map[string]interface{}{
							"prefix": "testprefix",
							"logger": logger,
						},
					},
				},
			},
		},
	}

	spec = &APISpec{APIDefinition: def}
	// From api_definition.go:
	spec.EventPaths = make(map[apidef.TykEvent][]config.TykEventHandler)
	for eventName, eventHandlerConfs := range def.EventHandlers.Events {
		for _, handlerConf := range eventHandlerConfs {
			eventHandlerInstance, err := ts.Gw.EventHandlerByName(handlerConf, spec)

			if err != nil {
				log.Error("Failed to init event handler: ", err)
			} else {
				spec.EventPaths[eventName] = append(spec.EventPaths[eventName], eventHandlerInstance)
			}

		}
	}

	return spec
}

func prepareEventsConf() (conf *config.Config) {
	return &config.Config{
		EventHandlers: apidef.EventHandlerMetaConfig{
			Events: map[apidef.TykEvent][]apidef.EventHandlerTriggerConfig{
				EventQuotaExceeded: {
					{
						Handler: EH_LogHandler,
						HandlerMeta: map[string]interface{}{
							"prefix": "testprefix1",
							"logger": log,
						},
					},
				},
				EventAuthFailure: {
					{
						Handler: EH_LogHandler,
						HandlerMeta: map[string]interface{}{
							"prefix": "testprefix2",
							"logger": log,
						},
					},
				},
			},
		},
	}
}

func prepareEventHandlerConfig(handler apidef.TykEventHandlerName) (config apidef.EventHandlerTriggerConfig) {
	config.Handler = handler
	switch handler {
	case EH_LogHandler:
		config.HandlerMeta = map[string]interface{}{
			"prefix": "testprefix",
			"logger": log,
		}
	case EH_WebHook:
		config.HandlerMeta = map[string]interface{}{}
	}
	return config
}
func TestEventHandlerByName(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.prepareSpecWithEvents(nil)
	for _, handlerType := range handlerTypes {
		handlerConfig := prepareEventHandlerConfig(handlerType)
		_, err := ts.Gw.EventHandlerByName(handlerConfig, spec)

		// CP is disabled on standard builds:
		if handlerType == EH_CoProcessHandler {
			continue
		}
		if err != nil {
			t.Fatalf("Couldn't get handler for %s\n", handlerType)
		}
	}
}

func TestLogMessageEventHandler(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	buf := &bytes.Buffer{}
	testLogger := logrus.New()
	testLogger.Out = buf
	spec := ts.prepareSpecWithEvents(testLogger)
	handler := spec.EventPaths[EventAuthFailure][0]
	em := config.EventMessage{
		Type: EventAuthFailure,
		Meta: EventKeyFailureMeta{
			EventMetaDefault: EventMetaDefault{Message: "Auth Failure"},
			Path:             "/",
			Origin:           "127.0.0.1",
			Key:              "abc",
		},
		TimeStamp: time.Now().Local().String(),
	}
	lookup := "testprefix:AuthFailure"
	handler.HandleEvent(em)
	if !strings.Contains(buf.String(), lookup) {
		t.Fatal("Couldn't find log message")
	}
}

func TestInitGenericEventHandlers(t *testing.T) {

	eventsConf := prepareEventsConf()
	conf := func(confi *config.Config) {
		confi.EventHandlers = eventsConf.EventHandlers
	}

	ts := StartTest(conf)
	defer ts.Close()

	ts.Gw.initGenericEventHandlers()
	triggers := ts.Gw.GetConfig().GetEventTriggers()

	if len(triggers) != 2 {
		t.Fatal("EventTriggers length doesn't match")
	}
	for _, e := range []apidef.TykEvent{EventQuotaExceeded, EventAuthFailure} {
		if triggers[e] == nil {
			t.Fatalf("EventTriggers doesn't contain %s handlers", e)
		}
	}
	for _, handlers := range triggers {
		if len(handlers) != 1 {
			t.Fatal("EventTriggers handlers length doesn't match")
		}
	}
}

func BenchmarkInitGenericEventHandlers(b *testing.B) {
	ts := StartTest(nil)
	defer ts.Close()

	b.ReportAllocs()

	conf := prepareEventsConf()
	ts.Gw.SetConfig(*conf)
	for i := 0; i < b.N; i++ {
		ts.Gw.initGenericEventHandlers()
	}
}

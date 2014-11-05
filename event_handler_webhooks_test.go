package main

import (
	"testing"
)

func TestGet(t *testing.T) {
	eventHandlerConf := WebHookHandlerConf{}
	eventHandlerConf.TargetPath = "http://httpbin.org/get"
	eventHandlerConf.Method = "GET"
	eventHandlerConf.EventTimeout = 10
	eventHandlerConf.TemplatePath = "templates/default_webhook.json"
	eventHandlerConf.HeaderList = make(map[string]string)
	eventHandlerConf.HeaderList["x-tyk-test"] = "TEST"

	myEventHandler := WebHookHandler{}.New(eventHandlerConf).(WebHookHandler)

	eventMessage := EventMessage{}
	eventMessage.EventType = EVENT_KeyExpired
	eventMessage.EventMetaData = EVENT_AuthFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "THIS IS A TEST"},
		Path:"/banana",
		Origin:"tyk.io",
		Key:"123456789",
	}

	thisBody, _ := myEventHandler.CreateBody(eventMessage)

	thisChecksum, _ := myEventHandler.GetChecksum(thisBody)
	myEventHandler.HandleEvent(eventMessage)

	wasFired := myEventHandler.WasHookFired(thisChecksum)

	log.Warning("Test Checksum: ", thisChecksum)

	if !wasFired {
		t.Error("Checksum should have matched, event did not fire!")
	}

}

func TestPost(t *testing.T) {
	eventHandlerConf := WebHookHandlerConf{}
	eventHandlerConf.TargetPath = "http://posttestserver.com/post.php?dir=tyk"
	eventHandlerConf.Method = "POST"
	eventHandlerConf.EventTimeout = 10
	eventHandlerConf.TemplatePath = "templates/default_webhook.json"
	eventHandlerConf.HeaderList = make(map[string]string)
	eventHandlerConf.HeaderList["x-tyk-test"] = "TEST POST"

	myEventHandler := WebHookHandler{}.New(eventHandlerConf).(WebHookHandler)

	eventMessage := EventMessage{}
	eventMessage.EventType = EVENT_KeyExpired
	eventMessage.EventMetaData = EVENT_AuthFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "THIS IS A TEST"},
		Path:"/banana",
		Origin:"tyk.io",
		Key:"123456789",
	}

	thisBody, _ := myEventHandler.CreateBody(eventMessage)

	thisChecksum, _ := myEventHandler.GetChecksum(thisBody)
	myEventHandler.HandleEvent(eventMessage)

	wasFired := myEventHandler.WasHookFired(thisChecksum)

	log.Warning("Test Checksum: ", thisChecksum)

	if !wasFired {
		t.Error("Checksum should have matched, event did not fire!")
	}

}

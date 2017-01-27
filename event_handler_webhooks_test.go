package main

import (
	"strings"
	"testing"
)

func createHookObj() *WebHookHandler {
	eventHandlerConf := WebHookHandlerConf{}
	eventHandlerConf.TargetPath = "http://httpbin.org/get"
	eventHandlerConf.Method = "GET"
	eventHandlerConf.EventTimeout = 10
	eventHandlerConf.TemplatePath = "templates/default_webhook.json"
	eventHandlerConf.HeaderList = make(map[string]string)
	eventHandlerConf.HeaderList["x-tyk-test"] = "TEST"

	ev, _ := (&WebHookHandler{}).New(eventHandlerConf)

	myEventHandler := ev.(*WebHookHandler)

	eventMessage := EventMessage{}
	eventMessage.EventType = EVENT_KeyExpired
	eventMessage.EventMetaData = EVENT_AuthFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "THIS IS A TEST"},
		Path:             "/banana",
		Origin:           "tyk.io",
		Key:              "123456789",
	}

	return myEventHandler
}

func TestNewValid(t *testing.T) {

	o := WebHookHandler{}
	var conf = make(map[string]interface{})

	conf["method"] = "POST"
	conf["target_path"] = "http://posttestserver.com/post.php?dir=tyk-event-test"
	conf["template_path"] = "templates/default_webhook.json"
	conf["header_map"] = map[string]string{"X-Tyk-Test-Header": "Tyk v1.BANANA"}
	conf["event_timeout"] = 10

	_, err := o.New(conf)

	if err != nil {
		t.Error("Webhook Handler should have created valid configuration")
	}
}

func TestNewInvlalid(t *testing.T) {

	o := WebHookHandler{}
	var conf = make(map[string]interface{})

	conf["method"] = 123
	conf["target_path"] = "http://posttestserver.com/post.php?dir=tyk-event-test"
	conf["template_path"] = "templates/default_webhook.json"
	conf["header_map"] = map[string]string{"X-Tyk-Test-Header": "Tyk v1.BANANA"}
	conf["event_timeout"] = 10

	_, err := o.New(conf)

	if err == nil {
		t.Error("Webhook Handler should have failed")
	}
}

func TestGetChecksum(t *testing.T) {
	rBody := `
	{
		"event": "QuotaExceeded",
		"message": "Key Quota Limit Exceeded",
		"path": "/about-lonelycoder/",
		"origin": "",
		"key": "4321",
		"timestamp": 2014-11-27 12:52:05.944549825 &#43;0000 GMT
	}
	`

	hook := createHookObj()
	checksum, err := hook.GetChecksum(rBody)

	if err != nil {
		t.Error("Checksum should not have failed with good objet and body")
	}

	if checksum != "1dedfbf3c3286d6d0d6e54a8df5212a2" {
		t.Error("Checksum is incorrect")
		t.Error(checksum)
	}
}

func TestBuildRequest(t *testing.T) {
	hook := createHookObj()

	rBody := `
	{
		"event": "QuotaExceeded",
		"message": "Key Quota Limit Exceeded",
		"path": "/about-lonelycoder/",
		"origin": "",
		"key": "4321",
		"timestamp": 2014-11-27 12:52:05.944549825 &#43;0000 GMT
	}
	`

	req, err := hook.BuildRequest(rBody)
	if err != nil {
		t.Error("Request should have built cleanly.")
	}

	if req.Method != "GET" {
		t.Error("Method hould be GET")
	}

	hVal, ok := req.Header["User-Agent"]
	if !ok {
		t.Error("Header was not set")
	}

	if hVal[0] != "Tyk-Hookshot" {
		t.Error("Header User Agent is not correct!")
	}

}

func TestCreateBody(t *testing.T) {
	em := EventMessage{}
	em.EventType = EVENT_QuotaExceeded
	em.TimeStamp = "0"

	thisHook := createHookObj()

	body, err := thisHook.CreateBody(em)

	if err != nil {
		t.Error("Create body failed with error! ", err)
	}

	expectedBody := `"event": "QuotaExceeded"`
	if !strings.Contains(body, expectedBody) {
		t.Error("Body incorrect, is: ", body)
	}

}

func TestGet(t *testing.T) {
	eventHandlerConf := WebHookHandlerConf{}
	eventHandlerConf.TargetPath = "http://httpbin.org/get"
	eventHandlerConf.Method = "GET"
	eventHandlerConf.EventTimeout = 10
	eventHandlerConf.TemplatePath = "templates/default_webhook.json"
	eventHandlerConf.HeaderList = make(map[string]string)
	eventHandlerConf.HeaderList["x-tyk-test"] = "TEST"

	ev, _ := (&WebHookHandler{}).New(eventHandlerConf)

	myEventHandler := ev.(*WebHookHandler)

	eventMessage := EventMessage{}
	eventMessage.EventType = EVENT_KeyExpired
	eventMessage.EventMetaData = EVENT_AuthFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "THIS IS A TEST"},
		Path:             "/banana",
		Origin:           "tyk.io",
		Key:              "123456789",
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

	ev, _ := (&WebHookHandler{}).New(eventHandlerConf)
	myEventHandler := ev.(*WebHookHandler)

	eventMessage := EventMessage{}
	eventMessage.EventType = EVENT_KeyExpired
	eventMessage.EventMetaData = EVENT_AuthFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "THIS IS A TEST"},
		Path:             "/banana",
		Origin:           "tyk.io",
		Key:              "123456789",
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

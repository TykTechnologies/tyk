package main

import (
	"strings"
	"testing"
)

func createGetHandler() *WebHookHandler {
	eventHandlerConf := WebHookHandlerConf{
		TargetPath:   testHttpGet,
		Method:       "GET",
		EventTimeout: 10,
		TemplatePath: "templates/default_webhook.json",
		HeaderList:   map[string]string{"x-tyk-test": "TEST"},
	}
	ev, _ := (&WebHookHandler{}).New(eventHandlerConf)
	return ev.(*WebHookHandler)
}

func TestNewValid(t *testing.T) {
	o := WebHookHandler{}
	_, err := o.New(map[string]interface{}{
		"method":        "POST",
		"target_path":   testHttpPost,
		"template_path": "templates/default_webhook.json",
		"header_map":    map[string]string{"X-Tyk-Test-Header": "Tyk v1.BANANA"},
		"event_timeout": 10,
	})
	if err != nil {
		t.Error("Webhook Handler should have created valid configuration")
	}
}

func TestNewInvlalid(t *testing.T) {
	o := WebHookHandler{}
	_, err := o.New(map[string]interface{}{
		"method":        123,
		"target_path":   testHttpPost,
		"template_path": "templates/default_webhook.json",
		"header_map":    map[string]string{"X-Tyk-Test-Header": "Tyk v1.BANANA"},
		"event_timeout": 10,
	})
	if err == nil {
		t.Error("Webhook Handler should have failed")
	}
}

func TestGetChecksum(t *testing.T) {
	rBody := `{
		"event": "QuotaExceeded",
		"message": "Key Quota Limit Exceeded",
		"path": "/about-lonelycoder/",
		"origin": "",
		"key": "4321",
		"timestamp": 2014-11-27 12:52:05.944549825 &#43;0000 GMT
	}`

	hook := createGetHandler()
	checksum, err := hook.GetChecksum(rBody)

	if err != nil {
		t.Error("Checksum should not have failed with good objet and body")
	}

	if checksum != "62a6b4fa9b45cd372b871764296fb3a5" {
		t.Error("Checksum is incorrect")
		t.Error(checksum)
	}
}

func TestBuildRequest(t *testing.T) {
	hook := createGetHandler()

	rBody := `{
		"event": "QuotaExceeded",
		"message": "Key Quota Limit Exceeded",
		"path": "/about-lonelycoder/",
		"origin": "",
		"key": "4321",
		"timestamp": 2014-11-27 12:52:05.944549825 &#43;0000 GMT
	}`

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
	em := EventMessage{
		EventType: EVENT_QuotaExceeded,
		TimeStamp: "0",
	}

	hook := createGetHandler()
	body, err := hook.CreateBody(em)
	if err != nil {
		t.Error("Create body failed with error! ", err)
	}

	expectedBody := `"event": "QuotaExceeded"`
	if !strings.Contains(body, expectedBody) {
		t.Error("Body incorrect, is: ", body)
	}
}

func TestGet(t *testing.T) {
	eventHandlerConf := WebHookHandlerConf{
		TargetPath:   "http://httpbin.org/get",
		Method:       "GET",
		EventTimeout: 10,
		TemplatePath: "templates/default_webhook.json",
		HeaderList:   map[string]string{"x-tyk-test": "TEST"},
	}

	ev, _ := (&WebHookHandler{}).New(eventHandlerConf)

	eventHandler := ev.(*WebHookHandler)

	eventMessage := EventMessage{
		EventType: EVENT_KeyExpired,
		EventMetaData: EVENT_AuthFailureMeta{
			EventMetaDefault: EventMetaDefault{Message: "THIS IS A TEST"},
			Path:             "/banana",
			Origin:           "tyk.io",
			Key:              "123456789",
		},
	}
	body, _ := eventHandler.CreateBody(eventMessage)

	checksum, _ := eventHandler.GetChecksum(body)
	eventHandler.HandleEvent(eventMessage)

	log.Info("Test Checksum: ", checksum)

	if wasFired := eventHandler.WasHookFired(checksum); !wasFired {
		t.Error("Checksum should have matched, event did not fire!")
	}

}

func TestPost(t *testing.T) {
	eventHandlerConf := WebHookHandlerConf{
		TargetPath:   "http://posttestserver.com/post.php?dir=tyk",
		Method:       "POST",
		EventTimeout: 10,
		TemplatePath: "templates/default_webhook.json",
		HeaderList:   map[string]string{"x-tyk-test": "TEST POST"},
	}

	ev, _ := (&WebHookHandler{}).New(eventHandlerConf)
	eventHandler := ev.(*WebHookHandler)

	eventMessage := EventMessage{
		EventType: EVENT_KeyExpired,
		EventMetaData: EVENT_AuthFailureMeta{
			EventMetaDefault: EventMetaDefault{Message: "THIS IS A TEST"},
			Path:             "/banana",
			Origin:           "tyk.io",
			Key:              "123456789",
		},
	}

	body, _ := eventHandler.CreateBody(eventMessage)

	checksum, _ := eventHandler.GetChecksum(body)
	eventHandler.HandleEvent(eventMessage)

	log.Info("Test Checksum: ", checksum)

	if wasFired := eventHandler.WasHookFired(checksum); !wasFired {
		t.Error("Checksum should have matched, event did not fire!")
	}
}

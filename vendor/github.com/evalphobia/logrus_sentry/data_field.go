package logrus_sentry

import (
	"net/http"

	"github.com/getsentry/raven-go"
	"github.com/sirupsen/logrus"
)

const (
	fieldEventID     = "event_id"
	fieldFingerprint = "fingerprint"
	fieldLogger      = "logger"
	fieldServerName  = "server_name"
	fieldTags        = "tags"
	fieldHTTPRequest = "http_request"
	fieldUser        = "user"
)

type dataField struct {
	data     logrus.Fields
	omitList map[string]struct{}
}

func newDataField(data logrus.Fields) *dataField {
	return &dataField{
		data:     data,
		omitList: make(map[string]struct{}),
	}
}

func (d *dataField) len() int {
	return len(d.data)
}

func (d *dataField) isOmit(key string) bool {
	_, ok := d.omitList[key]
	return ok
}

func (d *dataField) getLogger() (string, bool) {
	if logger, ok := d.data[fieldLogger].(string); ok {
		d.omitList[fieldLogger] = struct{}{}
		return logger, true
	}
	return "", false
}

func (d *dataField) getServerName() (string, bool) {
	if serverName, ok := d.data[fieldServerName].(string); ok {
		d.omitList[fieldServerName] = struct{}{}
		return serverName, true
	}
	return "", false
}

func (d *dataField) getTags() (raven.Tags, bool) {
	if tags, ok := d.data[fieldTags].(raven.Tags); ok {
		d.omitList[fieldTags] = struct{}{}
		return tags, true
	}
	return nil, false
}

func (d *dataField) getFingerprint() ([]string, bool) {
	if fingerprint, ok := d.data[fieldFingerprint].([]string); ok {
		d.omitList[fieldFingerprint] = struct{}{}
		return fingerprint, true
	}
	return nil, false
}

func (d *dataField) getError() (error, bool) {
	if err, ok := d.data[logrus.ErrorKey].(error); ok {
		d.omitList[logrus.ErrorKey] = struct{}{}
		return err, true
	}
	return nil, false
}

func (d *dataField) getHTTPRequest() (*raven.Http, bool) {
	if req, ok := d.data[fieldHTTPRequest].(*http.Request); ok {
		d.omitList[fieldHTTPRequest] = struct{}{}
		return raven.NewHttp(req), true
	}
	if req, ok := d.data[fieldHTTPRequest].(*raven.Http); ok {
		d.omitList[fieldHTTPRequest] = struct{}{}
		return req, true
	}
	return nil, false
}

func (d *dataField) getEventID() (string, bool) {
	eventID, ok := d.data[fieldEventID].(string)
	if !ok {
		return "", false
	}

	//verify eventID is 32 characters hexadecimal string (UUID4)
	uuid := parseUUID(eventID)
	if uuid == nil {
		return "", false
	}

	d.omitList[fieldEventID] = struct{}{}
	return uuid.noDashString(), true
}

func (d *dataField) getUser() (*raven.User, bool) {
	data := d.data
	if v, ok := data[fieldUser]; ok {
		switch val := v.(type) {
		case *raven.User:
			d.omitList[fieldUser] = struct{}{}
			return val, true
		case raven.User:
			d.omitList[fieldUser] = struct{}{}
			return &val, true
		}
	}

	username, _ := data["user_name"].(string)
	email, _ := data["user_email"].(string)
	id, _ := data["user_id"].(string)
	ip, _ := data["user_ip"].(string)

	if username == "" && email == "" && id == "" && ip == "" {
		return nil, false
	}

	return &raven.User{
		ID:       id,
		Username: username,
		Email:    email,
		IP:       ip,
	}, true
}

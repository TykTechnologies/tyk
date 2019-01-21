package goplugin

import (
	"net/http"

	"github.com/TykTechnologies/tyk/user"
)

// Logger provides interface to output to Tyk's logging system with log levels INFO, DEBUG, WARN and ERROR
type Logger interface {
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Infoln(args ...interface{})

	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Debugln(args ...interface{})

	Warning(args ...interface{})
	Warningf(format string, args ...interface{})
	Warningln(args ...interface{})

	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Errorln(args ...interface{})
}

type APISpec struct {
	OrgID      string
	APIID      string
	ConfigData map[string]interface{}
}

// ProcessFunc type functions are called for "pre", "post", "post_key_auth" custom middleware methods
type ProcessFunc func(
	http.ResponseWriter,
	*http.Request,
	*user.SessionState,
	APISpec,
	Logger,
) error

// AuthFunc type function is called for "auth_check" custom middleware method
type AuthFunc func(
	http.ResponseWriter,
	*http.Request,
	APISpec,
	Logger,
) (session *user.SessionState, token string, err error)

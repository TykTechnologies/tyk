// +build coprocess

package main

import (
	"github.com/mitchellh/mapstructure"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"

	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
)

var (
	// EnableCoProcess will be overridden by config.EnableCoProcess.
	EnableCoProcess = false

	// GlobalDispatcher will be implemented by the current CoProcess driver.
	GlobalDispatcher coprocess.Dispatcher
)

// CoProcessMiddleware is the basic CP middleware struct.
type CoProcessMiddleware struct {
	*TykMiddleware
	HookType         coprocess.HookType
	HookName         string
	MiddlewareDriver apidef.MiddlewareDriver
}

func (mw *CoProcessMiddleware) GetName() string {
	return "CoProcessMiddleware"
}

// CreateCoProcessMiddleware initializes a new CP middleware, takes hook type (pre, post, etc.), hook name ("my_hook") and driver ("python").
func CreateCoProcessMiddleware(hookName string, hookType coprocess.HookType, mwDriver apidef.MiddlewareDriver, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &CoProcessMiddleware{
		TykMiddleware:    tykMwSuper,
		HookType:         hookType,
		HookName:         hookName,
		MiddlewareDriver: mwDriver,
	}

	return CreateMiddleware(dMiddleware, tykMwSuper)
}

func doCoprocessReload() {
	if GlobalDispatcher != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Info("Reloading middlewares")
		GlobalDispatcher.Reload()
	}

}

// CoProcessor represents a CoProcess during the request.
type CoProcessor struct {
	HookType   coprocess.HookType
	Middleware *CoProcessMiddleware
}

// GetObjectFromRequest constructs a CoProcessObject from a given http.Request.
func (c *CoProcessor) GetObjectFromRequest(r *http.Request) *coprocess.Object {

	defer r.Body.Close()
	originalBody, _ := ioutil.ReadAll(r.Body)

	miniRequestObject := &coprocess.MiniRequestObject{
		Headers:        ProtoMap(r.Header),
		SetHeaders:     make(map[string]string),
		DeleteHeaders:  make([]string, 0),
		Body:           string(originalBody),
		Url:            r.URL.Path,
		Params:         ProtoMap(r.URL.Query()),
		AddParams:      make(map[string]string),
		ExtendedParams: ProtoMap(nil),
		DeleteParams:   make([]string, 0),
		ReturnOverrides: &coprocess.ReturnOverrides{
			ResponseCode:  -1,
			ResponseError: "",
		},
	}

	object := &coprocess.Object{
		Request:  miniRequestObject,
		HookName: c.Middleware.HookName,
	}

	// If a middleware is set, take its HookType, otherwise override it with CoProcessor.HookType
	if c.Middleware != nil && c.HookType == 0 {
		c.HookType = c.Middleware.HookType
	}

	object.HookType = c.HookType

	object.Metadata = make(map[string]string)
	object.Spec = make(map[string]string)

	// Append spec data:
	if c.Middleware != nil {
		object.Spec = map[string]string{
			"OrgID": c.Middleware.TykMiddleware.Spec.OrgID,
			"APIID": c.Middleware.TykMiddleware.Spec.APIID,
		}
	}

	// Encode the session object (if not a pre-process & not a custom key check):
	if c.HookType != coprocess.HookType_Pre && c.HookType != coprocess.HookType_CustomKeyCheck {
		session := ctxGetSession(r)
		if session != nil {
			object.Session = ProtoSessionState(session)
		}
	}

	return object
}

// ObjectPostProcess does CoProcessObject post-processing (adding/removing headers or params, etc.).
func (c *CoProcessor) ObjectPostProcess(object *coprocess.Object, r *http.Request) {
	r.ContentLength = int64(len(object.Request.Body))
	r.Body = ioutil.NopCloser(bytes.NewBufferString(object.Request.Body))

	for _, dh := range object.Request.DeleteHeaders {
		r.Header.Del(dh)
	}

	for h, v := range object.Request.SetHeaders {
		r.Header.Set(h, v)
	}

	values := r.URL.Query()
	for _, k := range object.Request.DeleteParams {
		values.Del(k)
	}

	for p, v := range object.Request.AddParams {
		values.Set(p, v)
	}

	r.URL.RawQuery = values.Encode()
}

// CoProcessInit creates a new CoProcessDispatcher, it will be called when Tyk starts.
func CoProcessInit() error {
	var err error
	if config.CoProcessOptions.EnableCoProcess {
		GlobalDispatcher, err = NewCoProcessDispatcher()
		EnableCoProcess = true
	}
	return err
}

// CoProcessMiddlewareConfig holds the middleware configuration.
type CoProcessMiddlewareConfig struct {
	ConfigData map[string]string `mapstructure:"config_data" bson:"config_data" json:"config_data"`
}

// New lets you do any initialisations for the object can be done here
func (m *CoProcessMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *CoProcessMiddleware) GetConfig() (interface{}, error) {
	var moduleConfig CoProcessMiddlewareConfig

	err := mapstructure.Decode(m.TykMiddleware.Spec.RawData, &moduleConfig)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error(err)
		return nil, err
	}

	return moduleConfig, nil
}

// IsEnabledForSpec checks if this middleware should be enabled for a given API.
func (m *CoProcessMiddleware) IsEnabledForSpec() bool {
	// This flag is true when Tyk has been compiled with CP support and when the configuration enables it.
	enableCoProcess := config.CoProcessOptions.EnableCoProcess && EnableCoProcess
	// This flag indicates if the current spec specifies any CP custom middleware.
	var usesCoProcessMiddleware bool

	supportedDrivers := []apidef.MiddlewareDriver{apidef.PythonDriver, apidef.LuaDriver, apidef.GrpcDriver}

	for _, driver := range supportedDrivers {
		if m.TykMiddleware.Spec.CustomMiddleware.Driver == driver && CoProcessName == driver {
			usesCoProcessMiddleware = true
			break
		}
	}

	if usesCoProcessMiddleware && enableCoProcess {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Debug("Enabling CP middleware.")
		return true
	}

	if usesCoProcessMiddleware && !enableCoProcess {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error("Your API specifies a CP custom middleware, either Tyk wasn't build with CP support or CP is not enabled in your Tyk configuration file!")
	}

	if !usesCoProcessMiddleware && m.TykMiddleware.Spec.CustomMiddleware.Driver != "" {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error("CP Driver not supported: ", m.TykMiddleware.Spec.CustomMiddleware.Driver)
	}

	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *CoProcessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	}).Debug("CoProcess Request, HookType: ", m.HookType)

	if !EnableCoProcess {
		return nil, 200
	}

	var extractor IdExtractor
	if m.TykMiddleware.Spec.EnableCoProcessAuth && m.TykMiddleware.Spec.CustomMiddleware.IdExtractor.Extractor != nil {
		extractor = m.TykMiddleware.Spec.CustomMiddleware.IdExtractor.Extractor.(IdExtractor)
	}

	var returnOverrides ReturnOverrides
	var sessionID string

	if m.HookType == coprocess.HookType_CustomKeyCheck && extractor != nil {
		sessionID, returnOverrides = extractor.ExtractAndCheck(r)

		if returnOverrides.ResponseCode != 0 {
			if returnOverrides.ResponseError == "" {
				return nil, returnOverrides.ResponseCode
			}
			err := errors.New(returnOverrides.ResponseError)
			return err, returnOverrides.ResponseCode
		}
	}

	// It's also possible to override the HookType:
	coProcessor := CoProcessor{
		Middleware: m,
		// HookType: coprocess.PreHook,
	}

	object := coProcessor.GetObjectFromRequest(r)

	returnObject, err := coProcessor.Dispatch(object)
	if err != nil {
		if m.HookType == coprocess.HookType_CustomKeyCheck {
			return errors.New("Key not authorised"), 403
		} else {
			return errors.New("Middleware error"), 500
		}
	}

	coProcessor.ObjectPostProcess(returnObject, r)

	token := returnObject.Metadata["token"]

	// The CP middleware indicates this is a bad auth:
	if returnObject.Request.ReturnOverrides.ResponseCode > 400 {

		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    token,
		}).Info("Attempted access with invalid key.")

		// Fire Authfailed Event
		AuthFailed(m.TykMiddleware, r, token)

		// Report in health check
		ReportHealthCheckValue(m.Spec.Health, KeyFailure, "1")

		return errors.New("Key not authorised"), int(returnObject.Request.ReturnOverrides.ResponseCode)
	}

	// Is this a CP authentication middleware?
	if m.TykMiddleware.Spec.EnableCoProcessAuth && m.HookType == coprocess.HookType_CustomKeyCheck {
		// The CP middleware didn't setup a session:
		if returnObject.Session == nil {
			return errors.New("Key not authorised"), 403
		}

		returnedSession := TykSessionState(returnObject.Session)

		if extractor == nil {
			sessionLifetime := getLifetime(m.Spec, returnedSession)
			// This API is not using the ID extractor, but we've got a session:
			m.Spec.SessionManager.UpdateSession(token, returnedSession, sessionLifetime)
			ctxSetSession(r, returnedSession)
			ctxSetAuthToken(r, token)
		} else {
			// The CP middleware did setup a session, we should pass it to the ID extractor (caching):
			extractor.PostProcess(r, returnedSession, sessionID)
		}
	}

	return nil, 200
}

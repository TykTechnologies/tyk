package oas

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/reflect"
)

// Server contains the configuration that sets Tyk up to receive requests from the client applications.
type Server struct {
	// ListenPath is the base path on Tyk to which requests for this API should
	// be sent. Tyk listens for any requests coming into the host at this
	// path, on the port that Tyk is configured to run on and processes these
	// accordingly.
	ListenPath ListenPath `bson:"listenPath" json:"listenPath"` // required

	// Authentication contains the configurations that manage how clients can authenticate with Tyk to access the API.
	Authentication *Authentication `bson:"authentication,omitempty" json:"authentication,omitempty"`

	// ClientCertificates contains the configurations related to establishing static mutual TLS between the client and Tyk.
	ClientCertificates *ClientCertificates `bson:"clientCertificates,omitempty" json:"clientCertificates,omitempty"`

	// GatewayTags contain segment tags to indicate which Gateways your upstream service is connected to (and hence where to deploy the API).
	GatewayTags *GatewayTags `bson:"gatewayTags,omitempty" json:"gatewayTags,omitempty"`

	// CustomDomain is the domain to bind this API to. This enforces domain matching for client requests.
	//
	// Tyk classic API definition: `domain`
	CustomDomain *Domain `bson:"customDomain,omitempty" json:"customDomain,omitempty"`

	// DetailedActivityLogs configures detailed analytics recording.
	DetailedActivityLogs *DetailedActivityLogs `bson:"detailedActivityLogs,omitempty" json:"detailedActivityLogs,omitempty"`

	// DetailedTracing enables OpenTelemetry's detailed tracing for this API.
	//
	// Tyk classic API definition: `detailed_tracing`
	DetailedTracing *DetailedTracing `bson:"detailedTracing,omitempty" json:"detailedTracing,omitempty"`

	// Events contains the configuration related to Tyk Events.
	//
	// Tyk classic API definition: `event_handlers`
	Events Events `bson:"events,omitempty" json:"events,omitempty"`
}

// Fill fills *Server from apidef.APIDefinition.
func (s *Server) Fill(api apidef.APIDefinition) {
	s.ListenPath.Fill(api)

	if s.ClientCertificates == nil {
		s.ClientCertificates = &ClientCertificates{}
	}

	s.ClientCertificates.Fill(api)
	if ShouldOmit(s.ClientCertificates) {
		s.ClientCertificates = nil
	}

	if s.GatewayTags == nil {
		s.GatewayTags = &GatewayTags{}
	}
	s.GatewayTags.Fill(api)
	if ShouldOmit(s.GatewayTags) {
		s.GatewayTags = nil
	}

	if s.CustomDomain == nil {
		s.CustomDomain = &Domain{}
	}

	s.CustomDomain.Fill(api)
	if ShouldOmit(s.CustomDomain) {
		s.CustomDomain = nil
	}

	if s.DetailedActivityLogs == nil {
		s.DetailedActivityLogs = &DetailedActivityLogs{}
	}

	s.DetailedActivityLogs.Fill(api)
	if ShouldOmit(s.DetailedActivityLogs) {
		s.DetailedActivityLogs = nil
	}

	if s.DetailedTracing == nil {
		s.DetailedTracing = &DetailedTracing{}
	}
	s.DetailedTracing.Fill(api)
	if ShouldOmit(s.DetailedTracing) {
		s.DetailedTracing = nil
	}

	if s.Events == nil {
		s.Events = Events{}
	}
	s.Events.Fill(api)
	if ShouldOmit(s.Events) {
		s.Events = nil
	}
}

// ExtractTo extracts *Server into *apidef.APIDefinition.
func (s *Server) ExtractTo(api *apidef.APIDefinition) {
	s.ListenPath.ExtractTo(api)

	if s.ClientCertificates == nil {
		s.ClientCertificates = &ClientCertificates{}
		defer func() {
			s.ClientCertificates = nil
		}()
	}

	s.ClientCertificates.ExtractTo(api)

	if s.GatewayTags == nil {
		s.GatewayTags = &GatewayTags{}
		defer func() {
			s.GatewayTags = nil
		}()
	}

	s.GatewayTags.ExtractTo(api)

	if s.CustomDomain == nil {
		s.CustomDomain = &Domain{}
		defer func() {
			s.CustomDomain = nil
		}()
	}

	s.CustomDomain.ExtractTo(api)

	if s.DetailedActivityLogs == nil {
		s.DetailedActivityLogs = &DetailedActivityLogs{}
		defer func() {
			s.DetailedActivityLogs = nil
		}()
	}

	s.DetailedActivityLogs.ExtractTo(api)

	if s.DetailedTracing == nil {
		s.DetailedTracing = &DetailedTracing{}
		defer func() {
			s.DetailedTracing = nil
		}()
	}

	s.DetailedTracing.ExtractTo(api)

	if s.Events == nil {
		s.Events = Events{}
		defer func() {
			s.Events = nil
		}()
	}

	s.Events.ExtractTo(api)
}

// ListenPath is the base path on Tyk to which requests for this API
// should be sent. Tyk listens out for any requests coming into the host at
// this path, on the port that Tyk is configured to run on and processes
// these accordingly.
type ListenPath struct {
	// Value is the value of the listen path e.g. `/api/` or `/` or `/httpbin/`.
	// Tyk classic API definition: `proxy.listen_path`
	Value string `bson:"value" json:"value"` // required

	// Strip removes the inbound listen path (as accessed by the client) when generating the outbound request for the upstream service.
	//
	// For example, consider the scenario where the Tyk base address is `http://acme.com/', the listen path is `example/` and the upstream URL is `http://httpbin.org/`:
	//
	// - If the client application sends a request to `http://acme.com/example/get` then the request will be proxied to `http://httpbin.org/example/get`
	// - If stripListenPath is set to `true`, the `example` listen path is removed and the request would be proxied to `http://httpbin.org/get`.
	//
	// Tyk classic API definition: `proxy.strip_listen_path`
	Strip bool `bson:"strip,omitempty" json:"strip,omitempty"`
}

// Fill fills *ListenPath from apidef.APIDefinition.
func (lp *ListenPath) Fill(api apidef.APIDefinition) {
	lp.Value = api.Proxy.ListenPath
	lp.Strip = api.Proxy.StripListenPath
}

// ExtractTo extracts *ListenPath into *apidef.APIDefinition.
func (lp *ListenPath) ExtractTo(api *apidef.APIDefinition) {
	api.Proxy.ListenPath = lp.Value
	api.Proxy.StripListenPath = lp.Strip
}

// ClientCertificates contains the configurations related to establishing static mutual TLS between the client and Tyk.
type ClientCertificates struct {
	// Enabled activates static mTLS for the API.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Allowlist is the list of client certificates which are allowed.
	Allowlist []string `bson:"allowlist" json:"allowlist"`
}

// Fill fills *ClientCertificates from apidef.APIDefinition.
func (cc *ClientCertificates) Fill(api apidef.APIDefinition) {
	cc.Enabled = api.UseMutualTLSAuth
	cc.Allowlist = api.ClientCertificates
}

// ExtractTo extracts *ClientCertificates into *apidef.APIDefinition.
func (cc *ClientCertificates) ExtractTo(api *apidef.APIDefinition) {
	api.UseMutualTLSAuth = cc.Enabled
	api.ClientCertificates = cc.Allowlist
}

// GatewayTags holds a list of segment tags that should apply for a gateway.
type GatewayTags struct {
	// Enabled activates use of segment tags.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Tags is a list of segment tags
	Tags []string `bson:"tags" json:"tags"`
}

// Fill fills *GatewayTags from apidef.APIDefinition.
func (gt *GatewayTags) Fill(api apidef.APIDefinition) {
	gt.Enabled = !api.TagsDisabled
	gt.Tags = api.Tags
}

// ExtractTo extracts *GatewayTags into *apidef.APIDefinition.
func (gt *GatewayTags) ExtractTo(api *apidef.APIDefinition) {
	api.TagsDisabled = !gt.Enabled
	api.Tags = gt.Tags
}

// Domain holds the configuration of the domain name the server should listen on.
type Domain struct {
	// Enabled allow/disallow the usage of the domain.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Name is the name of the domain.
	Name string `bson:"name" json:"name"`
	// Certificates defines a field for specifying certificate IDs or file paths
	// that the Gateway can utilise to dynamically load certificates for your custom domain.
	//
	// Tyk classic API definition: `certificates`
	Certificates []string `bson:"certificates,omitempty" json:"certificates,omitempty"`
}

// ExtractTo extracts *Domain into *apidef.APIDefinition.
func (cd *Domain) ExtractTo(api *apidef.APIDefinition) {
	api.DomainDisabled = !cd.Enabled
	api.Domain = cd.Name
	api.Certificates = cd.Certificates
}

// Fill fills *Domain from apidef.APIDefinition.
func (cd *Domain) Fill(api apidef.APIDefinition) {
	cd.Enabled = !api.DomainDisabled
	cd.Name = api.Domain
	cd.Certificates = api.Certificates
}

// DetailedActivityLogs holds the configuration related to recording detailed analytics.
type DetailedActivityLogs struct {
	// Enabled activates detailed activity logs.
	//
	// Tyk classic API definition: `enable_detailed_recording`
	Enabled bool `bson:"enabled" json:"enabled"`
}

// ExtractTo extracts *DetailedActivityLogs into *apidef.APIDefinition.
func (d *DetailedActivityLogs) ExtractTo(api *apidef.APIDefinition) {
	api.EnableDetailedRecording = d.Enabled
}

// Fill fills *DetailedActivityLogs from apidef.APIDefinition.
func (d *DetailedActivityLogs) Fill(api apidef.APIDefinition) {
	d.Enabled = api.EnableDetailedRecording
}

// DetailedTracing holds the configuration of the detailed tracing.
type DetailedTracing struct {
	// Enabled activates detailed tracing.
	Enabled bool `bson:"enabled" json:"enabled"`
}

// Fill fills *DetailedTracing from apidef.APIDefinition.
func (dt *DetailedTracing) Fill(api apidef.APIDefinition) {
	dt.Enabled = api.DetailedTracing
}

// ExtractTo extracts *DetailedTracing into *apidef.APIDefinition.
func (dt *DetailedTracing) ExtractTo(api *apidef.APIDefinition) {
	api.DetailedTracing = dt.Enabled
}

// Event holds information about individual event to be configured on the API.
type Event struct {
	// Enabled enables the event handler.
	Enabled bool `json:"enabled" bson:"enabled"`
	// Type specifies the TykEvent that should trigger the event handler.
	Type event.Event `json:"type" bson:"type"`
	// Action specifies the action to be taken on the event trigger.
	Action event.Action `json:"action" bson:"action"`
	// ID is the ID of event handler in storage.
	ID string `json:"id,omitempty" bson:"id,omitempty"`
	// Name is the name of event handler
	Name string `json:"name,omitempty" bson:"name,omitempty"`

	Webhook WebhookEvent `bson:"-" json:"-"`
}

// MarshalJSON marshals Event as per Tyk OAS API definition contract.
func (e *Event) MarshalJSON() ([]byte, error) {
	outMap, err := reflect.Cast[map[string]interface{}](*e)
	if err != nil {
		return nil, err
	}

	webhookMap, err := reflect.Cast[map[string]interface{}](e.Webhook)
	if err != nil {
		return nil, err
	}

	for k, v := range webhookMap {
		outMap[k] = v
	}

	return json.Marshal(outMap)
}

// UnmarshalJSON unmarshals Event as per Tyk OAS API definition contract.
func (e *Event) UnmarshalJSON(in []byte) error {
	type helperEvent Event
	helper := helperEvent{}
	if err := json.Unmarshal(in, &helper); err != nil {
		return err
	}

	if err := json.Unmarshal(in, &helper.Webhook); err != nil {
		return err
	}

	*e = Event(helper)
	return nil
}

// WebhookEvent stores the core information about a webhook event.
type WebhookEvent struct {
	URL          string            `json:"url" bson:"url"`
	Method       string            `json:"method" bson:"method"`
	Timeout      int64             `json:"timeout" bson:"timeout"`
	BodyTemplate string            `json:"bodyTemplate,omitempty" bson:"bodyTemplate,omitempty"`
	Headers      map[string]string `json:"headers,omitempty" bson:"headers,omitempty"`
}

// GetWebhookConf converts Event to apidef.WebHookHandlerConf.
func (e *Event) GetWebhookConf() apidef.WebHookHandlerConf {
	return apidef.WebHookHandlerConf{
		Disabled:     !e.Enabled,
		ID:           e.ID,
		Name:         e.Name,
		Method:       e.Webhook.Method,
		TargetPath:   e.Webhook.URL,
		HeaderList:   e.Webhook.Headers,
		EventTimeout: e.Webhook.Timeout,
		TemplatePath: e.Webhook.BodyTemplate,
	}
}

// Events holds the list of events to be processed for the API.
type Events []Event

// Fill fills Events from classic API definition. Currently only webhook events are supported.
func (e *Events) Fill(api apidef.APIDefinition) {
	if len(api.EventHandlers.Events) == 0 {
		return
	}

	events := Events{}
	for gwEvent, ehs := range api.EventHandlers.Events {
		for _, eh := range ehs {
			if eh.Handler == event.WebHookHandler {
				whConf := apidef.WebHookHandlerConf{}
				err := whConf.Scan(eh.HandlerMeta)
				if err != nil {
					continue
				}

				ev := Event{
					Enabled: !whConf.Disabled,
					Type:    gwEvent,
					Action:  event.WebhookAction,
					ID:      whConf.ID,
					Name:    whConf.Name,
					Webhook: WebhookEvent{

						URL:          whConf.TargetPath,
						Method:       whConf.Method,
						Headers:      whConf.HeaderList,
						Timeout:      whConf.EventTimeout,
						BodyTemplate: whConf.TemplatePath,
					},
				}

				events = append(events, ev)
			}
		}
	}

	*e = events
}

// ExtractTo extracts events to apidef.APIDefinition.
func (e *Events) ExtractTo(api *apidef.APIDefinition) {
	if e == nil {
		return
	}

	for _, ev := range *e {
		var (
			handler     event.HandlerName
			handlerMeta map[string]interface{}
			err         error
		)

		switch ev.Action {
		case event.WebhookAction:
			handler = event.WebHookHandler
			whConf := ev.GetWebhookConf()
			handlerMeta, err = reflect.Cast[map[string]interface{}](whConf)
		default:
			continue
		}

		if err != nil {
			log.WithError(err).Error("error converting event to map")
			continue
		}

		eventHandlerTriggerConfig := apidef.EventHandlerTriggerConfig{
			Handler:     handler,
			HandlerMeta: handlerMeta,
		}

		if api.EventHandlers.Events == nil {
			api.EventHandlers.Events = make(map[apidef.TykEvent][]apidef.EventHandlerTriggerConfig)
		}

		if val, ok := api.EventHandlers.Events[ev.Type]; ok {
			api.EventHandlers.Events[ev.Type] = append(val, eventHandlerTriggerConfig)
			continue
		}

		api.EventHandlers.Events[ev.Type] = []apidef.EventHandlerTriggerConfig{eventHandlerTriggerConfig}
	}
}

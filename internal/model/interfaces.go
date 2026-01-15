package model

import (
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"

	persistentmodel "github.com/TykTechnologies/storage/persistent/model"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

// Gateway is a collection of well defined gateway interfaces. It should only
// be implemented in full by gateway.Gateway, and is used for a built-time
// type assertion. Do not use the symbol elsewhere, use the smaller interfaces.
type Gateway interface {
	ConfigProvider
	PolicyProvider

	ReplaceTykVariables
}

// Middleware is a subset of the gateway.Middleware interface, that can be
// implemented outside of gateway scope.
type Middleware interface {
	Init()
	Name() string
	Logger() *logrus.Entry
	ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) // Handles request
	EnabledForSpec() bool
	Unload()
}

// LoggerProvider returns a new *logrus.Entry for the request.
// It's implemented by gateway and middleware. Middleware typically
// adds the `mw` field with the middleware name.
type LoggerProvider interface {
	Logger() *logrus.Entry
}

// ConfigProvider provides a typical config getter signature.
type ConfigProvider interface {
	GetConfig() config.Config
}

// PolicyProvider is a storage interface encapsulating policy retrieval.
type PolicyProvider interface {
	PolicyCount() int
	PolicyIDs() []PolicyID
	PolicyByID(PolicyID) (user.Policy, bool)
}

// These are utility methods without any real data model design around them.
type (
	// ReplaceTykVariables is a request-based template replacement hook.
	// Implemented by gateway.Gateway.
	ReplaceTykVariables interface {
		ReplaceTykVariables(r *http.Request, in string, escape bool) string
	}

	// StripListenPath is the interface implemented by APISpec.StripListenPath.
	StripListenPath interface {
		StripListenPath(string) string
	}

	// StripListenPathFunc is the function signature for StripListenPath.
	StripListenPathFunc func(string) string
)

// PolicyID sealed interface
type PolicyID interface {
	fmt.Stringer
	IsIdentifierOf(user.Policy) bool
	markerPolicyId()
}

type BasePolicyId struct{}

func (i BasePolicyId) markerPolicyId() {}

var (
	_ PolicyID = NonScopedPolicyId("")
	_ PolicyID = ScopedPolicyId{}
)

// NewScopedPolicyId creates custom policy identifier
func NewScopedPolicyId(orgId, idOrCustomId string) ScopedPolicyId {
	return ScopedPolicyId{
		orgId: orgId,
		id:    idOrCustomId,
	}
}

// ScopedPolicyId represents any policy identifier (database and custom)
type ScopedPolicyId struct {
	BasePolicyId
	orgId string
	id    string
}

func (c ScopedPolicyId) IsIdentifierOf(pol user.Policy) bool {
	return pol.OrgID == c.orgId && c.id == pol.ID
}

func (c ScopedPolicyId) OrgId() string {
	return c.orgId
}

func (c ScopedPolicyId) Id() string {
	return c.id
}

func (c ScopedPolicyId) String() string {
	return c.id
}

func (c ScopedPolicyId) customKey() customKey {
	return customKey(c.id)
}

func (c ScopedPolicyId) markerPolicyId() {}

type NonScopedPolicyId string

func (c NonScopedPolicyId) IsIdentifierOf(pol user.Policy) bool {
	return persistentmodel.ObjectID(c) == pol.MID || string(c) == pol.ID
}

func (c NonScopedPolicyId) String() string {
	return persistentmodel.ObjectID(c).Hex()
}

func (c NonScopedPolicyId) markerPolicyId() {}

type InvalidPolicyId struct {
	BasePolicyId
}

func (i InvalidPolicyId) String() string {
	return ""
}

func (i InvalidPolicyId) IsIdentifierOf(_ user.Policy) bool {
	return false
}

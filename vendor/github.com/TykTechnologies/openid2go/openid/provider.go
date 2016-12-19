package openid

// Provider represents an OpenId Identity Provider (OP) and contains
// the information needed to perform validation of ID Token.
// See OpenId terminology http://openid.net/specs/openid-connect-core-1_0.html#Terminology.
//
// The Issuer uniquely identifies an OP. This field will be used
// to validate the 'iss' claim present in the ID Token.
//
// The CliendIDs contains the list of client IDs registered with the OP that are meant to be accepted by the service using this package.
// These values are used to validate the 'aud' clain present in the ID Token.
type Provider struct {
	Issuer    string
	ClientIDs []string
}

// providers represent a collection of OPs.
type providers []Provider

// NewProvider returns a new instance of a Provider created with the given issuer and clientIDs.
func NewProvider(issuer string, clientIDs []string) (Provider, error) {
	p := Provider{issuer, clientIDs}

	if err := p.validate(); err != nil {
		return Provider{}, err
	}

	return p, nil
}

// The GetProvidersFunc defines the function type used to retrieve the collection of allowed OP(s) along with the
// respective client IDs registered with those providers that can access the backend service
// using this package.
// A function of this type must be provided to NewConfiguration through the option ProvidersGetter.
// The given function will then be invoked for every request intercepted by the Authenticate or AuthenticateUser middleware.
type GetProvidersFunc func() ([]Provider, error)

func (ps providers) validate() error {
	if len(ps) == 0 {
		return &SetupError{Code: SetupErrorEmptyProviderCollection, Message: "The collection of providers must contain at least one element."}
	}

	for _, p := range ps {
		if err := p.validate(); err != nil {
			return err
		}
	}

	return nil
}

func (p Provider) validate() error {
	if err := validateProviderIssuer(p.Issuer); err != nil {
		return err
	}

	if err := validateProviderClientIDs(p.ClientIDs); err != nil {
		return err
	}

	return nil
}

func validateProviderIssuer(iss string) error {
	if iss == "" {
		return &SetupError{Code: SetupErrorInvalidIssuer, Message: "Empty string issuer not allowed."}
	}

	// TODO: Validate that the issuer format complies with openid spec.
	return nil
}

func validateProviderClientIDs(cIDs []string) error {
	if len(cIDs) == 0 {
		return &SetupError{Code: SetupErrorInvalidClientIDs, Message: "At leat one client id must be provided."}
	}

	return nil
}

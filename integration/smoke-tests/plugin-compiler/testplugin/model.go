package main

import "encoding/json"

type StringOrArrString []string

func (s *StringOrArrString) UnmarshalJSON(data []byte) error {
	if len(data) > 1 && data[0] == '[' {
		var obj []string
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		*s = StringOrArrString(obj)
		return nil
	}

	var obj string
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*s = StringOrArrString([]string{obj})
	return nil
}

// https://tools.ietf.org/html/rfc7662
type IntrospectResponse struct {
	// active REQUIRED.  Boolean indicator of whether or not the presented token
	//      is currently active.  The specifics of a token's "active" state
	//      will vary depending on the implementation of the authorization
	//      server and the information it keeps about its tokens, but a "true"
	//      value return for the "active" property will generally indicate
	//      that a given token has been issued by this authorization server,
	//      has not been revoked by the resource owner, and is within its
	//      given time window of validity (e.g., after its issuance time and
	//      before its expiration time).  See Section 4 for information on
	//      implementation of such checks.
	Active bool `json:"active"`
	// scope OPTIONAL.  A JSON string containing a space-separated list of
	//      scopes associated with this token, in the format described in
	//      Section 3.3 of OAuth 2.0 [RFC6749].
	Scope *string `json:"scope,omitempty"`
	// client_id OPTIONAL.  Client identifier for the OAuth 2.0 client that
	//      requested this token.
	ClientID *string `json:"client_id"`
	// username OPTIONAL.  Human-readable identifier for the resource owner who
	//      authorized this token.
	Username *string `json:"username"`
	// token_type OPTIONAL.  Type of the token as defined in Section 5.1 of OAuth
	//      2.0 [RFC6749].
	TokenType *string `json:"token_type"`
	// exp OPTIONAL.  Integer timestamp, measured in the number of seconds
	//      since January 1 1970 UTC, indicating when this token will expire,
	//      as defined in JWT [RFC7519].
	Exp *int64 `json:"exp"`
	// iat OPTIONAL.  Integer timestamp, measured in the number of seconds
	//      since January 1 1970 UTC, indicating when this token was
	//      originally issued, as defined in JWT [RFC7519].
	Iat *int64 `json:"iat"`
	// nbf OPTIONAL.  Integer timestamp, measured in the number of seconds
	//      since January 1 1970 UTC, indicating when this token is not to be
	//      used before, as defined in JWT [RFC7519].
	Nbf *int64 `json:"nbf"`
	// sub OPTIONAL.  Subject of the token, as defined in JWT [RFC7519].
	//      Usually a machine-readable identifier of the resource owner who
	//      authorized this token.
	Sub *string `json:"sub"`
	// aud OPTIONAL.  Service-specific string identifier or list of string
	//      identifiers representing the intended audience for this token, as
	//      defined in JWT [RFC7519].
	Aud *StringOrArrString `json:"aud"`
	// iss OPTIONAL.  String representing the issuer of this token, as
	//      defined in JWT [RFC7519].
	Iss *string `json:"iss"`
	// jti OPTIONAL.  String identifier for the token, as defined in JWT
	//      [RFC7519].
	Jti *string `json:"jti"`
}

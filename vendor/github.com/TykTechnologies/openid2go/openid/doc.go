/*Package openid implements web service middlewares for authenticating identities represented by
OpenID Connect (OIDC) ID Tokens.
For details on OIDC go to http://openid.net/specs/openid-connect-core-1_0.html

The middlewares will: extract the ID Token from the request; retrieve the OIDC provider (OP)
configuration and signing keys; validate the token and provide the user identity and claims to the
underlying web service.

The Basics

At the core of this package are the Authenticate and AuthenticateUser middlewares. To use either one
of them you will need an instance of the Configuration type, to create that you use NewConfiguration.

       func Authenticate(conf *Configuration, h http.Handler) http.Handler
       func AuthenticateUser(conf *Configuration, h UserHandler) http.Handler
       NewConfiguration(options ...option) (*Configuration, error)

       // options:

       func ErrorHandler(eh ErrorHandlerFunc) func(*Configuration) error
       func ProvidersGetter(pg GetProvidersFunc) func(*Configuration) error

       // extension points:

       type ErrorHandlerFunc func(error, http.ResponseWriter, *http.Request) bool
       type GetProvidersFunc func() ([]Provider, error)

The Example below demonstrates these elements working together.

Token Parsing

Both Authenticate and AuthenticateUser middlewares expect the incoming requests to have an HTTP
Authorization header with the content 'Bearer [idToken]' where [idToken] is a valid ID Token issued by
an OP. For instance:

        Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6...

By default, requests that do not contain an Authorization header with this content will not be forwarded
to the next HTTP handler in the pipeline, instead they will fail back to the client with HTTP status
400/Bad Request.

Token Validation

Once parsed the ID Token will be validated:

  1) Is the token a valid jwt?
  2) Is the token issued by a known OP?
  3) Is the token issued for a known client?
  4) Is the token valid at the time ('not use before' and 'expire at' claims)?
  5) Is the token signed accordingly?

The signature validation is done with the public keys retrieved from the jwks_uri published by the OP in
its OIDC metadata (https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

The token's issuer and audiences will be verified using a collection of the type Provider. This
collection is retrieved by calling the implementation of the function GetProvidersFunc registered with
the Configuration.
If the token issuer matches the Issuer of any of the providers and the token audience matches at least
one of the ClientIDs of the respective provider then the token is considered valid.

 func myGetProviders() ([]openid.Provider, error) {
     p, err := openid.NewProvider("https://accounts.google.com",
                                  []string{"407408718192.apps.googleusercontent.com"})
     // ....
     return []openid.Provider{p}, nil
 }

 c, _ := openid.NewConfiguration(openid.ProvidersGetter(myGetProviders))

In code above only tokens with Issuer claim ('iss') https://accounts.google.com and Audiences claim
('aud') containing "407408718192.apps.googleusercontent.com" can be valid.

By default, when the token validation fails for any reason the requests will not be forwarded to the next
handler in the pipeline, instead they will fail back to the client with HTTP status 401/Unauthorized.

Error Handling

The default behavior of the Authenticate and AuthenticateUser middlewares upon error conditions is:
the execution pipeline is stopped (the next handler will not be executed), the response will contain
status 400 when a token is not found and 401 when it is invalid, and the response will also contain the
error message.
This behavior can be changed by implementing a function of type ErrorHandlerFunc and registering it
using ErrorHandler with the Configuration.

 type ErrorHandlerFunc func(error, http.ResponseWriter, *http.Request) bool
 func ErrorHandler(eh ErrorHandlerFunc) func(*Configuration) error

For instance:

 func myErrorHandler(e error, w http.ResponseWriter, r *http.Request) bool {
     fmt.Fprintf(w, e.Error())
     return false
 }

 c, _ := openid.NewConfiguration(openid.ProvidersGetter(myGetProviders),
                                 openid.ErrorHandler(myErrorHandler))

In the code above myErrorHandler adds the error message to the response and let the execution
continue to the next handler in the pipeline (returning false) for all error types.
You can use this extension point to fine tune what happens when a specific error is returned by your
implementation of the GetProvidersFunc or even for the error types and codes exported by this
package:

  type ValidationError struct
  type ValidationErrorCode uint32
  type SetupError struct
  type SetupErrorCode uint32

Authenticate vs AuthenticateUser

Both middlewares Authenticate and AuthenticateUser behave exactly the same way when it comes to
parsing and validating the ID Token. The only difference is that AuthenticateUser will forward the
information about the user's identity from the ID Token to the next handler in the pipeline.
If your service does not need to know the identity of the authenticated user then Authenticate will
suffice, otherwise your choice is AuthenticateUser.
In order to receive the User information from the AuthenticateUser the next handler in the pipeline
must implement the interface UserHandler with the following function:

 ServeHTTPWithUser(*User, http.ResponseWriter, *http.Request)

You can also make use of the function adapter UserHandlerFunc as shown in the example below:

 func myHandlerWithUser(u *openid.User, w http.ResponseWriter, r *http.Request) {
     fmt.Fprintf(w, "Authenticated! The user is %+v.", u)
 }

 http.Handle("/user", openid.AuthenticateUser(c, openid.UserHandlerFunc(myHandlerWithUser)))
*/
package openid

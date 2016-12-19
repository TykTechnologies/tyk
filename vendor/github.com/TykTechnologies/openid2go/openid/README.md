Go OpenId
===========
[![godoc](http://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/emanoelxavier/openid2go/openid)
[![license](http://img.shields.io/badge/license-MIT-yellowgreen.svg?style=flat)](https://raw.githubusercontent.com/emanoelxavier/openid2go/master/openid/LICENSE)
## Summary

A Go package that implements web service middlewares for authenticating identities represented by OpenID Connect (OIDC) ID Tokens.

"OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It enables Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server"  - [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html)

## Installation

go get github.com/emanoelxavier/openid2go/openid

## Example
This example demonstrates how to use this package to validate incoming ID Tokens. It initializes the Configuration with the desired providers (OPs) and registers two middlewares: openid.Authenticate and openid.AuthenticateUser. The former performs the token validation while the latter, in addition to that, will forward the user information to the next handler.

```go
import (
	"fmt"
	"net/http"

	"github.com/emanoelxavier/openid2go/openid"
)

func AuthenticatedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "The user was authenticated!")
}

func AuthenticatedHandlerWithUser(u *openid.User, w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "The user was authenticated! The token was issued by %v and the user is %+v.", u.Issuer, u)
}

func Example() {
	configuration, err := openid.NewConfiguration(openid.ProvidersGetter(getProviders_googlePlayground))

	if err != nil {
		panic(err)
	}
	
	http.Handle("/user", openid.AuthenticateUser(configuration, openid.UserHandlerFunc(AuthenticatedHandlerWithUser)))
	http.Handle("/authn", openid.Authenticate(configuration, http.HandlerFunc(AuthenticatedHandler)))
	
	http.ListenAndServe(":5100", nil)
}

func myGetProviders() ([]openid.Provider, error) {
	provider, err := openid.NewProvider("https://providerissuer", []string{"myClientID"})

	if err != nil {
		return nil, err
	}

	return []openid.Provider{provider}, nil
}
```
This example is also available in the documentation of this package, for more details see [GoDoc](https://godoc.org/github.com/emanoelxavier/openid2go/openid).

## Tests

#### Unit Tests
```sh
go test github.com/emanoelxavier/openid2go/openid
```

#### Integration Tests
In addition to to unit tests, this package also comes with integration tests that will validate real ID Tokens issued by real OIDC providers. The following command will run those tests:

```sh
go test -tags integration github.com/emanoelxavier/openid2go/openid -issuer=[issuer] -clientID=[clientID] -idToken=[idToken]
```

Replace [issuer], [clientID] and [idToken] with the information from an identity provider of your choice. 

For a quick spin you can use it with tokens issued by Google for the [Google OAuth PlayGround](https://developers.google.com/oauthplayground) entering "openid" (without quotes) within the scope field and copying the issued ID Token. For this provider and client the values will be:

```sh
go test -tags integration github.com/emanoelxavier/openid2go/openid -issuer=https://accounts.google.com -clientID=407408718192.apps.googleusercontent.com -idToken=copiedIDToken
```

## Contributing

1. Open an issue if found a bug or have a functional request.
2. Disccuss.
3. Branch off, write the fix with test(s) and commit attaching to the issue.
4. Make a pull request.
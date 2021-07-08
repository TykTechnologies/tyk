OSIN
====

[![GoDoc](https://godoc.org/github.com/RangelReale/osin?status.svg)](https://godoc.org/github.com/RangelReale/osin)


Golang OAuth2 server library
----------------------------

OSIN is an OAuth2 server library for the Go language, as specified at
http://tools.ietf.org/html/rfc6749 and http://tools.ietf.org/html/draft-ietf-oauth-v2-10.

It also includes support for PKCE, as specified at https://tools.ietf.org/html/rfc7636,
which increases security for code-exchange flows for public OAuth clients.

Using it, you can build your own OAuth2 authentication service.

The library implements the majority of the specification, like authorization and token endpoints, and authorization code, implicit, resource owner and client credentials grant types.

### Example Server

````go
import (
	"github.com/RangelReale/osin"
	ex "github.com/RangelReale/osin/example" 
)

// ex.NewTestStorage implements the "osin.Storage" interface
server := osin.NewServer(osin.NewServerConfig(), ex.NewTestStorage())

// Authorization code endpoint
http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
	resp := server.NewResponse()
	defer resp.Close()

	if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {

		// HANDLE LOGIN PAGE HERE

		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, r, ar)
	}
	osin.OutputJSON(resp, w, r)
})

// Access token endpoint
http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
	resp := server.NewResponse()
	defer resp.Close()

	if ar := server.HandleAccessRequest(resp, r); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, r, ar)
	}
	osin.OutputJSON(resp, w, r)
})

http.ListenAndServe(":14000", nil)
````

### Example Access

Open in your web browser:

````
http://localhost:14000/authorize?response_type=code&client_id=1234&redirect_uri=http%3A%2F%2Flocalhost%3A14000%2Fappauth%2Fcode
````

### Storage backends

There is a mock available at [example/teststorage.go](/example/teststorage.go) which you can use as a guide for writing your own.  

You might want to check out other implementations for common database management systems as well:

* [PostgreSQL](https://github.com/ory-am/osin-storage)
* [MongoDB](https://github.com/martint17r/osin-mongo-storage)
* [RethinkDB](https://github.com/ahmet/osin-rethinkdb)
* [DynamoDB](https://github.com/uniplaces/osin-dynamodb)
* [Couchbase](https://github.com/elgris/osin-couchbase-storage)
* [MySQL](https://github.com/felipeweb/osin-mysql)
* [Redis](https://github.com/ShaleApps/osinredis)

### License

The code is licensed using "New BSD" license.

### Author

Rangel Reale
rangelreale@gmail.com

### Changes

2014-06-25
==========
* BREAKING CHANGES:
	- Storage interface has 2 new methods, Clone and Close, to better support storages
	  that need to clone / close in each connection (mgo)
	- Client was changed to be an interface instead of an struct. Because of that,
	  the Storage interface also had to change, as interface is already a pointer.

	- HOW TO FIX YOUR CODE:
		+ In your Storage, add a Clone function returning itself, and a do nothing Close.
		+ In your Storage, replace all *osin.Client with osin.Client (remove the pointer reference)
		+ If you used the osin.Client struct directly in your code, change it to osin.DefaultClient,
		  which is a struct with the same fields that implements the interface.
		+ Change all accesses using osin.Client to use the methods instead of the fields directly.
		+ You MUST defer Response.Close in all your http handlers, otherwise some
		  Storages may not clean correctly.

				resp := server.NewResponse()
				defer resp.Close()

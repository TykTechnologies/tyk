package swagger

var isRequired = true

const TykDesc = `The Tyk Gateway API is the primary means for integrating your application with the Tyk API Gateway system. This API is very small, and has no granular permissions system. It is intended to be used purely for internal automation and integration.

**Warning: Under no circumstances should outside parties be granted access to this API.**

The Tyk Gateway API is capable of:

* Managing session objects (key generation).
* Managing and listing policies.
* Managing and listing API Definitions (only when not using the Tyk Dashboard).
* Hot reloads / reloading a cluster configuration.
* OAuth client creation (only when not using the Tyk Dashboard).

In order to use the Gateway API, you'll need to set the **secret** parameter in your tyk.conf file.

The shared secret you set should then be sent along as a header with each Gateway API Request in order for it to be successful:

**x-tyk-authorization: <your-secret>***
<br/>

<b>The Tyk Gateway API is subsumed by the Tyk Dashboard API in Pro installations.</b>

`

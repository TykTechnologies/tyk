# Redis in the gateway

This is a summary of redis usage in the gateway and my proposal on how to decouple
redis dependency. The goal is to make redis optional for the gateway to be operation.

This document also highlights the cons/pros of decoupling redis and its impact on
the gateway operations.

# General redis storages

There are four different stores used. The stores are differentiated with key prefix.

- `base` : prefix `apiKey-`
- `org` : prefix `orgkey.`
- `health` : prefix `apihealth.`
- `rpcAuth` : prefix `apiKey-`
- `rpcOrg` : prefix `orgkey.`


## Base store

Base store stores values under the `apiKey-` prefix.

Used by
- `FallbackKeySesionManager`
- `APISpec.AuthManager` as the default store when `APISpec.AuthProvider.StorageEngine` is not provided.
- `APISpec.SessionManager` as the default storage when `APISpec.SessionProvider.StorageEngine` is not specified to `RPCStorageEngine`

Both of about api's uses this store as key/value store so its possible to be replaced.
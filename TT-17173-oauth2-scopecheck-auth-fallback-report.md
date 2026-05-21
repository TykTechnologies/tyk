# TT-17173 OAuth2 Scope Check: Auth Fallback Scenario

## Summary

The Jira-shaped OAS config for `oauth2.scopeCheck` enables API authentication, but the new OAS-native OAuth2 scheme does not enable any concrete gateway authenticator during extraction. In the normal gateway load path this can cause the API to fall back to default Tyk key authentication before `OAuth2Middleware` runs.

## Scenario

Advertised config shape:

```yaml
security:
  - oauth2: [api:access]

x-tyk-api-gateway:
  server:
    authentication:
      enabled: true
      securitySchemes:
        oauth2:
          enabled: true
          header: { enabled: true, name: Authorization }
          scopeCheck:
            enabled: true
```

Expected behavior: a Bearer JWT reaches `OAuth2Middleware`, scopes are evaluated, and a missing scope returns `403 insufficient_scope`.

Observed extraction behavior: `authentication.enabled: true` becomes `UseKeylessAccess=false`, but the OAS-native `oauth2` branch skips classic auth extraction. No JWT, External OAuth, classic OAuth, or standard auth middleware is enabled from this config alone.

## Why It Fails

When `UseKeylessAccess=false`, `api_loader.go` builds the auth chain. If no concrete auth middleware was added, it appends default `AuthKey` middleware:

```go
if spec.UseStandardAuth || len(authArray) == 0 {
    authKeyMW := &AuthKey{baseMid.Copy()}
    authArray = append(authArray, gw.createMiddleware(authKeyMW))
}
```

`OAuth2Middleware` is appended later. A normal Bearer JWT is therefore treated as a Tyk API key first and can be rejected before scope-check enforcement executes.

## Demonstrating Test

Temporary regression test added in the PR scratch worktree:

```go
func TestOAuth2ScopeCheck_JiraShapeEnablesConcreteAuthenticator(t *testing.T) {
    // Build the Jira-shaped OAS document, then:
    var api apidef.APIDefinition
    doc.extractSecurityTo(&api)

    require.False(t, api.UseKeylessAccess)
    assert.True(t,
        api.EnableJWT || api.ExternalOAuth.Enabled || api.UseOauth2 || api.UseStandardAuth,
        "an authenticated oauth2 scopeCheck API must enable a concrete authenticator")
}
```

Command:

```bash
GOCACHE=/private/tmp/tyk-go-cache go test -count=1 ./apidef/oas -run TestOAuth2ScopeCheck_JiraShapeEnablesConcreteAuthenticator
```

Result:

```text
--- FAIL: TestOAuth2ScopeCheck_JiraShapeEnablesConcreteAuthenticator
    oauth2_test.go:333:
        Error: Should be true
        Messages: an authenticated oauth2 scopeCheck API must enable a concrete authenticator; otherwise api_loader falls back to default Tyk key auth before OAuth2Middleware runs
```

## Impact

This is a release blocker for the advertised configuration path. Operators following the Jira example may see valid Bearer JWT requests fail as missing or invalid Tyk keys instead of receiving OAuth2 scope enforcement behavior.

## Fix Direction

The OAS-native OAuth2 scope-check configuration needs an explicit authentication path. Options include:

- wire the OAS-native oauth2 scheme to a concrete JWT/introspection authenticator before `OAuth2Middleware`;
- prevent default `AuthKey` fallback when the only configured scheme is OAS-native oauth2 scope-check;
- or require and validate an accompanying JWT/External OAuth scheme, with tests proving the Jira-shaped config works end to end.

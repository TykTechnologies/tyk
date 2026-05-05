package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/user"
)

// markedRequest constructs a request that is marked for auth-skip and
// carries a synthetic session in context — the standard input for every
// per-site skip-auth test. It bypasses ctxSetSession (which depends on
// global config) and writes the session value directly.
func markedRequest(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	sess := &user.SessionState{KeyID: "synthetic"}
	c := context.WithValue(r.Context(), ctx.SessionData, sess)
	r = r.WithContext(c)
	r = httpctx.SetSkipAuth(r)
	return r
}

// TestSkipAuthHelper covers the helper itself in isolation.
func TestSkipAuthHelper(t *testing.T) {
	t.Run("unmarked request returns false, nil", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		skip, sess := skipAuthIfMarked(r)
		if skip {
			t.Fatalf("expected skip=false on unmarked request, got true")
		}
		if sess != nil {
			t.Fatalf("expected sess=nil on unmarked request, got %v", sess)
		}
	})

	t.Run("marked request without session still returns true", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		r = httpctx.SetSkipAuth(r)
		skip, sess := skipAuthIfMarked(r)
		if !skip {
			t.Fatalf("expected skip=true on marked request, got false")
		}
		if sess != nil {
			t.Fatalf("expected sess=nil when no session set, got %v", sess)
		}
	})

	t.Run("marked request with session returns true and the session", func(t *testing.T) {
		r := markedRequest(t)
		skip, sess := skipAuthIfMarked(r)
		if !skip {
			t.Fatalf("expected skip=true, got false")
		}
		if sess == nil {
			t.Fatalf("expected non-nil session, got nil")
		}
		if sess.KeyID != "synthetic" {
			t.Fatalf("expected session.KeyID=synthetic, got %q", sess.KeyID)
		}
	})
}

// assertSkipped runs a per-site assertion: the middleware must return
// (nil, 200) on a marked request without panicking. A panic here means
// the helper is not the FIRST statement of ProcessRequest — something
// else dereferenced Spec/IDP/etc. before the short-circuit.
func assertSkipped(t *testing.T, name string, fn func(http.ResponseWriter, *http.Request, interface{}) (error, int)) {
	t.Helper()
	r := markedRequest(t)
	w := httptest.NewRecorder()
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("[%s] ProcessRequest panicked on skip-auth path (helper not first?): %v", name, rec)
		}
	}()
	err, code := fn(w, r, nil)
	if err != nil {
		t.Fatalf("[%s] expected nil error on skip-auth, got %v (code=%d)", name, err, code)
	}
	if code != http.StatusOK {
		t.Fatalf("[%s] expected status %d on skip-auth, got %d", name, http.StatusOK, code)
	}
}

func TestAuthKey_SkipAuth(t *testing.T) {
	mw := &AuthKey{BaseMiddleware: &BaseMiddleware{}}
	assertSkipped(t, "AuthKey", mw.ProcessRequest)
}

func TestBasicAuth_SkipAuth(t *testing.T) {
	mw := &BasicAuthKeyIsValid{BaseMiddleware: &BaseMiddleware{}}
	assertSkipped(t, "BasicAuthKeyIsValid", mw.ProcessRequest)
}

func TestJWT_SkipAuth(t *testing.T) {
	mw := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{}}
	assertSkipped(t, "JWTMiddleware", mw.ProcessRequest)
}

func TestOauth2KeyExists_SkipAuth(t *testing.T) {
	mw := &Oauth2KeyExists{BaseMiddleware: &BaseMiddleware{}}
	assertSkipped(t, "Oauth2KeyExists", mw.ProcessRequest)
}

func TestExternalOAuth_SkipAuth(t *testing.T) {
	mw := &ExternalOAuthMiddleware{BaseMiddleware: &BaseMiddleware{}}
	assertSkipped(t, "ExternalOAuthMiddleware", mw.ProcessRequest)
}

func TestOpenID_SkipAuth(t *testing.T) {
	mw := &OpenIDMW{BaseMiddleware: &BaseMiddleware{}}
	assertSkipped(t, "OpenIDMW", mw.ProcessRequest)
}

func TestHTTPSignatureValidation_SkipAuth(t *testing.T) {
	mw := &HTTPSignatureValidationMiddleware{BaseMiddleware: &BaseMiddleware{}}
	assertSkipped(t, "HTTPSignatureValidationMiddleware", mw.ProcessRequest)
}

func TestCoProcess_SkipAuth(t *testing.T) {
	mw := &CoProcessMiddleware{BaseMiddleware: &BaseMiddleware{}, HookType: coprocess.HookType_Pre}
	assertSkipped(t, "CoProcessMiddleware", mw.ProcessRequest)
}

func TestGoPlugin_SkipAuth(t *testing.T) {
	mw := &GoPluginMiddleware{BaseMiddleware: &BaseMiddleware{}}
	assertSkipped(t, "GoPluginMiddleware", mw.ProcessRequest)
}

func TestDynamicMiddleware_SkipAuth(t *testing.T) {
	// The JS plugin's helper guard fires only when Auth=true (the
	// auth-check role). With Auth=false the middleware is in another
	// role (pre/post body transform) and is not on the auth path.
	mw := &DynamicMiddleware{BaseMiddleware: &BaseMiddleware{}, Auth: true}
	assertSkipped(t, "DynamicMiddleware", mw.ProcessRequest)
}

func TestAuthORWrapper_SkipAuth(t *testing.T) {
	mw := &AuthORWrapper{}
	assertSkipped(t, "AuthORWrapper", mw.ProcessRequest)
}

func TestCertificateCheck_SkipAuth(t *testing.T) {
	mw := &CertificateCheckMW{BaseMiddleware: &BaseMiddleware{}}
	assertSkipped(t, "CertificateCheckMW", mw.ProcessRequest)
}

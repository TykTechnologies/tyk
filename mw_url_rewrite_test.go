package main

import (
	"net/http/httptest"
	"testing"

	"bytes"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

func TestRewriter(t *testing.T) {
	tests := []struct {
		name        string
		pattern, to string
		in, want    string
	}{
		{
			"Straight",
			"/test/straight/rewrite", "/change/to/me",
			"/test/straight/rewrite", "/change/to/me",
		},
		{
			"OneVal",
			"test/val/(.*)", "change/to/$1",
			"/test/val/VALUE", "change/to/VALUE",
		},
		{
			"ThreeVals",
			"/test/val/(.*)/space/(.*)/and/then/(.*)", "/change/to/$1/$2/$3",
			"/test/val/ONE/space/TWO/and/then/THREE", "/change/to/ONE/TWO/THREE",
		},
		{
			"Reverse",
			"/test/val/(.*)/space/(.*)/and/then/(.*)", "/change/to/$3/$2/$1",
			"/test/val/ONE/space/TWO/and/then/THREE", "/change/to/THREE/TWO/ONE",
		},
		{
			"Missing",
			"/test/val/(.*)/space/(.*)/and/then/(.*)", "/change/to/$1/$2",
			"/test/val/ONE/space/TWO/and/then/THREE", "/change/to/ONE/TWO",
		},
		{
			"MissingAgain",
			"/test/val/(.*)/space/(.*)/and/then/(.*)", "/change/to/$3/$1",
			"/test/val/ONE/space/TWO/and/then/THREE", "/change/to/THREE/ONE",
		},
		{
			"QS",
			"(.*)", "$1&newParam=that",
			"/foo/bar?param1=this", "/foo/bar?param1=this&newParam=that",
		},
		{
			"QS2",
			"/test/val/(.*)/space/(.*)/and/then(.*)", "/change/to/$2/$1$3",
			"/test/val/ONE/space/TWO/and/then?param1=this", "/change/to/TWO/ONE?param1=this",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testConf := apidef.URLRewriteMeta{
				MatchPattern: tc.pattern,
				RewriteTo:    tc.to,
			}
			r := httptest.NewRequest("GET", tc.in, nil)
			got, err := urlRewrite(&testConf, r)
			if err != nil {
				t.Error("compile failed:", err)
			}
			if got != tc.want {
				t.Errorf("rewrite failed, want %q, got %q", tc.want, got)
			}
		})
	}
}

func TestRewriterTriggers(t *testing.T) {
	type TestDef struct {
		name        string
		pattern, to string
		in, want    string
		triggerConf []apidef.RoutingTrigger
		req         *http.Request
	}
	tests := []func() TestDef{
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/straight/rewrite", nil)

			patt := "hello"
			r.Header.Set("x-test", patt)

			hOpt := apidef.StringRegexMap{MatchPattern: "hello"}
			hOpt.Init()

			return TestDef{
				"Header Single",
				"/test/straight/rewrite", "/change/to/me/ignore",
				"/test/straight/rewrite", "/change/to/me/hello",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							HeaderMatches: map[string]apidef.StringRegexMap{
								"x-test": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-X-Test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/straight/rewrite", nil)

			patt := "bar"
			r.Header.Set("x-test-Two", patt)

			hOpt := apidef.StringRegexMap{MatchPattern: "hello"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt2.Init()

			return TestDef{
				"Header Multi Any",
				"/test/straight/rewrite", "/change/to/me/ignore",
				"/test/straight/rewrite", "/change/to/me/bar",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							HeaderMatches: map[string]apidef.StringRegexMap{
								"x-test":     hOpt,
								"x-test-Two": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-X-Test-Two-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/straight/rewrite", nil)

			patt := "bar"
			r.Header.Set("x-test-Two", patt)

			hOpt := apidef.StringRegexMap{MatchPattern: "hello"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt2.Init()

			return TestDef{
				"Header Multi All Fail",
				"/test/straight/rewrite", "/change/to/me/ignore",
				"/test/straight/rewrite", "/change/to/me/ignore",
				[]apidef.RoutingTrigger{
					{
						On: apidef.All,
						Options: apidef.RoutingTriggerOptions{
							HeaderMatches: map[string]apidef.StringRegexMap{
								"x-test":     hOpt,
								"x-test-Two": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-X-Test-Two-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/straight/rewrite", nil)

			r.Header.Set("x-test-Two", "bar")
			r.Header.Set("x-test", "hello")

			hOpt := apidef.StringRegexMap{MatchPattern: "hello"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt2.Init()

			return TestDef{
				"Header Multi All Pass",
				"/test/straight/rewrite", "/change/to/me/ignore",
				"/test/straight/rewrite", "/change/to/me/hello",
				[]apidef.RoutingTrigger{
					{
						On: apidef.All,
						Options: apidef.RoutingTriggerOptions{
							HeaderMatches: map[string]apidef.StringRegexMap{
								"x-test":     hOpt,
								"x-test-Two": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-X-Test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/straight/rewrite", nil)

			r.Header.Set("y-test", "baz")
			r.Header.Set("y-test-Two", "qux")

			hOpt := apidef.StringRegexMap{MatchPattern: "hello"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt2.Init()

			hOpt3 := apidef.StringRegexMap{MatchPattern: "baz"}
			hOpt3.Init()
			hOpt4 := apidef.StringRegexMap{MatchPattern: "fnee"}
			hOpt4.Init()

			return TestDef{
				"Header Many Multi Any Pass",
				"/test/straight/rewrite", "/change/to/me/ignore",
				"/test/straight/rewrite", "/change/to/me/baz",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							HeaderMatches: map[string]apidef.StringRegexMap{
								"x-test":     hOpt,
								"x-test-Two": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-X-Test-0",
					},
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							HeaderMatches: map[string]apidef.StringRegexMap{
								"y-test":     hOpt3,
								"y-test-Two": hOpt4,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-1-Y-Test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/query/rewrite?x_test=foo", nil)

			hOpt := apidef.StringRegexMap{MatchPattern: "foo"}
			hOpt.Init()

			return TestDef{
				"Query Single",
				"/test/query/rewrite", "/change/to/me/ignore",
				"/test/query/rewrite", "/change/to/me/foo",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							QueryValMatches: map[string]apidef.StringRegexMap{
								"x_test": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-x_test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/query/rewrite?x_test=foo&y_test=bar", nil)

			hOpt := apidef.StringRegexMap{MatchPattern: "foo"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt2.Init()

			return TestDef{
				"Query Multi All",
				"/test/query/rewrite", "/change/to/me/ignore",
				"/test/query/rewrite", "/change/to/me/bar",
				[]apidef.RoutingTrigger{
					{
						On: apidef.All,
						Options: apidef.RoutingTriggerOptions{
							QueryValMatches: map[string]apidef.StringRegexMap{
								"x_test": hOpt,
								"y_test": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-y_test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/query/rewrite?x_test=foo", nil)
			r.Header.Set("y-test", "qux")

			hOpt := apidef.StringRegexMap{MatchPattern: "foo"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt2.Init()

			return TestDef{
				"Multi Multi Type Any",
				"/test/query/rewrite", "/change/to/me/ignore",
				"/test/query/rewrite", "/change/to/me/foo",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							QueryValMatches: map[string]apidef.StringRegexMap{
								"x_test": hOpt,
							},
							HeaderMatches: map[string]apidef.StringRegexMap{
								"y-test": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-x_test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/query/rewrite?x_test=foo", nil)
			r.Header.Set("y-test", "bar")

			hOpt := apidef.StringRegexMap{MatchPattern: "foo"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt2.Init()

			return TestDef{
				"Multi Multi Type All",
				"/test/query/rewrite", "/change/to/me/ignore",
				"/test/query/rewrite", "/change/to/me/bar",
				[]apidef.RoutingTrigger{
					{
						On: apidef.All,
						Options: apidef.RoutingTriggerOptions{
							QueryValMatches: map[string]apidef.StringRegexMap{
								"x_test": hOpt,
							},
							HeaderMatches: map[string]apidef.StringRegexMap{
								"y-test": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-Y-Test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/query/rewrite?x_test=foo", nil)
			r.Header.Set("y-test", "bar")
			r.Header.Set("z-test", "fnee")

			hOpt := apidef.StringRegexMap{MatchPattern: "foo"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt2.Init()
			hOpt3 := apidef.StringRegexMap{MatchPattern: "baz"}
			hOpt3.Init()

			return TestDef{
				"Multi Multi Type All Fail",
				"/test/query/rewrite", "/change/to/me/ignore",
				"/test/query/rewrite", "/change/to/me/ignore",
				[]apidef.RoutingTrigger{
					{
						On: apidef.All,
						Options: apidef.RoutingTriggerOptions{
							QueryValMatches: map[string]apidef.StringRegexMap{
								"x_test": hOpt,
							},
							HeaderMatches: map[string]apidef.StringRegexMap{
								"y-test": hOpt2,
								"z-test": hOpt3,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-Y-Test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			var jsonStr = []byte(`{"foo":"bar"}`)
			r, _ := http.NewRequest("POST", "/test/pl/rewrite", bytes.NewBuffer(jsonStr))

			hOpt := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt.Init()

			return TestDef{
				"Payload Single",
				"/test/pl/rewrite", "/change/to/me/ignore",
				"/test/pl/rewrite", "/change/to/me/bar",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PayloadMatches: hOpt,
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-payload",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/foo/rewrite", nil)
			hOpt := apidef.StringRegexMap{MatchPattern: "foo"}
			hOpt.Init()

			return TestDef{
				"PathPart Single",
				"/test/foo/rewrite", "/change/to/me/ignore",
				"/test/foo/rewrite", "/change/to/me/foo",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PathPartMatches: map[string]apidef.StringRegexMap{
								"pathpart": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-pathpart-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/foo/rewrite/foo", nil)
			hOpt := apidef.StringRegexMap{MatchPattern: "foo"}
			hOpt.Init()

			return TestDef{
				"PathPart MoreParts",
				"/test/foo/rewrite/foo", "/change/to/me/ignore",
				"/test/foo/rewrite/foo", "/change/to/me/foo/biz/foo",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PathPartMatches: map[string]apidef.StringRegexMap{
								"pathpart": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-pathpart-0/biz/$tyk_context.trigger-0-pathpart-1",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/foo/rewrite", nil)
			hOpt := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt.Init()

			return TestDef{
				"Meta Simple",
				"/test/foo/rewrite", "/change/to/me/ignore",
				"/test/foo/rewrite", "/change/to/me/bar",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							SessionMetaMatches: map[string]apidef.StringRegexMap{
								"rewrite": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-rewrite",
					},
				},
				r,
			}
		},
	}
	for _, tf := range tests {
		tc := tf()
		t.Run(tc.name, func(t *testing.T) {
			testConf := apidef.URLRewriteMeta{
				MatchPattern: tc.pattern,
				RewriteTo:    tc.to,
				Triggers:     tc.triggerConf,
			}

			ctxSetSession(tc.req, &user.SessionState{
				MetaData: map[string]interface{}{
					"rewrite": "bar",
				},
			})

			got, err := urlRewrite(&testConf, tc.req)
			if err != nil {
				t.Error("compile failed:", err)
			}
			if got != tc.want {
				t.Errorf("rewrite failed, want %q, got %q", tc.want, got)
			}
		})
	}
}

func TestInitTriggerRx(t *testing.T) {
	// prepare test data
	testRewriteMW := &URLRewriteMiddleware{
		BaseMiddleware: BaseMiddleware{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{},
			},
		},
	}
	testRewriteMW.Spec.APIDefinition.VersionData = struct {
		NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
		DefaultVersion string                        `bson:"default_version" json:"default_version"`
		Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
	}{}

	routingTriggerOptions := apidef.RoutingTriggerOptions{
		HeaderMatches: map[string]apidef.StringRegexMap{
			"abc": {
				MatchPattern: "^abc.*",
			},
		},
		QueryValMatches: map[string]apidef.StringRegexMap{
			"def": {
				MatchPattern: "^def.*",
			},
		},
		PayloadMatches: apidef.StringRegexMap{
			MatchPattern: "^ghi.*",
		},
	}

	extendedPathsSet := apidef.ExtendedPathsSet{
		URLRewrite: []apidef.URLRewriteMeta{
			{
				Triggers: []apidef.RoutingTrigger{
					{
						Options: routingTriggerOptions,
					},
				},
			},
		},
	}
	testRewriteMW.Spec.APIDefinition.VersionData.Versions = map[string]apidef.VersionInfo{
		"Default": {
			ExtendedPaths: extendedPathsSet,
		},
	}

	// run method under test
	testRewriteMW.InitTriggerRx()

	// assert HeaderMatches
	headerMatch := testRewriteMW.
		Spec.
		APIDefinition.
		VersionData.
		Versions["Default"].
		ExtendedPaths.
		URLRewrite[0].
		Triggers[0].
		Options.
		HeaderMatches["abc"]
	if headerMatch.Check("abc") == "" {
		t.Errorf("Expected HeaderMatches initalized and matched, received no match")
	}

	// assert QueryValMatches
	queryValMatch := testRewriteMW.
		Spec.
		APIDefinition.
		VersionData.
		Versions["Default"].
		ExtendedPaths.
		URLRewrite[0].
		Triggers[0].
		Options.
		QueryValMatches["def"]
	if queryValMatch.Check("def") == "" {
		t.Errorf("Expected QueryValMatches initalized and matched, received no match")
	}

	// assert PayloadMatches
	payloadMatch := testRewriteMW.
		Spec.
		APIDefinition.
		VersionData.
		Versions["Default"].
		ExtendedPaths.
		URLRewrite[0].
		Triggers[0].
		Options.
		PayloadMatches
	if payloadMatch.Check("ghi") == "" {
		t.Errorf("Expected PayloadMatches initalized and matched, received no match")
	}
}

package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/test"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

var testRewriterData = []struct {
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

type testRewriterCase struct {
	name     string
	meta     *apidef.URLRewriteMeta
	reqMaker func() *http.Request
	want     string
}

func prepareRewriterCases() []testRewriterCase {
	tcs := make([]testRewriterCase, len(testRewriterData))
	for i, td := range testRewriterData {
		reqTarget := td.in
		tcs[i] = testRewriterCase{
			name: td.name,
			meta: &apidef.URLRewriteMeta{
				MatchPattern: td.pattern,
				RewriteTo:    td.to,
			},
			reqMaker: func() *http.Request {
				return httptest.NewRequest("GET", reqTarget, nil)
			},
			want: td.want,
		}
	}
	return tcs
}

func TestRewriter(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	cases := prepareRewriterCases()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.reqMaker()
			got, err := ts.Gw.urlRewrite(tc.meta, r)
			if err != nil {
				t.Error("compile failed:", err)
			}
			if got != tc.want {
				t.Errorf("rewrite failed, want %q, got %q", tc.want, got)
			}
		})
	}
}
func BenchmarkRewriter(b *testing.B) {
	ts := StartTest(nil)
	defer ts.Close()

	cases := prepareRewriterCases()
	//warm-up regexp caches
	for _, tc := range cases {
		r := tc.reqMaker()
		ts.Gw.urlRewrite(tc.meta, r)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for _, tc := range cases {
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			r := tc.reqMaker()
			b.StartTimer()
			ts.Gw.urlRewrite(tc.meta, r)
		}
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

	ts := StartTest(nil)
	defer ts.Close()

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

			r.Header.Set("x-test", "hello-world")

			hOpt := apidef.StringRegexMap{MatchPattern: "hello-(\\w+)"}
			hOpt.Init()

			return TestDef{
				"Header Single Group",
				"/test/straight/rewrite", "/change/to/me/ignore",
				"/test/straight/rewrite", "/change/to/me/world",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							HeaderMatches: map[string]apidef.StringRegexMap{
								"x-test": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-X-Test-0-0",
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
			r, _ := http.NewRequest("GET", "/test/straight/rewrite", nil)

			r.Header.Set("x-test", "hello")
			r.Header.Set("x-test-Two", "world")

			hOpt := apidef.StringRegexMap{MatchPattern: "hello"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "w.*", Reverse: true}
			hOpt2.Init()

			return TestDef{
				"Header Reverse Logic Any Pass",
				"/test/straight/rewrite", "/change/to/me/ignore",
				"/test/straight/rewrite", "/change/to/me/hello",
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
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/straight/rewrite", nil)

			r.Header.Set("x-test", "hello")
			r.Header.Set("x-test-Two", "world")

			hOpt := apidef.StringRegexMap{MatchPattern: "hello"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "w.*", Reverse: true}
			hOpt2.Init()

			return TestDef{
				"Header Reverse Logic All Fail",
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
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-X-Test-0",
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
			r, _ := http.NewRequest("GET", "/test/query/rewrite?x_test=foo-bar", nil)

			hOpt := apidef.StringRegexMap{MatchPattern: "foo-(\\w+)"}
			hOpt.Init()

			return TestDef{
				"Query Single Group",
				"/test/query/rewrite", "/change/to/me/ignore",
				"/test/query/rewrite", "/change/to/me/bar",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							QueryValMatches: map[string]apidef.StringRegexMap{
								"x_test": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-x_test-0-0",
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
			r, _ := http.NewRequest("GET", "/test/query/rewrite?x_test=foo", nil)
			r.Header.Set("y-test", "bar")
			r.Header.Set("z-test", "baz")

			hOpt := apidef.StringRegexMap{MatchPattern: "foo"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt2.Init()
			hOpt3 := apidef.StringRegexMap{MatchPattern: "baz", Reverse: true}
			hOpt3.Init()

			return TestDef{
				"Multi Multi Type Reverse Logic All Fail",
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
			r, _ := http.NewRequest("GET", "/test/query/rewrite?x_test=foo", nil)
			r.Header.Set("y-test", "bar")
			r.Header.Set("z-test", "baz")

			hOpt := apidef.StringRegexMap{MatchPattern: "foo"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt2.Init()
			hOpt3 := apidef.StringRegexMap{MatchPattern: "baz", Reverse: true}
			hOpt3.Init()

			return TestDef{
				"Multi Multi Type Reverse Logic All Fail",
				"/test/query/rewrite", "/change/to/me/ignore",
				"/test/query/rewrite", "/change/to/me/bar",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
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
			var jsonStr = []byte(`{"foo":"barxxx", "fooble":"baryyy"}`)
			r, _ := http.NewRequest("POST", "/test/pl/rewrite", bytes.NewBuffer(jsonStr))

			hOpt := apidef.StringRegexMap{MatchPattern: "bar\\w*"}
			hOpt.Init()

			return TestDef{
				"Payload Multiple Match",
				"/test/pl/rewrite", "/change/to/me/ignore",
				"/test/pl/rewrite", "/change/to/me/barxxx/baryyy",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PayloadMatches: hOpt,
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-payload-0/$tyk_context.trigger-0-payload-1",
					},
				},
				r,
			}
		},
		func() TestDef {
			var jsonStr = []byte(`{"foo":"barxxx", "fooble":"baryyy"}`)
			r, _ := http.NewRequest("POST", "/test/pl/rewrite", bytes.NewBuffer(jsonStr))

			hOpt := apidef.StringRegexMap{MatchPattern: "bar(\\w*)"}
			hOpt.Init()

			return TestDef{
				"Payload Multiple Match Groups",
				"/test/pl/rewrite", "/change/to/me/ignore",
				"/test/pl/rewrite", "/change/to/me/xxx/yyy",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PayloadMatches: hOpt,
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-payload-0-0/$tyk_context.trigger-0-payload-1-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			var jsonStr = []byte(`{"foo":"barxxx", "fooble":"baryyy"}`)
			r, _ := http.NewRequest("POST", "/test/pl/rewrite", bytes.NewBuffer(jsonStr))

			hOpt := apidef.StringRegexMap{MatchPattern: "bar(\\w*)"}
			hOpt.Init()

			return TestDef{
				"Payload Multiple Match Groups",
				"/test/pl/rewrite", "/change/to/me/ignore",
				"/test/pl/rewrite", "/change/to/me/xxx/yyy",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PayloadMatches: hOpt,
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-payload-0-0/$tyk_context.trigger-0-payload-1-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			var jsonStr = []byte(`{"foo":"bar"}`)
			r, _ := http.NewRequest("POST", "/test/pl/rewrite", bytes.NewBuffer(jsonStr))
			r.Header.Set("x-test", "apple")

			hOpt := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "apple"}
			hOpt2.Init()

			return TestDef{
				"Multi Type All",
				"/test/pl/rewrite", "/change/to/me/ignore",
				"/test/pl/rewrite", "/change/to/me/bar/apple",
				[]apidef.RoutingTrigger{
					{
						On: apidef.All,
						Options: apidef.RoutingTriggerOptions{
							PayloadMatches: hOpt,
							HeaderMatches: map[string]apidef.StringRegexMap{
								"x-test": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-payload-0/$tyk_context.trigger-0-X-Test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			var jsonStr = []byte(`{"foo":"bar"}`)
			r, _ := http.NewRequest("POST", "/test/pl/rewrite", bytes.NewBuffer(jsonStr))
			r.Header.Set("x-test", "apple")

			hOpt := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "apple", Reverse: true}
			hOpt2.Init()

			return TestDef{
				"Multi Multi Type Reverse Logic Any 1",
				"/test/pl/rewrite", "/change/to/me/ignore",
				"/test/pl/rewrite", "/change/to/me/bar/",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PayloadMatches: hOpt,
							HeaderMatches: map[string]apidef.StringRegexMap{
								"x-test": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-payload-0/$tyk_context.trigger-0-X-Test-0",
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
			var jsonStr = []byte(`{"foo":"bar"}`)
			r, _ := http.NewRequest("POST", "/test/pl/rewrite", bytes.NewBuffer(jsonStr))
			r.Header.Set("x-test", "apple")

			hOpt := apidef.StringRegexMap{MatchPattern: "bar", Reverse: true}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "apple"}
			hOpt2.Init()

			return TestDef{
				"Multi Multi Type Reverse Logic Any 2",
				"/test/pl/rewrite", "/change/to/me/ignore",
				"/test/pl/rewrite", "/change/to/me//apple",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PayloadMatches: hOpt,
							HeaderMatches: map[string]apidef.StringRegexMap{
								"x-test": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-payload-0/$tyk_context.trigger-0-X-Test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			var jsonStr = []byte(`{"foo":"bar"}`)
			r, _ := http.NewRequest("POST", "/test/pl/rewrite", bytes.NewBuffer(jsonStr))
			r.Header.Set("x-test", "apple")

			hOpt := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt.Init()
			hOpt2 := apidef.StringRegexMap{MatchPattern: "apple", Reverse: true}
			hOpt2.Init()

			return TestDef{
				"Multi Multi Type Reverse Logic Any 3",
				"/test/pl/rewrite", "/change/to/me/ignore",
				"/test/pl/rewrite", "/change/to/me/bar/",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PayloadMatches: hOpt,
							HeaderMatches: map[string]apidef.StringRegexMap{
								"x-test": hOpt2,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-payload-0/$tyk_context.trigger-0-X-Test-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/foobar/rewrite", nil)
			hOpt := apidef.StringRegexMap{MatchPattern: "foo(\\w+)"}
			hOpt.Init()

			return TestDef{
				"PathPart Single Group",
				"/test/foobar/rewrite", "/change/to/me/ignore",
				"/test/foobar/rewrite", "/change/to/me/bar",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PathPartMatches: map[string]apidef.StringRegexMap{
								"pathpart": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-pathpart-0-0",
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

			ctxSetSession(r, &user.SessionState{
				MetaData: map[string]interface{}{
					"rewrite": "bar-baz",
				},
			}, false, ts.Gw.GetConfig().HashKeys)

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
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/foo/rewrite", nil)
			hOpt := apidef.StringRegexMap{MatchPattern: "bar-(\\w+)"}
			hOpt.Init()

			ctxSetSession(r, &user.SessionState{
				MetaData: map[string]interface{}{
					"rewrite": "bar-baz",
				},
			}, false, ts.Gw.GetConfig().HashKeys)

			return TestDef{
				"Meta Simple Group",
				"/test/foo/rewrite", "/change/to/me/ignore",
				"/test/foo/rewrite", "/change/to/me/baz",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							SessionMetaMatches: map[string]apidef.StringRegexMap{
								"rewrite": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-rewrite-0",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/foo/rewrite", nil)
			hOpt := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt.Init()

			ctxSetSession(r, &user.SessionState{
				MetaData: map[string]interface{}{
					"rewrite": "bar-baz",
					"somevar": "someval",
				},
			}, false, ts.Gw.GetConfig().HashKeys)

			return TestDef{
				"Meta Value from Session",
				"/test/foo/rewrite", "/change/to/me/ignore",
				"/test/foo/rewrite", "/change/to/me/bar/someval",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							SessionMetaMatches: map[string]apidef.StringRegexMap{
								"rewrite": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-rewrite/$tyk_meta.somevar",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/foo/rewrite", nil)
			hOpt := apidef.StringRegexMap{MatchPattern: "bar"}
			hOpt.Init()

			ctxSetData(r, map[string]interface{}{
				"rewrite": "bar-baz",
			})

			return TestDef{
				"Request context",
				"/test/foo/rewrite", "/change/to/me/ignore",
				"/test/foo/rewrite", "/change/to/me/bar",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							RequestContextMatches: map[string]apidef.StringRegexMap{
								"rewrite": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-rewrite",
					},
				},
				r,
			}
		},
		func() TestDef {
			r, _ := http.NewRequest("GET", "/test/foo/rewrite", nil)
			hOpt := apidef.StringRegexMap{MatchPattern: "foo"}
			hOpt.Init()

			ctxSetSession(r, &user.SessionState{
				MetaData: map[string]interface{}{
					"rewrite": "bar-baz",
				},
			}, false, ts.Gw.GetConfig().HashKeys)

			return TestDef{
				"Variable not found",
				"/test/foo/rewrite", "/change/to/me/ignore",
				"/test/foo/rewrite", "/change/to/me/foo//",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PathPartMatches: map[string]apidef.StringRegexMap{
								"pathpart": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-pathpart-0/$tyk_context.nonexistent/$tyk_meta.nonexistent",
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
				"Session not found",
				"/test/foo/rewrite", "/change/to/me/ignore",
				"/test/foo/rewrite", "/change/to/me/foo/",
				[]apidef.RoutingTrigger{
					{
						On: apidef.Any,
						Options: apidef.RoutingTriggerOptions{
							PathPartMatches: map[string]apidef.StringRegexMap{
								"pathpart": hOpt,
							},
						},
						RewriteTo: "/change/to/me/$tyk_context.trigger-0-pathpart-0/$tyk_meta.nonexistent",
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

			got, err := ts.Gw.urlRewrite(&testConf, tc.req)
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
	ts := StartTest(nil)
	defer ts.Close()

	// prepare test data
	testRewriteMW := &URLRewriteMiddleware{
		BaseMiddleware: BaseMiddleware{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{},
			},
			Gw: ts.Gw,
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
		t.Errorf("Expected HeaderMatches initialized and matched, received no match")
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
		t.Errorf("Expected QueryValMatches initialized and matched, received no match")
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
		t.Errorf("Expected PayloadMatches initialized and matched, received no match")
	}
}

func TestURLRewriteCaseSensitivity(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	assert := func(relativePath string, requestedPath string, bodyMatch string) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{{
					Path:         relativePath,
					Method:       "GET",
					MatchPattern: requestedPath,
					RewriteTo:    "/xyz",
				}}
			})
		})

		ts.Run(t, test.TestCase{
			Path: requestedPath, Code: 200, BodyMatch: bodyMatch,
		})
	}

	// Matches and rewrites
	t.Run("Relative path lower, requested path lower", func(t *testing.T) {
		assert("/get", "/get", `"Url":"/xyz"`)
	})

	// Doesn't match and doesn't rewrite
	t.Run("Relative path lower, requested path upper", func(t *testing.T) {
		assert("/get", "/Get", `"Url":"/Get"`)
	})

	// Doesn't match and doesn't rewrite
	t.Run("Relative path upper, requested path lower", func(t *testing.T) {
		assert("/Get", "/get", `"Url":"/get"`)
	})

	// Matches and rewrites
	t.Run("Relative path upper, requested path upper", func(t *testing.T) {
		assert("/Get", "/Get", `"Url":"/xyz"`)
	})
}

func TestValToStr(t *testing.T) {

	example := []interface{}{
		"abc",      // string
		int64(456), // int64
		12.22,      // float
		"abc,def",  // string url encode
	}

	str := valToStr(example)
	expected := "abc,456,12.22,abc%2Cdef"

	if str != expected {
		t.Errorf("expected (%s) got (%s)", expected, str)
	}
}

func TestLoopingUrl(t *testing.T) {
	cases := []struct{ host, expectedHost string }{
		{"__api", "tyk://-api"},
		{"__api__", "tyk://-api-"},
		{"__ api __", "tyk://-api-"},
		{"@api@", "tyk://-api-"},
		{"__ api __ name __", "tyk://-api-name-"},
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			assert.Equal(t, tc.expectedHost, LoopingUrl(tc.host))
		})
	}
}

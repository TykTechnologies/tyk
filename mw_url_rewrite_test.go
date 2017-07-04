package main

import (
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestRewriter(t *testing.T) {
	tests := []struct {
		name        string
		pattern, to string
		in, want    string
	}{
		{
			"Straight",
			"test/straight/rewrite", "change/to/me",
			"test/straight/rewrite", "change/to/me",
		},
		{
			"OneVal",
			"test/val/(.*)", "change/to/$1",
			"test/val/VALUE", "change/to/VALUE",
		},
		{
			"ThreeVals",
			"test/val/(.*)/space/(.*)/and/then/(.*)", "change/to/$1/$2/$3",
			"test/val/ONE/space/TWO/and/then/THREE", "change/to/ONE/TWO/THREE",
		},
		{
			"Reverse",
			"test/val/(.*)/space/(.*)/and/then/(.*)", "change/to/$3/$2/$1",
			"test/val/ONE/space/TWO/and/then/THREE", "change/to/THREE/TWO/ONE",
		},
		{
			"Missing",
			"test/val/(.*)/space/(.*)/and/then/(.*)", "change/to/$1/$2",
			"test/val/ONE/space/TWO/and/then/THREE", "change/to/ONE/TWO",
		},
		{
			"MissingAgain",
			"test/val/(.*)/space/(.*)/and/then/(.*)", "change/to/$3/$1",
			"test/val/ONE/space/TWO/and/then/THREE", "change/to/THREE/ONE",
		},
		{
			"QS",
			"(.*)", "$1&newParam=that",
			"foo/bar?param1=this", "foo/bar?param1=this&newParam=that",
		},
		{
			"QS2",
			"test/val/(.*)/space/(.*)/and/then(.*)", "change/to/$2/$1$3",
			"test/val/ONE/space/TWO/and/then?param1=this", "change/to/TWO/ONE?param1=this",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testConf := apidef.URLRewriteMeta{
				MatchPattern: tc.pattern,
				RewriteTo:    tc.to,
			}
			r := httptest.NewRequest("GET", "/", nil)
			got, err := urlRewrite(&testConf, tc.in, false, r)
			if err != nil {
				t.Error("compile failed:", err)
			}
			if got != tc.want {
				t.Errorf("rewrite failed, want %q, got %q", tc.want, got)
			}
		})
	}
}

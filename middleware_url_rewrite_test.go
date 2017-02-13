package main

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestRewriter(t *testing.T) {
	rw := URLRewriter{}

	testConf := apidef.URLRewriteMeta{
		Path:         "",
		Method:       "",
		MatchPattern: "test/straight/rewrite",
		RewriteTo:    "change/to/me",
	}

	inbound := "test/straight/rewrite"
	expected := "change/to/me"

	val, err := rw.Rewrite(&testConf, inbound, false, nil)

	if err != nil {
		t.Error("Compile failed: ", err)
	}

	if val != expected {
		t.Errorf("Transform failed, expected: %v, got: %v ", expected, val)
	}
}

func TestRewriterWithOneVal(t *testing.T) {
	rw := URLRewriter{}

	testConf := apidef.URLRewriteMeta{
		Path:         "",
		Method:       "",
		MatchPattern: "test/val/(.*)",
		RewriteTo:    "change/to/$1",
	}

	inbound := "test/val/VALUE"
	expected := "change/to/VALUE"

	val, err := rw.Rewrite(&testConf, inbound, false, nil)

	if err != nil {
		t.Error("Compile failed: ", err)
	}

	if val != expected {
		t.Errorf("Transform failed, expected: %v, got: %v ", expected, val)
	}
}

func TestRewriterWithThreeVals(t *testing.T) {
	rw := URLRewriter{}

	testConf := apidef.URLRewriteMeta{
		Path:         "",
		Method:       "",
		MatchPattern: "test/val/(.*)/space/(.*)/and/then/(.*)",
		RewriteTo:    "change/to/$1/$2/$3",
	}

	inbound := "test/val/ONE/space/TWO/and/then/THREE"
	expected := "change/to/ONE/TWO/THREE"

	val, err := rw.Rewrite(&testConf, inbound, false, nil)

	if err != nil {
		t.Error("Compile failed: ", err)
	}

	if val != expected {
		t.Errorf("Transform failed, expected: %v, got: %v ", expected, val)
	}
}

func TestRewriterWithReverse(t *testing.T) {
	rw := URLRewriter{}

	testConf := apidef.URLRewriteMeta{
		Path:         "",
		Method:       "",
		MatchPattern: "test/val/(.*)/space/(.*)/and/then/(.*)",
		RewriteTo:    "change/to/$3/$2/$1",
	}

	inbound := "test/val/ONE/space/TWO/and/then/THREE"
	expected := "change/to/THREE/TWO/ONE"

	val, err := rw.Rewrite(&testConf, inbound, false, nil)

	if err != nil {
		t.Error("Compile failed: ", err)
	}

	if val != expected {
		t.Errorf("Transform failed, expected: %v, got: %v ", expected, val)
	}
}

func TestRewriterWithMissing(t *testing.T) {
	rw := URLRewriter{}

	testConf := apidef.URLRewriteMeta{
		Path:         "",
		Method:       "",
		MatchPattern: "test/val/(.*)/space/(.*)/and/then/(.*)",
		RewriteTo:    "change/to/$1/$2",
	}

	inbound := "test/val/ONE/space/TWO/and/then/THREE"
	expected := "change/to/ONE/TWO"

	val, err := rw.Rewrite(&testConf, inbound, false, nil)

	if err != nil {
		t.Error("Compile failed: ", err)
	}

	if val != expected {
		t.Errorf("Transform failed, expected: %v, got: %v ", expected, val)
	}
}

func TestRewriterWithMissingAgain(t *testing.T) {
	rw := URLRewriter{}

	testConf := apidef.URLRewriteMeta{
		Path:         "",
		Method:       "",
		MatchPattern: "test/val/(.*)/space/(.*)/and/then/(.*)",
		RewriteTo:    "change/to/$3/$1",
	}

	inbound := "test/val/ONE/space/TWO/and/then/THREE"
	expected := "change/to/THREE/ONE"

	val, err := rw.Rewrite(&testConf, inbound, false, nil)

	if err != nil {
		t.Error("Compile failed: ", err)
	}

	if val != expected {
		t.Errorf("Transform failed, expected: %v, got: %v ", expected, val)
	}
}

func TestRewriterWithQS(t *testing.T) {
	rw := URLRewriter{}

	testConf := apidef.URLRewriteMeta{
		Path:         "",
		Method:       "",
		MatchPattern: "(.*)",
		RewriteTo:    "$1&newParam=that",
	}

	inbound := "foo/bar?param1=this"
	expected := "foo/bar?param1=this&newParam=that"

	val, err := rw.Rewrite(&testConf, inbound, false, nil)

	if err != nil {
		t.Error("Compile failed: ", err)
	}

	if val != expected {
		t.Errorf("Transform failed, expected: %v, got: %v ", expected, val)
	}
}

func TestRewriterWithQS2(t *testing.T) {
	rw := URLRewriter{}

	testConf := apidef.URLRewriteMeta{
		Path:         "",
		Method:       "",
		MatchPattern: "test/val/(.*)/space/(.*)/and/then(.*)",
		RewriteTo:    "change/to/$2/$1$3",
	}

	inbound := "test/val/ONE/space/TWO/and/then?param1=this"
	expected := "change/to/TWO/ONE?param1=this"

	val, err := rw.Rewrite(&testConf, inbound, false, nil)

	if err != nil {
		t.Error("Compile failed: ", err)
	}

	if val != expected {
		t.Errorf("Transform failed, expected: %v, got: %v ", expected, val)
	}
}

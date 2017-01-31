package main

import "testing"

func TestBundleGetter(t *testing.T) {
}

func TestHttpBundleGetter(t *testing.T) {
	getter := &HttpBundleGetter{}
	getter.Get()
}

func TestBundleSaver(t *testing.T) {
}

func TestZipBundleSaver(t *testing.T) {
}

func TestFetchBundle(t *testing.T) {
	// var testBundleSaver BundleSaver
	// testBundleSaver = &ZipBundleSaver{}
}

func TestSaveBundle(t *testing.T) {
	// var testBundleFormat = "zip"
	// var testBundleSaver BundleSaver
	// testBundleSaver = &ZipBundleSaver{}
}

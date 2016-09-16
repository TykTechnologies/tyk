package main

type BundleGetter interface {
  Get()
  Save()
}

type HttpBundleGetter struct {
  BundleGetter
}

func FetchBundle(name string) {
  var thisGetter BundleGetter
  thisGetter.Get()
  thisGetter.Save()
}

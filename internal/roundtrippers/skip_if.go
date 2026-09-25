package roundtrippers

func SkipIf(mw Middleware, skip bool) Middleware {
	if skip {
		return nil
	}
	return mw
}

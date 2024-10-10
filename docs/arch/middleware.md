# Middleware

One of the key objects in gateway is the BaseMiddleware object. The
object itself is intended to be used as a value, rather than a pointer
object. Middlewares rely on a copy of BaseMiddleware, to provide
middleware specific loggers, with the `mw` field being set for each
middleware.

Known design requirements of BaseMiddleware:

> Logger is middleware scoped with the new allocation/copy of *logrus.Entry in BaseMiddleware.
> This is facilitated by a shallow copy of the BaseMiddleware object when creating middleware.

BaseMiddleware bundles several APIs, that don't necessarily rely on
needing a copy of this value. For example, two key objects:

- `SuccessHandler`
- `ErrorHandler`

Both of these objects rely on a pointer value.

Both invoke:

```
defer s.BaseMiddleware.UpdateRequestSession(r)
```

And within, the base middleware Logger is invoked. For those particular
cases, the `mw` should be set to the initiating middleware, providing
additional context for logging.

The `Base() *BaseMiddleware` function is part of the TykMiddleware
interface, providing a pointer to the base middleware object. This in turn
allows to reference the fields in BaseMiddleware, namely:

- APISpec, for the API definition wrapper
- Gateway config (Gw.GetConfig())
- APIs like BaseMiddleware.FireEvent, UpdateRequestSession

Base() doesn't create a copy, is rarely used (~6x), and should likely be
obsolete when constructors get adopted.

- Constructors can take dependencies like `*config.Config`
- Constructors give control of the allocation in one place
- Inheritance/embedding is confusing

What do we mean when we say confusing?

- `*BaseMiddleware` can only be a pointer
- `BaseMiddleware` can be a struct or an interface

The cognitive and behavioral complexities of shallow copies make this an
area of maintenance. While all the inner values are pointers, the only
requirement of the copy is to provide a middleware-scoped logger, rather
than an apispec scoped one.

This is the key internal detail:

```
func (t *BaseMiddleware) SetName(name string) {
	t.logger = t.Logger().WithField("mw", name)
}

func (t *BaseMiddleware) SetRequestLogger(r *http.Request) {
	t.logger = t.Gw.getLogEntryForRequest(t.Logger(), r, ctxGetAuthToken(r), nil)
}
```

This is what requires the per-middleware logger scope.
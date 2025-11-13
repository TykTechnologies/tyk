# Build package

This package contains values that are injected by goreleaser at build
time. The main used value in gateway is `VERSION`, notably by goplugins,
as well as by the gateway itself, providing build information.

This enables:

```
import "github.com/TykTechnologies/tyk/internal/build"
// use build.VERSION
```

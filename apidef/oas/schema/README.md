# NOTE

We need to convert the schema files to a go object, 
run go generate after adding a new schema in this directory

``go generate apidef/oas/validator.go``

This will use `go-bindata` to generate go objects from the static files.

*TODO*: Explore possibilities of `go:embed` after upgrading Tyk to `go1.16`

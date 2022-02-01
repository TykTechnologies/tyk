#  (2020-05-06)

This is an update to jsonpointer. It adds usability functions and options for perfomance optimized use.

### Bug Fixes

* **Test:** fix failing tests when using go 1.14. [c51da06](https://github.com/qri-io/jsonpointer/commit/c51da06b3a9796e12c0a8309b728b015c01387c0)

### Features

* **Head,Tail,IsEmpty:** added methods to get the first token, all tokens after the head and to check if a given pointer is empty [c51da06](https://github.com/qri-io/jsonpointer/commit/c51da06b3a9796e12c0a8309b728b015c01387c0)
* **RawDescendant,NewPointer:** methods that allow to directly append to the current pointer without safety checks and a way to create a pointer with pre-allocated memory for performance intensive use cases [c51da06](https://github.com/qri-io/jsonpointer/commit/c51da06b3a9796e12c0a8309b728b015c01387c0)

#  (2019-05-23)

This is the first proper release of jsonpointer. In preparation for go 1.13, in which `go.mod` files and go modules are the primary way to handle go dependencies, we are going to do an official release of all our modules. This will be version v0.1.0 of jsonpointer.

### Bug Fixes

* **Parse:** fix incorrect handling of empty url fragment strings ([5919095](https://github.com/qri-io/jsonpointer/commit/5919095))


### Features

* **Descendant,WalkJSON:** added pointer descendant method, experimental WalkJSON func ([707e879](https://github.com/qri-io/jsonpointer/commit/707e879))
* initial commit ([448ab45](https://github.com/qri-io/jsonpointer/commit/448ab45))




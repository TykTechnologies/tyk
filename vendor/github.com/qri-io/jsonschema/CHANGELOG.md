# [](https://github.com/qri-io/jsonschema/compare/v0.2.0...v) (2021-03-29)


### Bug Fixes

* **error:** show error message for `minLength` ([#73](https://github.com/qri-io/jsonschema/issues/73)) ([0995c6b](https://github.com/qri-io/jsonschema/commit/0995c6b04506cc858dee03b166771edeeab95f64))


### Features

* **resolve:** file URI resolution ([#90](https://github.com/qri-io/jsonschema/issues/90)) ([dbc3af1](https://github.com/qri-io/jsonschema/commit/dbc3af1d666cc034a9ac89f10fba0ad6d5cb6c8e))
* **type:** support additional number types ([#72](https://github.com/qri-io/jsonschema/issues/72)) ([9874480](https://github.com/qri-io/jsonschema/commit/9874480d05ec5edf3e0c19873bd2bd4fb322b3fe))



# [](https://github.com/qri-io/jsonschema/compare/v0.1.2...v) (2020-05-21)

This is relase v0.2.0. It's a rework of the jsonschema implementation which now has better support for the spec, equal or better performance depending on the keyword, possibility to easily extend with your own keywords and finally, draft2019_09 support.

### Features

* **jsonschema:** reworking json schema (migration to draft2019_09) ([bb2a1cf](https://github.com/qri-io/jsonschema/commit/bb2a1cf423024a5144c05dcced8f1226fd7e65b9))


# [](https://github.com/qri-io/jsonschema/compare/v0.1.1...v) (2020-05-21)

This is a patch release of jsonschema to mark v0.1.2. The purpose of it is to provide a stable v0.1 version for managing the dependencies as the upcoming v0.2.0 will break a lot of the existing API.

### Bug Fixes

* Typo ([#52](https://github.com/qri-io/jsonschema/issues/52)) ([9f11b79](https://github.com/qri-io/jsonschema/commit/9f11b79125715650da0b4932b3ca66328b508ac7))


### Features

* **type:** identify custom struct as objects ([c1722b7](https://github.com/qri-io/jsonschema/commit/c1722b720fafa56f0514e08063b5a3c6baa73863))



#  (2019-05-23)

This is the first proper release of jsonschema. In preparation for go 1.13, in which `go.mod` files and go modules are the primary way to handle go dependencies, we are going to do an official release of all our modules. This will be version v0.1.1 of jsonschema.


### Bug Fixes

* **jsonschema:** Handle empty url fragment "#", add unit tests. ([ca0e82f](https://github.com/qri-io/jsonschema/commit/ca0e82f))
* An issue where if $id starts with # caused a slice bounds out of range panic while Unmarshaling ([9f6179a](https://github.com/qri-io/jsonschema/commit/9f6179a))
* **$comment:** add support for $comment keyword, add $comment to testschema_test ExampleBasic() ([#33](https://github.com/qri-io/jsonschema/issues/33)) ([3313399](https://github.com/qri-io/jsonschema/commit/3313399))
* **const error:** error reports what const must equal instead of supplied value ([9b9427b](https://github.com/qri-io/jsonschema/commit/9b9427b)), closes [#34](https://github.com/qri-io/jsonschema/issues/34)


### Features

* **IfThenElse:** implement If/Then/Else, cleanup ([bef9c1e](https://github.com/qri-io/jsonschema/commit/bef9c1e))
* **json.Marshaler:** marshal schemas back to json properly. ([f7d8215](https://github.com/qri-io/jsonschema/commit/f7d8215))
* **jsonschema:** Change to TopLevelType function, more general. ([4a66928](https://github.com/qri-io/jsonschema/commit/4a66928))
* **jsonschema:** Cleanup mistakes, test for unknown schema type. ([9ab452b](https://github.com/qri-io/jsonschema/commit/9ab452b))
* **jsonschema:** Field to tell if RootSchema is an array or object. ([8bd68f0](https://github.com/qri-io/jsonschema/commit/8bd68f0))
* **jsonschema format:** added iri, iri-ref, regex format validators ([06217c5](https://github.com/qri-io/jsonschema/commit/06217c5))
* **jsonschema format:** added iri, iri-ref, regex format validators ([4e5183a](https://github.com/qri-io/jsonschema/commit/4e5183a))
* **jsonschema format:** added jsonpointer, reljsonpointer validators ([6205399](https://github.com/qri-io/jsonschema/commit/6205399))
* **refs:** first signs of life on refs working properly ([435c766](https://github.com/qri-io/jsonschema/commit/435c766))
* **ValError:** overhaul and upgrade error collection & reporting ([66b03e6](https://github.com/qri-io/jsonschema/commit/66b03e6))
* added format validators for datetime, date, email, ipv4/6 and some others ([3394369](https://github.com/qri-io/jsonschema/commit/3394369))
* added format validators for datetime, date, email, ipv4/6 and some others ([5bf895c](https://github.com/qri-io/jsonschema/commit/5bf895c))
* added Must func for easier schema declaration in Go. ([2874aff](https://github.com/qri-io/jsonschema/commit/2874aff))
* **jsonschema format:** added jsonpointer, reljsonpointer validators ([d787e78](https://github.com/qri-io/jsonschema/commit/d787e78))
* first pass of draft7 test suite passing ([263a72d](https://github.com/qri-io/jsonschema/commit/263a72d))
* initial commit ([b620f19](https://github.com/qri-io/jsonschema/commit/b620f19))
* initial support for local references ([a99baf2](https://github.com/qri-io/jsonschema/commit/a99baf2))
* return multiple errors on validation call. ([00b42a8](https://github.com/qri-io/jsonschema/commit/00b42a8)), closes [#15](https://github.com/qri-io/jsonschema/issues/15)




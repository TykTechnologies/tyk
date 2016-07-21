# Coprocess - PoC

## Build

It's possible to use a [build tag](https://golang.org/pkg/go/build/#hdr-Build_Constraints):

```
go build -tags 'coprocess python'
```

```
go build -tags 'coprocess somelanguage'
```

Each language should implement a ```CoProcessInit``` function, this will be called from the main function when the ```coprocess``` build tag is used.

Using the ```coprocess``` build tag with no language tag will fail.

A standard build is still possible:

```
go build
```

```coprocess_dummy.go``` provides a dummy ```CoProcessInit``` function that will be called if you perform a standard Tyk build. This file will be ignored when using the ```coprocess``` build tag, as we expect it to be implemented by a language.

## References

[Trello note](https://trello.com/c/6QNWnF2n/265-coprocess-handlers-middleware-replacements-and-hooks)

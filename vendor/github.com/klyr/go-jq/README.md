# JQ bindings for Go

This library implements bindings to the "jq" JSON processor from Go:

  http://stedolan.github.io/jq/

The code is in a very early state, and not ready for production use. There are
passing tests covering conversion between Go and JQ's internal JSON structures,
and basic JSON query processing, but it does almost no error handling, and
almost certainly contains memory leaks due to the allocation of objects in C.

There are a few other JQ bindings for Go, in various states:

 * https://github.com/jingweno/jqpipe-go
 * https://github.com/threatgrid/jq-go
 * https://github.com/bongole/go-jq
 * https://github.com/MattAitchison/jq

This library attempts to convert directly between Go data structures and JQ's
internal C data structures instead of an intermediate JSON serialization.

// The allocator package handles two concerns related to allocations:
//
// 1. It uses sync.Pool to manage an in-memory cache of reusable types.
// 2. Provides a generic interface to take advantage of type safety.
//
// Extensions may focus on measuring allocation pressure.
//
// To use the allocator, typed code must provide a constructor.
// If this was typed code, the following function is expected:
//
// ~~~
// func NewDocument() (*Document, error)
// ~~~
//
// With Go generics, expected usage is:
//
// ~~~
// doc, err := allocator.New[Document](NewDocument)
// ~~~
//
// The type must implement the Reset() function.
// No cleanup API is required, the allocator uses
// runtime.SetFinalizer to return the object to
// the pool.
package allocator

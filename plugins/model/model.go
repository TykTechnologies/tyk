// Package model holds symbols required for all plugin types.
// This is a data model only package and should avoid logic.

package model

import (
	"errors"
	"plugin"
)

// Plugin is the common interface that should be implemented by
// any plugin type. It allows to load a plugin symbol, and list
// plugin symbols. If a plugin subsystem can't implement a symbols
// list, it is expected to return a model.ErrNoSymbols.
type Plugin interface {
	// Lookup retrieves the value for a symbol.
	Lookup(name string) (plugin.Symbol, error)

	// Symbols lists all plugin symbols and types of symbol.
	Symbols() (map[string]string, error)
}

// Registry is an optional interface implemented by plugin loaders.
type Registry interface {
	// Register adds a plugin callback to the registry.
	Register(name string, val plugin.Symbol)
}

// ErrNoSymbols is returned from Symbols() if no symbols can be listed.
var ErrNoSymbols = errors.New("No symbols found")

// ErrNotFound is returned from Lookup() if symbol is not found.
var ErrNotFound = errors.New("Symbol not found")

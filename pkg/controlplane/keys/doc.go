// Package keys holds the control-plane key administration logic that the
// gateway admin API (/tyk/keys, /tyk/org/keys) is built on. It is designed to
// run inside the gateway and inside the Dashboard, against the same Redis,
// with byte-identical output.
package keys

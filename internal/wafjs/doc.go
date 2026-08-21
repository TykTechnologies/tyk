// Package wafjs hosts the waf-js track's Goja engine integration for the
// CRS-derived WAF.
//
// At this stage the package exists to retain the capability spike evidence
// required by the WAF-JS plan: whether vm.Interrupt bounds long-running
// regular-expression work at the pinned engine version. The measured
// evidence, the capability map, and the primary-source citations live in
// docs/dev/program/waf-js/goja-capability-map.md.
package wafjs

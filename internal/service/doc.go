// The service package is the service layer base for the gateway.
//
// It's a connecting package between the data model packages,
// allowing for a stdlib-only implementation under imports.
// This carries import restrictions. This package and the
// packages nested within are only to be used by the gateway package.
//
// All other packages may be used by the data model, preventing
// import cycles and the diamond dependency problem.
package service

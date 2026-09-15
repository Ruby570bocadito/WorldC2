// Package version holds the build identity of the server binary. The
// variables are injected at link time (Makefile / CI):
//
//	go build -ldflags "-X .../internal/version.Version=v1.18.0 \
//	        -X .../internal/version.Commit=abc1234" ./cmd/server
//
// The defaults are honest fallbacks so a binary built without flags still
// reports a non-empty identity instead of an empty string that would
// render as an empty label in the build_info metric.
package version

import "runtime"

var (
	// Version is the semantic version of the build (e.g. "v1.19.0").
	Version = "dev"
	// Commit is the git commit the binary was built from (short or long
	// SHA). "unknown" when built from a dirty tree without VCS metadata.
	Commit = "unknown"
)

// GoVersion is the toolchain that produced the binary (runtime version),
// exposed alongside Version/Commit by worldc2_build_info and the enriched
// /api/status (r19). Computed once at package init: runtime.Version() is
// constant for the lifetime of the process.
var GoVersion = runtime.Version()

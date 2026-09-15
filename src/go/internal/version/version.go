// Package version holds the build identity of the server binary. The
// variables are injected at link time (Makefile / CI):
//
//	go build -ldflags "-X .../internal/version.Version=v1.18.0 \
//		-X .../internal/version.Commit=abc1234" ./cmd/server
//
// The defaults are honest fallbacks so a binary built without flags still
// reports a non-empty identity instead of an empty string that would
// render as an empty label in the build_info metric.
package version

var (
	// Version is the semantic version of the build (e.g. "v1.18.0").
	Version = "dev"
	// Commit is the git commit the binary was built from (short or long
	// SHA). "unknown" when built from a dirty tree without VCS metadata.
	Commit = "unknown"
)

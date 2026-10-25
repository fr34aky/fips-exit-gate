// Package version reports which build of fips-exit-gate is running. One
// version covers every component; it comes from the git tag.
package version

import (
	"runtime/debug"
	"strings"
)

// Version is set at build time:
//
//	go build -ldflags "-X github.com/fr34aky/fips-exit-gate/pkg/version.Version=$(git describe --tags --always --dirty)"
//
// The Dockerfiles pass it through as the VERSION build argument. When empty,
// String falls back to the VCS information Go embeds in the binary.
var Version = ""

// String returns the build's version: the tag (0.1.0), the tag plus commits
// since it (0.1.0-3-gabc1234), "dev+<revision>" for a build without a tag,
// or "dev" when nothing is known. A "-dirty" suffix marks uncommitted changes.
func String() string {
	if Version != "" {
		return strings.TrimPrefix(Version, "v")
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		var rev string
		dirty := false
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if rev != "" {
			if len(rev) > 12 {
				rev = rev[:12]
			}
			if dirty {
				return "dev+" + rev + "-dirty"
			}
			return "dev+" + rev
		}
	}
	return "dev"
}

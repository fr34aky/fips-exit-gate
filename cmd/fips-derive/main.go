// Command fips-derive prints the fips mesh address(es) for one or more npubs.
// Operational helper for seeding the Phase 1 allowlist and for debugging.
//
//	fips-derive npub1... [npub2 ...]
//	echo npub1... | fips-derive     # one per line on stdin
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fr34aky/fips-exit/pkg/fipsaddr"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		os.Exit(run(args))
	}
	// No args: read npubs from stdin.
	var in []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			in = append(in, line)
		}
	}
	os.Exit(run(in))
}

func run(npubs []string) int {
	rc := 0
	for _, npub := range npubs {
		addr, err := fipsaddr.FromNpub(npub)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", npub, err)
			rc = 1
			continue
		}
		fmt.Println(addr.String())
	}
	return rc
}

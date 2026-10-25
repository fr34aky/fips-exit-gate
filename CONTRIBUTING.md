# Contributing to fips-exit-gate

<!-- markdownlint-disable MD013 -->

fips-exit-gate is a paid Internet exit for the [fips](https://github.com/jmcorgan/fips)
mesh: a client's fips address, derived from its npub, is its identity; the
exit lets authorized addresses out to the Internet and bills them per byte.
The tree is one Go module with a few small, deliberately separate programs:

- **`agent/`** — runs on each exit node. Keeps the nftables `authorized` set in
  sync with the backend (long-poll delta sync plus periodic full reconcile),
  reads the per-`(client, service)` byte counters and reports usage, applies
  inline revocations. Drives the `nft` binary; stdlib only, so it also runs
  on OpenWrt.
- **`backend/`** — the control plane and the user portal (Go + Postgres):
  the agent-facing API (enroll / authz / usage / heartbeat), nostr login,
  packages, whitelist, payments (BTCPay, phoenixd, Cashu), admin API.
  `backend/store/` is the only code that talks to Postgres; migrations are
  embedded and applied on start.
- **`captive/`, `dispatch/`, `exit/`** — the data path on the node: a
  captive SOCKS daemon that sends unauthorized HTTP to the portal, the
  connectivity dispatcher (`*.onion` → Tor, else → Dante), and the Dante
  egress engine with its policy in `exit/sockd.conf`. None of them logs
  destinations.
- **`deploy/`** — everything an operator runs: the templated nftables
  ruleset (`render-nftables.sh` over `services.conf`), `up.sh`, compose
  files, systemd units, monitoring, and container-based integration tests
  under `deploy/test/` and `deploy/client/test/`.
- **`pkg/`** — shared primitives (`fipsaddr` derivation, metrics, …).
- **`docs/`** — the specs the code is held to: agent↔backend API, data model,
  threat model, configuration reference, runbooks.

The security boundary runs through the **nftables gate** (`deploy/`), the
**authorization recompute and attribution** (`backend/store/authz.go`,
`whitelist`), and the **payment settlement paths** (`backend/store/payments.go`,
webhooks). Changes there get the strictest review in the project; the
[threat model](docs/threat-model.md) says what each control is supposed to
guarantee, and must only ever claim what the code does.

## Quick start

```sh
git clone https://github.com/fr34aky/fips-exit-gate.git
cd fips-exit-gate
gofmt -l . && go vet ./... && go test ./...
```

Requirements: Go as pinned by the `go` directive in `go.mod` (do not bump it
casually; a `go get @latest` can do so silently), Docker for the integration
tests, and a throwaway Postgres for the store and portal tests:

```sh
docker run -d --name fips-pg-test -e POSTGRES_USER=fips -e POSTGRES_PASSWORD=pw \
  -e POSTGRES_DB=fips_exit -p 127.0.0.1:5433:5432 postgres:16-alpine
TEST_DATABASE_URL=postgres://fips:pw@127.0.0.1:5433/fips_exit go test -p 1 ./backend/...
```

Never point `TEST_DATABASE_URL` at a live database: the tests drop and
recreate the schema. `-p 1` is required because every test does.

There is no mock fips mesh. Anything that changes what the exit enforces on
the wire (the ruleset, `up.sh`, the dispatcher, the client tunnel) is run
through the container tests, which load the real ruleset in a real kernel:

```sh
sh deploy/test/run-nft-gate-test.sh        # gate semantics (redirect, accept, live reset, acct)
sh deploy/client/test/run-tunnel-test.sh   # whole-device client tunnel against a real SOCKS server
```

and, before release, against two real fips peers (an exit and a client).

## Branches

There is one long-lived branch, `master`. Open PRs against it. Tags mark
releases (see [Releasing](#releasing)) and [CHANGELOG.md](CHANGELOG.md)
records what changed between them. Stacked PRs are fine when a change really
builds on an unmerged one; say so in the PR body with the merge order.

## Reporting bugs

Search [open issues](https://github.com/fr34aky/fips-exit-gate/issues) before
filing a new one. Include:

- **Version** of each component involved (`git describe --tags --always` on
  the checkout; the agent logs its version at start, the heartbeat carries it).
- **Which host** the problem is on: exit node, backend, or client; and for
  clients, how they connect (PAC, whole-device tunnel, raw SOCKS).
- **fips version** (`fipsctl --version`) and whether the mesh firewall is on.
- **What you expected** and **what happened**, with reproduction steps.
- **Evidence** — agent/backend logs, `nft list table inet fips_exit` (sets and
  counters), `/admin/authz` and `/admin/accounts/<npub>` output for an
  authorization problem, the captive/dispatch logs for a data-path one.
  Redact addresses and npubs if you prefer; shapes matter more than values.
- For **payment** problems: the rail (BTCPay, phoenixd, Cashu), the purchase
  and invoice state, and the webhook log lines. Never paste tokens or secrets.

One issue per bug.

## Submitting pull requests

### Scope discipline

Every PR makes one logical change. The reviewer should be able to read the
whole diff and trace every line back to the PR's stated purpose.

- No drive-by reformatting of unrelated files.
- No unrelated refactors folded into a bug fix or a feature PR.
- No "while I was in there" cleanups outside the change's natural footprint.
  Send them separately; they land faster on their own.

### Required before opening any PR

```sh
gofmt -l .                                   # must print nothing
go vet ./...
go test ./...
TEST_DATABASE_URL=… go test -p 1 ./backend/...   # when backend/ or backend/store/ changed
sh -n deploy/*.sh deploy/client/*.sh deploy/test/*.sh
sh deploy/test/run-nft-gate-test.sh          # when deploy/render-nftables.sh, up.sh or gate semantics changed
sh deploy/client/test/run-tunnel-test.sh     # when deploy/client/ changed
```

CI runs the same checks on every PR (`.github/workflows/ci.yml`). A change to
the data path or to deployment is additionally exercised on a real fips node
before it is merged, and the PR body says what was run.

### Self-review against the project review checklist

The 13-criteria checklist used on every incoming PR is published at
[PR-REVIEW.md](PR-REVIEW.md). Run your own change through it before opening,
or hand the document to your coding agent with "review my branch against this
checklist". It is the first thing that happens to any submission, so doing it
yourself saves a round trip.

### Additional requirements for feature PRs

- **Documentation updated alongside the code.** Every environment variable in
  [docs/configuration.md](docs/configuration.md) and the matching
  `deploy/*.env.example`; agent↔backend wire changes in
  [docs/api-agent-backend.md](docs/api-agent-backend.md); schema changes in
  [docs/data-model.md](docs/data-model.md); new failure modes in
  [docs/troubleshooting.md](docs/troubleshooting.md).
- **A CHANGELOG entry** under `[Unreleased]`, written for operators: what
  changes for them, whether `up.sh reload`, an agent restart or a migration
  is involved.
- **Tests that fail before the change** for a bug fix, and tests for the new
  behaviour for a feature. Prefer the existing fakes (`agent/agent_test.go`,
  `testStore` / `testPortal`) over new scaffolding.

### Additional requirements for changes to the security boundary

Changes to `deploy/render-nftables.sh`, `deploy/up.sh`, `exit/sockd.conf`,
`backend/store/authz.go`, the whitelist/attribution code, payment settlement
or webhook verification must:

- state in the PR body **what a client (or an operator's mistake) can do
  after the change that it could not before**, and the other way round;
- keep [docs/threat-model.md](docs/threat-model.md) true: add or correct the
  claim, citing the file that enforces it;
- keep the agent↔backend API additive within `/v1` so that an older agent
  keeps working against a newer backend (and say what a newer agent loses
  against an older backend);
- keep migrations additive and safe for existing rows, with the default you
  chose for them and why.

### Merge mechanics

PRs are squash-merged. One logical change per PR becomes one commit on
`master`; the commit message is rewritten at merge time, so in-PR history
does not need to be pretty. Stacked PRs merge in their declared order; GitHub
retargets the next one automatically.

## Releasing

Not every merged change is a release. Changes collect under `[Unreleased]` in
[CHANGELOG.md](CHANGELOG.md) until the maintainer decides to release them; a
release is then a single annotated tag on `master`:

```sh
git switch master && git pull
git tag -a v0.1.0 -m "fips-exit-gate 0.1.0"
git push origin v0.1.0
```

Versions follow [Semantic Versioning](https://semver.org/). One version
covers every component in the tree (agent, backend, captive, dispatch, exit
image, deploy scripts): **patch** for fixes, **minor** for features and for
additive agent↔backend API changes, **major** for anything that breaks the
agent↔backend wire contract, the deployment layout (`up.sh`, compose, env
variables) or a migration that older backends cannot run. Before 1.0 a minor
release may still contain breaking changes; the changelog calls them out
under an **Upgrade notes** heading.

Pushing the tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml):

1. Checks the tag: `vX.Y.Z` or `vX.Y.Z-pre` (for example `v0.2.0-rc.1`),
   annotated, on a commit of `master`, and not released yet.
2. Runs the [CI checks](.github/workflows/ci.yml) on the tagged commit. If
   they fail nothing is published; delete the tag
   (`git push --delete origin v0.1.0 && git tag -d v0.1.0`), fix, tag again.
3. Publishes the GitHub release with the `[Unreleased]` section as its notes
   (GitHub's generated notes when the section is empty). A tag with a
   pre-release suffix becomes a pre-release.
4. Moves the `[Unreleased]` entries under `## [X.Y.Z] - date` on `master` and
   updates the compare links (a commit by `github-actions[bot]`; skipped with
   a warning if `[Unreleased]` changed after the tag).

**Upgrade order** for a release is backend first (it applies its migrations
on start and must accept the previous agent version), then the exit nodes
(`up.sh reload` only when the release notes say the ruleset changed, then the
compose stack with `--build`). The notes for each release say which of these
steps it needs.

The version comes from the tag. `pkg/version` reports the value baked in with
`-ldflags "-X github.com/fr34aky/fips-exit-gate/pkg/version.Version=$(git describe --tags --always --dirty)"`
(the Dockerfiles take it as the `VERSION` build argument:
`docker compose build --build-arg VERSION=$(git describe --tags --always)`),
or falls back to the VCS revision Go embeds in the binary. `VERSION` at the
repo root is substituted by `git archive` (`export-subst`), so a tarball of a
tag carries its name even without `.git`.

## AI coding assistant policy

Use of AI coding assistants in preparing a contribution is welcome. What is
required is that the contributor does a thorough manual review and editorial
pass over the output before submission:

- Verify the code does what it claims, not just that it builds and the tests
  pass; for anything on the data path, that means the container tests and,
  where it matters, a real fips node.
- Verify the documentation matches the behaviour, in particular the threat
  model: a claimed control that does not exist is worse than none.
- Spot-check the diff: no unrelated files, no fabricated APIs, no references
  to symbols that do not exist, no `go.mod` bumps you did not intend.
- Do not include coding-assistant attribution trailers in commit messages or
  PR descriptions.
- Be ready to discuss the design choices in the PR as if you wrote every
  line, because for the purposes of accountability you did.

Submissions that show signs of being unreviewed agent output will be closed
without human review.

## Where the conversation happens

- **GitHub issues** — bugs, feature requests, design discussion.
- **GitHub PRs** — discussion specific to a change in flight.

For anything about the fips protocol or daemon itself (addressing, the mesh
firewall, transports), go upstream to
[jmcorgan/fips](https://github.com/jmcorgan/fips); this project builds on
what the daemon provides.

## Further reading

- [PR-REVIEW.md](PR-REVIEW.md) — the review checklist.
- [docs/threat-model.md](docs/threat-model.md) — what every control is meant to guarantee.
- [docs/api-agent-backend.md](docs/api-agent-backend.md) — the agent↔backend contract.
- [docs/configuration.md](docs/configuration.md) — every environment variable and config file.
- [README.md](README.md) — components, how access works, documentation index.

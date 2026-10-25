# PR Review Checklist

<!-- markdownlint-disable MD013 -->

This is the 13-criteria checklist run against every incoming PR. The first
pass on any submission is exactly this list, so executing it yourself before
opening, or after pushing a fresh revision, saves a review round trip.

The document is also written so you can hand it to a coding agent with
"review my branch against this checklist" and get a structured pass.

## Step 1 — Should this even be reviewed?

Skip the review (and say so) if the PR is:

- closed, merged, or marked draft
- automated (bot author, dependency bumps) and trivially OK
- so small and obviously correct (typo fix, single-line doc tweak) that a
  thirteen-point pass is overkill; a one-paragraph informal review is better
  in that case

## Step 2 — Gather context

Read these *before* analyzing the diff:

1. PR metadata.

   ```sh
   gh pr view <num> --json title,body,author,headRefName,baseRefName,headRefOid,baseRefOid,mergeable,statusCheckRollup,commits
   ```

2. The diff.

   ```sh
   gh pr diff <num>
   ```

3. Base-branch freshness: how far `master` has moved since the PR forked, and
   whether the PR is stacked on another open PR (its body must say so).
4. Project guidance: [CONTRIBUTING.md](CONTRIBUTING.md), and
   [docs/threat-model.md](docs/threat-model.md) if the diff touches the
   gate (`deploy/`), authorization (`backend/store/authz.go`, whitelist),
   payments, or the captive/dispatch data path.
5. The contracts the change is held to: the
   [agent↔backend API](docs/api-agent-backend.md) for anything crossing that
   wire, the [data model](docs/data-model.md) for migrations, and upstream's
   [address derivation](docs/derivation.md) for anything touching identity.
6. Related work: skim open issues and PRs for overlap.
7. For "this looks wrong" observations: `git blame` the lines first. What
   looks like a bug is sometimes a deliberate workaround with a commit message
   explaining it (the NAT-vs-filter gate split, the `-p 1` store tests, the
   `fd00::/8` block in Dante are all of that kind).

## Step 3 — The 13 criteria

### Group A — PR hygiene

1. **PR body and issue cross-reference.** Does the body describe the change
   accurately and match what the diff does? Does it state the problem and a
   concrete failure scenario, not just the solution? Should it carry
   `Closes #N`? For a stacked PR, is the merge order stated?
2. **Commit hygiene and base freshness.** Clean commits or a single commit,
   no "WIP" / "fix typo" noise, based on a recent `master` (or on its
   declared parent PR).
3. **Commit message quality.** Subject plus body where warranted, accurate
   to the commit, explaining *why*, and free of extraneous footers, in
   particular coding-assistant attribution trailers.

### Group B — Diff content

4. **Does it do what it says it does.** Walk each claimed behaviour from the
   PR body against the diff. For a bug fix, is there a test that failed
   before the change, and does the PR say so?
5. **Coherent whole.** All of the diff serves the stated goal; no drive-by
   formatting, no unrelated touch-ups, no scope creep. Docs and env examples
   that the change makes stale are updated in the same PR.
6. **Fits the codebase as a natural extension.** Uses the existing pieces:
   `Store.inTx` / `readTxRR` and `RecomputeAuthz` rather than ad-hoc SQL
   outside the store; the `Firewall` interface and `nft -f` batches in the
   agent; `render-nftables.sh` over `services.conf` rather than hand-edited
   rules; the `pkg/metrics` registry; the portal's templates, `friendlyErr`
   and `render`; the `testStore` / `testPortal` / fake-firewall harnesses in
   tests. New environment variables follow the existing `getenv` /
   `getenvInt` pattern and have a documented default.

### Group C — Cross-cutting concerns

7. **New dependency surface.** `agent/`, `captive/` and `dispatch/` are
   stdlib-only on purpose (the agent must build for OpenWrt); a new module
   anywhere needs a stated reason, and `go.mod`'s `go` directive must not
   move as a side effect. System tools shelled out to (`nft`, `wg`,
   `docker`), container images, and external services (mints, BTCPay,
   relays) all count.
8. **Verification.** `gofmt`, `go vet`, `go test ./...`, the store tests
   against Postgres when `backend/` changed; `deploy/test/run-nft-gate-test.sh`
   when the ruleset or `up.sh` changed; `deploy/client/test/run-tunnel-test.sh`
   when `deploy/client/` changed; and, for data-path or deployment changes,
   what was run on a real fips node. The PR body says which of these ran.
9. **Documentation impact.** [docs/configuration.md](docs/configuration.md)
   and `deploy/*.env.example` for every variable; the API, data-model and
   threat-model docs where they apply; a troubleshooting entry for a new
   failure mode; a CHANGELOG entry under `[Unreleased]` written for the
   operator (migration? `up.sh reload`? agent restart?).
10. **Security and the trust boundary.** Does anything change what traffic
    the gate lets through, and is that re-checked per packet, not only at
    connection setup? Can a client influence which account its bytes are
    billed to (whitelist, attribution, `authz_current`)? Are payment
    settlements idempotent and webhook signatures verified before any grant?
    Does the backend ever trust a header or form field for the source
    address? Are secrets kept out of logs and the changelog? Does a new
    endpoint need the node bearer, the admin token, or a session, and does
    it get it? Does the threat model still only claim what exists?
11. **Go, SQL and shell practices.** Errors surface with context rather than
    being swallowed; contexts and deadlines on every external call; SQL that
    must see one snapshot runs under `readTxRR`, writes that must serialize
    take the advisory lock or a `FOR UPDATE`; migrations are additive and
    numbered after the last one on `master`; shell is POSIX `sh`, `set -eu`
    aware (no `[ … ] && …` as the last statement of a loop body), and
    validated with `sh -n`.
12. **Compatibility.** An older agent against the new backend keeps working;
    the new agent against an older backend degrades, not breaks; existing
    rows get a sensible default from a migration; a live exit node survives
    the upgrade order in [CONTRIBUTING.md](CONTRIBUTING.md#releasing).
13. **Overlap and other concerns.** Open issues and PRs this duplicates,
    partially addresses or unblocks; behaviour on nodes unlike the author's
    (OpenWrt, no IPv6 egress, Docker's `FORWARD DROP`, a backend behind a
    source-masking proxy); deployment impact (`up.sh reload`, agent restart,
    rebuilt images); and fragility notes for future maintainers.

## Step 4 — Compose the review

The report is **not** a Q&A walk through the 13 criteria. Write it as prose
that reads start to finish, ordered by what matters most for this PR. All 13
criteria are addressed somewhere in the body; do not reference criterion
numbers.

A typical shape: an opening paragraph on what the PR does and the headline
observations; a body covering diff analysis, design fit, cross-cutting
concerns and surprises; a closing with a disposition: *land*,
*land-with-followups* (list them), *request-changes* (name the blockers), or
*hold*.

## Step 5 — Filter aggressively

Do not flag:

- pre-existing issues on lines the PR did not modify
- anything `gofmt`, `go vet`, the build or the test suite would catch
- pedantic style nitpicks a senior engineer would not call out
- likely intentional changes related to the broader goal
- stylistic preferences not anchored in CONTRIBUTING.md or the surrounding code

For every issue you do surface, include a concrete fix suggestion so the
author can act without a round trip. For a suspected data-path bug, the best
suggestion is a case for the container test that would catch it.

## Step 6 — Citation discipline

Reference code by full-SHA permalink so the link survives history rewrites:

```text
https://github.com/fr34aky/fips-exit-gate/blob/<full-40-char-sha>/<path>#L<start>-L<end>
```

## Notes

- Distinguish "blocker" from "worth asking about" from "fragility note". The
  closing disposition makes the action explicit.
- On re-review after new commits, lead with the delta from the prior review.
- The checklist exists to surface problems, not to assign blame.

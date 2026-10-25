# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
One version covers every component (agent, backend, captive, dispatch, exit
image, deploy). Each release's notes end with **Upgrade notes** when a
migration, an `up.sh reload` or an agent restart is involved.

Changes before this file existed are in the git history (Phase 0 through the
authz drift self-heal, August–October 2026).

## [Unreleased]

### Added

- `CONTRIBUTING.md` (workflow, required checks, security-boundary rules,
  releasing and versioning), `PR-REVIEW.md` (the 13-criteria review checklist
  every PR goes through) and this changelog.
- CI on every pull request (`.github/workflows/ci.yml`: gofmt, vet, tests with
  a Postgres service, shell syntax, and the container integration tests when
  present) and tag-driven releases (`.github/workflows/release.yml`).
- `pkg/version`: the build's version from the git tag (`-ldflags -X`, or the
  Dockerfiles' `VERSION` build argument), falling back to the VCS revision Go
  embeds. The backend logs it at start. `VERSION` at the repo root is
  substituted by `git archive`.

[Unreleased]: https://github.com/fr34aky/fips-exit-gate/commits/master

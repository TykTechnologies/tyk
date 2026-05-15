# Apollo Router federation integration harness

This directory exists so reviewers (and future contributors) can re-run
the Apollo Router 2.14.0 validation that produced Casts 1–5 in
[PR #8193](https://github.com/TykTechnologies/tyk/pull/8193). It is a
manual reproduction harness, not a CI gate.

## Prerequisites

Two binaries must be on `$PATH`:

- **Apollo Rover** (`rover`): `curl -sSL https://rover.apollo.dev/nix/latest | sh`
- **Apollo Router** (`apollo-router`): see
  [the install guide](https://www.apollographql.com/docs/router/quickstart/)

You also need:

- Go 1.25+ (parent module's toolchain — used to compile the in-process
  Tyk runner under `runner/`).
- Python 3.10+ with `aiohttp` for the stub second subgraph.
- `envsubst` (typically from `gettext`), `bash`, and `curl`.

The scripts will not download licensed Apollo Router GraphOS features.
Apollo Router's ELv2 license requires `APOLLO_ELV2_LICENSE=accept` and
telemetry can be opted out with `APOLLO_TELEMETRY_DISABLED=1`; the
scenario scripts set both for you, but you can override them.

## Layout

- `runner/` — in-process Tyk gateway, separate Go module so the parent
  build does not pull in the test-only `gateway.StartTest` helper.
- `stub-subgraph/` — Python aiohttp federation v2 subgraph that owns
  `Post` and references `User` so the supergraph fans out to Tyk.
- `compose/` — `rover supergraph compose` configs, one per scenario,
  with `${TYK_URL}` / `${STUB_URL}` placeholders the scripts fill in.
- `router/router.yaml` — Apollo Router config (subgraph errors enabled,
  no subscription block — see PR description for why).
- `scenarios/` — five end-to-end reproduction scripts, one per cast.

## Running a scenario

Each scenario is self-contained. From this directory:

```bash
bash scenarios/01-rest.sh
bash scenarios/02-hasura.sh
bash scenarios/03-partial-failure.sh
bash scenarios/04-proxy-passthrough.sh
bash scenarios/05-both-positions.sh
```

Every script prints the curl response on stdout and exits non-zero on
failure. Background processes are SIGTERMed via a trap on EXIT.

## What is and isn't covered

The harness covers Casts 1–5 from PR #8193: REST UDG federation,
GraphQL UDG federation with Hasura-style auto-detect, partial-failure
spec compliance, proxy-mode passthrough, and Tyk in both subgraph and
proxy positions in the same supergraph.

**Cast 6 (subscriptions through Apollo Router) is intentionally not in
this harness.** Apollo Router 2.14 requires a GraphOS commercial license
(`APOLLO_KEY` / `APOLLO_GRAPH_REF`) for federated subscriptions. See the
PR description for the full walkthrough, expected responses, and notes
on what's been validated end-to-end versus what's deferred.

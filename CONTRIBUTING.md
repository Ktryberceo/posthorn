# Contributing to Posthorn

Thanks for your interest. This guide covers what you need to build, test, and contribute.

## Scope

v1.0 and v2.0 are shipped and v2.1 is at release candidate. The full requirements live in [`spec/`](./spec/) across three documents:

1. [`spec/01-project-brief.md`](./spec/01-project-brief.md) — problem, users, scope, threat model, risks
2. [`spec/02-prd.md`](./spec/02-prd.md) — functional and non-functional requirements, epic and story breakdown
3. [`spec/03-architecture.md`](./spec/03-architecture.md) — file layout, lifecycle, request flow, component design, ADRs

v1.0 covers three ingress shapes (HTTP form, HTTP API with Bearer auth + idempotency, SMTP listener) and five transports (Postmark, Resend, Mailgun, AWS SES, outbound-SMTP relay) plus the operational surface (`/healthz`, `/metrics`, dry-run, CSRF tokens, named `trusted_proxies` presets, IP-stripping). v2.0 added the stateful platform: optional SQLite storage with a durable retry queue and durable idempotency, a bounce/complaint suppression list, Postmark lifecycle webhooks, a webhook transport, HTML bodies, and attachments. v2.1 adds multiple SMTP listeners, allowlisted List-header passthrough, and implicit TLS on the outbound SMTP transport.

What comes next is on the [roadmap page](https://posthorn.dev/roadmap/), which is canonical. The demand-gated items (unsubscribe injection, fan-out to several transports, per-sender routing on a shared listener, batch send) ship when an operator shows up with the workload, not before. The canonical "deliberately not on the roadmap" list is in [`spec/01-project-brief.md`](./spec/01-project-brief.md). If you're unsure whether a contribution fits, open an issue before writing code.

### Adding a transport

A new provider transport is accepted when all four hold: a named operator is using the provider; the bespoke client fits in roughly 250 lines of implementation, in one file under `core/transport/` (see "Registering a new transport" on the [transports page](https://posthorn.dev/configuration/transports/)); the provider has a free or sandbox tier, so the maintainer can validate it without a paid account; and the pull request includes one live send from the contributor's own account with the redacted `submission_sent` log line. Open an issue first and name the provider, then the PR carries the same tests every transport has: the header-injection table, the sentinel-credential-not-in-logs test, an entry in `core/providertest/`, a docs page, and a section in [docs/manual-test.md](./docs/manual-test.md). The maintainer writes the spec requirement.

The architecture doc's [Architectural decisions log](./spec/03-architecture.md#architectural-decisions-log) records the ADRs that pin the structure. To deviate from any of them, update the architecture doc with the new decision and rationale before changing code.

## Prerequisites

- Go 1.26+
- An account with at least one of the supported transactional providers for end-to-end testing (Postmark sandbox token, Resend test key, Mailgun sandbox domain, AWS SES sandbox, or a generic outbound-SMTP relay like Mailtrap)
- Docker (optional, for testing the container deployment)

## Repository layout

Posthorn is a single Go module:

- [`core/`](./core/) — the gateway, the `cmd/posthorn` binary, all the business logic.
- [`spec/`](./spec/) — the specification: project brief, PRD, architecture.
- [`docs/`](./docs/) — operator-facing documentation that lives in-repo. The public site source is in [`site/`](./site/) and ships to [posthorn.dev](https://posthorn.dev).
- [`site/`](./site/) — Astro + Starlight source for the docs site.

## Build and test

A `Makefile` at the repo root wraps the common tasks (`make help` lists them):

```bash
make test        # hermetic suite with the race detector — no network, no keys
make lint        # golangci-lint
make build       # build the posthorn binary
make site        # build the docs site
```

`make test` needs **no third-party credentials** and is the everyday gate. It includes the `core/providertest/` harness — ingress→egress end-to-end tests that drive a real form (or a real `net/smtp` client) through the real gateway/listener and the real transport into a fake provider, asserting the wire shape and header-injection safety. CI runs exactly this on every push and PR (`go test -race ./...`); see [`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

### The docs site

The [`site/`](./site/) Astro + Starlight source builds with `make site` (or `npm run build` inside `site/`) and **deploys automatically to GitHub Pages** via [`.github/workflows/site-deploy.yml`](./.github/workflows/site-deploy.yml) on every push to `main` that touches `site/**`. There's no manual publish step.

The `/changelog` page is generated from the repo-root [`CHANGELOG.md`](./CHANGELOG.md) by `site/scripts/gen-changelog.mjs` as part of the build, so edit `CHANGELOG.md`, not the generated page (which is gitignored).

### Live-provider validation

```bash
make test-live   # -tags integration: real provider APIs, non-delivering targets
```

The live tier hits real provider endpoints against non-delivering targets (Postmark's public test token, the SES simulator, Resend's `delivered@resend.dev`). Postmark uses a **public** token and always runs; the others **skip** unless you supply credentials via the environment — source them from your secret store, e.g.:

```bash
RESEND_API_KEY=$(pass show posthorn/resend-test) \
MAILGUN_API_KEY=$(pass show posthorn/mailgun-test) MAILGUN_DOMAIN=sandboxXXX.mailgun.org \
  make test-live
```

In CI the live tier runs only via [`integration-live.yml`](./.github/workflows/integration-live.yml) — manual dispatch or a weekly schedule, on the canonical repo, behind the protected `live-providers` Environment. It never runs on pull requests, so fork contributors can never reach a credential. SES authenticates via GitHub OIDC (no stored AWS key). As of 2026-09-29 the canonical repo's `live-providers` Environment holds only the Postmark lifecycle token, so the weekly run exercises Postmark and the Resend, Mailgun, and SES tests skip; the table under "What has actually been validated" in [docs/manual-test.md](./docs/manual-test.md) is the record. The design and remaining slices are tracked in [issue #76](https://github.com/craigmccaskill/posthorn/issues/76).

The live tier stops at "the real provider accepted a well-formed request" — it does **not** assert inbox delivery or DKIM/SPF. That's deliberate: the provider signs and owns reputation, and Posthorn is upstream of signing, so DKIM is not ours to test (see the brief's outbound-abuse posture). The older [manual end-to-end procedure](./docs/manual-test.md) remains the reference for a full-binary walkthrough (form mode, API mode, SMTP listener) when you want to eyeball a real send by hand.

## Commit conventions

- Tag each commit with the story ID it implements, e.g. `feat(gateway): retry policy on transient transport errors (Story 4.1)`
- Prefixes: `feat:` new functionality, `fix:` bug fixes, `test:` test-only changes, `docs:` documentation, `chore:` build/config/CI
- Reference the relevant FR or NFR in the commit body when it adds clarity (e.g., "Implements NFR1 — header injection prevention via structured JSON API")
- Don't squash stories into a single commit — each story should be at least one commit so the git history maps to the PRD

## Updating the spec

If implementation reveals something the spec missed, update the relevant doc in `spec/` and reference the change in the commit that exposes it. The spec is the source of truth; pull requests that change behavior without a corresponding spec update will be sent back.

## Security

This codebase handles untrusted input from public form submissions, server-to-server callers (API mode), and internal-network SMTP clients, plus credentials for an outbound email provider. Security-relevant changes — header construction, API key handling, rate limiting, input validation, fail-closed origin checks, SMTP envelope vs. MIME header handling, idempotency-key tampering, brute-force lockouts — require explicit test coverage per the security NFRs in [`spec/02-prd.md`](./spec/02-prd.md) (NFR1 through NFR33).

For vulnerability reporting, see [SECURITY.md](./SECURITY.md). **Do not open public GitHub issues for security vulnerabilities.**

## Community projects

Third-party clients, libraries, and tools are listed on the [ecosystem page](./docs/ecosystem.md). Listing is a convenience for users, **not an endorsement**. Posthorn does not maintain, continuously review, or vouch for third-party code, and a listed project can ship new versions at any time without review.

To propose a project, open a pull request adding a row to [`docs/ecosystem.md`](./docs/ecosystem.md). To be listed, a project must:

- have a public source repository (the listing links the repository, not a package registry)
- be released under an [OSI-approved license](https://opensource.org/licenses)
- work against the current Posthorn release
- show signs of being maintained (a versioned release and recent activity)
- use a name that does not imply official status

Clients that handle API keys or other credentials get extra scrutiny, and the listing records the specific version last reviewed.

## Naming

"Posthorn" refers to this project. Community packages are welcome to reference it in their names (for example `posthorn-rb` or `go-posthorn`), but please do not name or describe a project in a way that implies it is official or endorsed (for example "Posthorn Official Client", or presenting the project's branding as your own). This keeps it clear to users which code the project maintains and which it does not.

## Questions

Open a GitHub issue or start a discussion. For implementation questions, [`spec/03-architecture.md`](./spec/03-architecture.md) is the source of truth; for scoping questions, [`spec/01-project-brief.md`](./spec/01-project-brief.md).

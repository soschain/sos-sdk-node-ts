# Shared SOS Node SDK agent contract
## Blocking local-first SDK release

Accumulate all grouped functional branches and changelogs without changing the
package version. Merge them to `main`, validate that cumulative state, and only
then create one version-only release branch. Preserve the exact published SHA
as immutable `stable/v<version>`; never increment once per feature branch.

The canonical contract is [`SDK_LAYERING.md`](https://github.com/soschain/sos-data-utils-ts/blob/main/docs/SDK_LAYERING.md). Its
indivisible order is **local packages -> full local test matrix -> merge every
validated branch to `main` -> publish bottom-up -> install exact registry
versions and commit lockfiles on `main` -> staging**. Never publish to discover
deterministic failures and never commit a local package reference. Staging
begins only after exact registry packages are installed and verified.

Scope the affected matrix by access path. Demo requires relevant local Demo
checks, exact registry dependencies/lockfiles and portal build, then online
Demo deployment. Run dev:staging/Test Network lifecycle checks afterward and
redeploy fixes; they do not hold Demo or establish Test Network/production
readiness. Demo remains BFF-only; network cases retain their GW/Fabric gates.
No-GDC architecture, authentication, privacy and custody remain mandatory.

## Jurisdiction-scoped integration acceptance

Jurisdiction-specific journeys are optional and nonblocking unless the change
affects that exact flow. Unaffected Demo and general technology-sector
lifecycles must not wait for Spain's certificate-signed PDF or another
jurisdiction's documents, provider or private fixture. Preserve the selected
lifecycle's own authentication, authority, privacy and custody checks.

Affected regressions remain mandatory, including signing, upload and
verification when a Spanish signed-PDF admission flow changes. Select scope
before testing. A selected failure remains a failure; never turn it into a
skip, synthetic success or green release claim. Report journeys separately
from their viewport, theme, flavour and access-mode execution variants.


## Mandatory TDD

Write the smallest failing test before every behavior change. Begin every test
file with a `Flow contract:` comment and prove positive, negative and retained
compatibility behavior.

## Package boundary

- Consume runtime-neutral authorization and orchestration from
  `sos-sdk-core-ts`.
- Keep product-neutral Node transport, credentials, persistence and jobs here
  so SOSChain, Vet and UHC do not duplicate them.
- Do not duplicate types or deterministic builders from `sos-data-utils-ts`.
- Do not put Vet or UHC product policy here; use their public SDK contracts at
  an explicit SOSChain integration boundary when required.
- Keep new functionality out of frozen GW CORE v1 and `gdc-*`.
- Never commit Git, workspace, vendored or `file:` dependencies.
- For prompt audio, consume the canonical descriptor produced by
  `sos-data-utils-ts/prompt-audio`; never reproduce its fields or cache a live
  OTP as one object. Prewarm paid synthesis sequentially and bound every test
  run to one worker/process unless an isolated matrix explicitly requires more.

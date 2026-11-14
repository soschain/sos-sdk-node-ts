---
name: preserve-shared-sos-sdk-layering
description: Preserve sos-sdk-node-ts as the product-neutral Node runtime shared by SOSChain, Vet and UHC above sos-data-utils-ts and sos-sdk-core-ts. Use for Node HTTP clients, credentials, persistence, jobs, prompt audio, emergency delivery, exports, package dependencies or SDK-layering decisions.
---

# Preserve shared SOS SDK layering in Node
## Blocking local-first SDK release

All grouped behavior and changelog changes merge without a version change.
After the cumulative gate, create one version-only release branch and preserve
its exact published commit as immutable `stable/v<version>`. Never increment
once per feature or move, reuse, delete or force-update a stable branch.

The canonical contract is [`SDK_LAYERING.md`](https://github.com/soschain/sos-data-utils-ts/blob/main/docs/SDK_LAYERING.md). Its
indivisible order is **local packages -> full local test matrix -> merge every
validated branch to `main` -> publish bottom-up -> install exact registry
versions and commit lockfiles on `main` -> staging**. Never publish to discover
deterministic failures and never commit a local package reference. Staging
begins only after exact registry packages are installed and verified.


Read [docs/SDK_LAYERING.md](../../../docs/SDK_LAYERING.md).

`sos-data-utils-ts` consumes independent Antifraud and FHIR contracts.
`sos-sdk-core-ts` consumes those contracts and owns runtime-neutral orchestration.
`sos-sdk-node-ts` consumes the shared layers and owns Node adapters.
No SOS package imports, depends on, wraps or re-exports a `gdc-*` package,
directly or transitively. Frozen GDC projects may consume these independent
packages in a future approved migration.


- Keep deterministic types and builders in `sos-data-utils-ts`.
- Keep runtime-neutral authorization and orchestration in `sos-sdk-core-ts`.
- Keep product-neutral Node transport, bearer credentials, persistence and
  jobs here. SOSChain, Vet and UHC runtimes may all consume these adapters.
- Persist an accepted Encounter handover through one atomic adapter method
  containing the projection Communication, expected/current audience delta and
  family-safe journey event. Never expose partial persistence steps or rewrite
  historical Communication recipients.
- Prompt-audio canonicalization and localized digit fragments come from
  `sos-data-utils-ts/prompt-audio`. This package hashes that canonical value,
  owns Node storage and synthesis adapters, coalesces misses and prewarms paid
  assets sequentially. Never cache a complete live OTP.
- For secure messages, inject `node:crypto.randomBytes` through the shared
  `SecureRandomSource` only. Keep ML-KEM, KDF, CEK wrapping and AES operations
  in `sos-sdk-core-ts`; text and audio use the same byte API and differ only by
  protected content type.
- Do not make the shared packages depend on this runtime package.
- Do not commit a local, Git, workspace or vendored dependency.
- Run Node tests with concurrency one on a shared developer machine. Never
  launch full matrices, local services or browser runs in parallel; inventory
  and clean every owned process before ending the gate.

Use red-green TDD, require HTTPS outside localhost, preserve idempotency and
fail closed without logging or returning credentials.

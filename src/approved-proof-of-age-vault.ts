import { createHash } from 'node:crypto'
import { isDeepStrictEqual } from 'node:util'
import type { TransactionalVaultRepository } from './transactional-vault.js'

type Holder = Readonly<{ tenantVaultId: string; holderReference: string; generationId?: string }>
type Projection = Readonly<{
  docType: string
  namespaces: Readonly<Record<string, Readonly<Record<string, boolean>>>>
}>
type Review = Holder & Readonly<{ revision: string; replaces?: string }> & (
  Readonly<{ expiresAt: number; projection: Projection }>
  | Readonly<{ expiresAt?: never; projection?: never }>
)
type StoredReview = Pick<Review, 'revision' | 'replaces' | 'expiresAt' | 'projection'> & { id: string }

const collection = 'approved-proof-of-age-reviews'
const holderKey = ({tenantVaultId, holderReference, generationId}: Holder) => {
  const binding = generationId === undefined
    ? [tenantVaultId, holderReference]
    : [tenantVaultId, holderReference, generationId]
  return createHash('sha256').update(JSON.stringify(binding)).digest('hex')
}

/** Uses the same transactional port in Demo and in the hosted issuer. Both
 * authority callbacks must resolve current, server-verified identities. */
export class ApprovedProofOfAgeVault {
  constructor(private readonly options: Readonly<{
    store: TransactionalVaultRepository
    verifyReview(participant: unknown, reviewId: string): Promise<Review | undefined>
    resolveHolder(participant: unknown): Promise<Holder | undefined>
    now?: () => number
  }>) {}

  async record(participant: unknown, reviewId: string): Promise<string> {
    const review = await this.options.verifyReview(participant, reviewId)
    if (!review || !reviewId || review.revision !== reviewId || !review.tenantVaultId || !review.holderReference) {
      throw new Error('proof_of_age_review_forbidden')
    }
    const { revision, replaces, expiresAt, projection } = review
    const next = structuredClone({
      id: holderKey(review), revision,
      ...(replaces !== undefined ? { replaces } : {}),
      ...(projection ? { expiresAt, projection } : {}),
    })
    return this.options.store.runTransaction(async store => {
      const current = await store.get<StoredReview>(collection, next.id)
      if (current?.revision === revision && isDeepStrictEqual(current, next)) return revision
      if (current?.revision !== replaces || current?.revision === revision || (!projection && !current)) {
        throw new Error('proof_of_age_review_conflict')
      }
      if (projection && (typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt <= this.now())) {
        throw new Error('proof_of_age_review_expired')
      }
      if (!await store.put(collection, next)) throw new Error('proof_of_age_review_write_failed')
      return revision
    })
  }

  async read(participant: unknown): Promise<Readonly<{ revision: string; projection: Projection }> | undefined> {
    const holder = await this.options.resolveHolder(participant)
    if (!holder) return undefined
    const current = await this.options.store.get<StoredReview>(collection, holderKey(holder))
    if (!current?.projection || typeof current.expiresAt !== 'number' ||
      !Number.isSafeInteger(current.expiresAt) || current.expiresAt <= this.now()) return undefined
    return { revision: current.revision, projection: current.projection }
  }

  private now() {
    return this.options.now?.() ?? Date.now()
  }
}

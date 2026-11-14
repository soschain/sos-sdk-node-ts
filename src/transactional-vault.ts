import type { IVaultRepository, VaultQuery, VaultRecord } from 'sos-sdk-core-ts/vault-repository'

type VaultState = Map<string, Map<string, VaultRecord>>

function memoryPort(state: VaultState): IVaultRepository {
  return {
    async put(collection, values) {
      const records = state.get(collection) ?? new Map<string, VaultRecord>()
      const copies = structuredClone(Array.isArray(values) ? values : [values])
      for (const record of copies) records.set(record.id, record)
      state.set(collection, records)
      return true
    },
    async get<T extends VaultRecord>(collection: string, id: string) {
      return structuredClone(state.get(collection)?.get(id)) as T | undefined
    },
    async query<T extends VaultRecord>(collection: string, query: VaultQuery) {
      let records = [...(state.get(collection)?.values() ?? [])] as T[]
      for (const condition of query.where ?? []) {
        records = records.filter(record => {
          const value = (record as Record<string, unknown>)[condition.attribute]
          if (condition.equals !== undefined) return value === condition.equals
          return condition.in ? condition.in.includes(value) : true
        })
      }
      if (query.orderBy) {
        const { attribute, direction } = query.orderBy
        records.sort((left, right) => {
          const a = (left as Record<string, any>)[attribute]
          const b = (right as Record<string, any>)[attribute]
          return (a < b ? -1 : a > b ? 1 : 0) * (direction === 'desc' ? -1 : 1)
        })
      }
      if (query.offset) records = records.slice(query.offset)
      if (query.limit) records = records.slice(0, query.limit)
      return structuredClone(records)
    },
    async delete(collection, id) { return state.get(collection)?.delete(id) ?? false },
  }
}

/** Atomic capability on the SOS-owned runtime-neutral vault interface. */
export interface TransactionalVaultRepository extends IVaultRepository {
  initialize(): Promise<void>
  /** Use only the supplied port inside the callback; read before writing for durable adapters. */
  runTransaction<T>(operation: (vault: IVaultRepository) => Promise<T>): Promise<T>
}

/** Process-owned memory adapter with isolated commit/rollback and serialized access. */
export class TransactionalMemoryVaultRepository implements TransactionalVaultRepository {
  private state: VaultState = new Map()
  private pending: Promise<void> = Promise.resolve()
  async initialize(): Promise<void> {}
  put<T extends { id: string }>(collection: string, values: T | T[]): Promise<boolean> {
    return this.exclusive(() => memoryPort(this.state).put(collection, values))
  }
  get<T extends { id: string }>(collection: string, id: string): Promise<T | undefined> {
    return this.exclusive(() => memoryPort(this.state).get<T>(collection, id))
  }
  query<T extends { id: string }>(collection: string, query: VaultQuery): Promise<T[]> {
    return this.exclusive(() => memoryPort(this.state).query<T>(collection, query))
  }
  delete(collection: string, id: string): Promise<boolean> {
    return this.exclusive(() => memoryPort(this.state).delete(collection, id))
  }
  runTransaction<T>(operation: (vault: IVaultRepository) => Promise<T>): Promise<T> {
    return this.exclusive(async () => {
      const draft = structuredClone(this.state)
      const result = await operation(memoryPort(draft))
      this.state = structuredClone(draft)
      return result
    })
  }
  private exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.pending.then(operation)
    this.pending = result.then(() => undefined, () => undefined)
    return result
  }
}

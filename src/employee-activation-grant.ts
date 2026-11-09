import { buildStableActorIdentifier, type ActorContactInput } from 'antifraud-data-utils-ts/organization-identity'
import { EmployeeActivationGrantVersions, type EmployeeActivationGrant } from 'gdc-common-utils-ts'

export type EmployeeActivationGrantInput = ActorContactInput & Readonly<
  Pick<EmployeeActivationGrant, 'employeeDid' | 'employeeRoleCode' | 'providerDid' | 'routeContext'> & {
    createdAt: Date
    expiresAt: Date
  }
>

/** Routing data only: contact possession, owner binding and TTL enforcement remain in the BFF. */
export function createEmployeeActivationGrant(input: EmployeeActivationGrantInput): EmployeeActivationGrant {
  return {
    version: EmployeeActivationGrantVersions.V1,
    employeeDid: input.employeeDid,
    employeeRoleCode: input.employeeRoleCode,
    employeeActorIdentifier: buildStableActorIdentifier(input),
    providerDid: input.providerDid,
    routeContext: input.routeContext,
    createdAt: input.createdAt.toISOString(),
    expiresAt: input.expiresAt.toISOString(),
  }
}

/** Compares one explicitly selected contact; matching does not establish authority. */
export function employeeActivationGrantMatchesContact(
  grant: Pick<EmployeeActivationGrant, 'employeeActorIdentifier'>,
  contact: ActorContactInput,
): boolean {
  return grant.employeeActorIdentifier === buildStableActorIdentifier(contact)
}

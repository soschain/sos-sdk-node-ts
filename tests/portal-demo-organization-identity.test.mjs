// Flow contract: verified account identity and Demo scope determine one private organization per sector, independently of portal process or selected professional role; different accounts never share an organization.
import test from 'node:test'
import assert from 'node:assert/strict'
import {derivePortalDemoOrganizationIdentity,derivePortalDemoOrganizationIdentityFromSpace} from '../dist/portal-demo-exchange.js'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
test('the same verified email opens the same private sector organization in both portals',()=>{
  const first=derivePortalDemoOrganizationIdentity(safe.tenantId,safe.individualEmail,'health-care')
  assert.deepEqual(first,derivePortalDemoOrganizationIdentity(safe.tenantId,safe.individualEmail.toUpperCase(),'health-care'))
  assert.deepEqual(first,derivePortalDemoOrganizationIdentityFromSpace(safe.tenantId,first.spaceKey,'health-care'))
  assert.notEqual(first.organizationUuid,derivePortalDemoOrganizationIdentity(safe.tenantId,safe.firstContactEmail,'health-care').organizationUuid)
  assert.notEqual(first.organizationUuid,derivePortalDemoOrganizationIdentity(safe.tenantId,safe.individualEmail,'animal-care').organizationUuid)
  assert.ok(!JSON.stringify(first).includes(safe.individualEmail))
})

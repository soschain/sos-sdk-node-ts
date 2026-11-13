// Flow contract: controller-authored catalog resources share one injected vault through the authenticated peer BFF port; publication is revision-checked, organization-scoped and atomic.
import assert from 'node:assert/strict'
import test from 'node:test'
import {OrganizationCatalogVaultProvider} from '../dist/organization-catalog-vault.js'
import {PortalDemoExchange,PortalDemoExchangeClient,createPortalDemoExchangeHandler} from '../dist/portal-demo-exchange.js'
import {TransactionalMemoryVaultRepository} from '../dist/transactional-vault.js'
import {buildDemoWorkspaceScope} from 'sos-data-utils-ts/demo-workspace-scope'
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy'
test('publishes and reads a catalog across the real handler boundary, rejecting stale writes and foreign organizations',async()=>{
 const scope=buildDemoWorkspaceScope({deployment:'test',network:'demo',portalFamily:'soschain',tenantId:'demo-soschain'}),store=new TransactionalMemoryVaultRepository()
 const organizationReference=`Organization/${safe.demoOrganizationUuids.healthCare}`,participant={actorIdentifier:`urn:uuid:${safe.resourceUuid}`,organizationReference}
 const provider=new OrganizationCatalogVaultProvider({store,collection:'catalog-test',organizationReference,expiresAt:Date.now()+60_000})
 const bearer='fixture-service-token-at-least-32-characters'
 const handler=createPortalDemoExchangeHandler({exchange:new PortalDemoExchange({store}),scope,bearer,catalogProvider:async input=>{if(input.participant.organizationReference!==organizationReference)throw Object.assign(new Error('catalog_forbidden'),{status:403});return provider.execute(input.catalog)}})
 const client=new PortalDemoExchangeClient({baseUrl:'http://localhost',bearer,fetchImpl:async(url,init)=>handler(new Request(url,init))})
 const resource={resourceType:'HealthcareService',id:safe.resourceUuid,meta:{claims:{'HealthcareService.name':'Synthetic dental service'}}}
 const written=await client.catalog(scope,participant,{kind:'save',expectedRevision:0,resources:[resource]})
 assert.equal(written.revision,1)
 assert.deepEqual((await client.catalog(scope,participant,{kind:'read'})).resources,[resource])
 await assert.rejects(client.catalog(scope,participant,{kind:'save',expectedRevision:0,resources:[resource]}),/catalog_revision_conflict/)
 await assert.rejects(client.catalog(scope,{...participant,organizationReference:'Organization/foreign'},{kind:'read'}),/catalog_forbidden/)
 assert.equal((await handler(new Request('http://localhost',{method:'POST',body:'{}'}))).status,401)
})

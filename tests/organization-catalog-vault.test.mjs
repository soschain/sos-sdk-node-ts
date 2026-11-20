// Flow contract: controller-authored catalog resources and replacement documents share one injected vault through the authenticated peer BFF port; publication is revision-checked, organization-scoped and atomic.
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

test('replaces the public catalogue while retaining directory resources and validating the host publisher', async () => {
  const store = new TransactionalMemoryVaultRepository()
  const organizationReference = `Organization/${safe.demoOrganizationUuids.animalCare}`
  const publisher = {id: organizationReference, name: 'Demo animal provider'}
  const publication = {publisher, sector:'animal-care', demo:true}
  const provider = new OrganizationCatalogVaultProvider({store, collection:'catalog-test', organizationReference, expiresAt:Date.now()+60_000, publication})
  const previous = {resourceType:'Product', id:'previous-product', meta:{claims:{}}}
  await provider.execute({kind:'save', expectedRevision:0, resources:[previous]})

  const offer = {id:'north-america', seller:{id:'demo-distributor', name:'Demo distributor'},
    eligibleRegions:[{country:'CA',regions:[]},{country:'US',regions:[]}], deliveryCountries:[], supportCountries:[], operationCountries:[],
    url:new URL('/checkout',safe.httpsBaseUrl).href, plans:[{name:'Basic',currency:'CAD',features:['Tracking'],monthly:'3.95',annually:'39.50'}]}
  const document = {jsonapi:{version:'1.1'},data:[{id:'animal-device',type:'Product',attributes:{
    category:'devices',name:'Demo animal device',description:'Demo tracker',offers:[offer],
  }}]}
  const replacement = {kind:'replace-offering-catalogue',expectedRevision:1,document}
  const published = await provider.execute(replacement)
  assert.equal(published.revision,2)
  assert.deepEqual(published.resources,[previous])
  assert.deepEqual(published.publishedOfferings[0],{id:'animal-device',type:'Product',category:'devices',name:'Demo animal device',description:'Demo tracker',demo:true,publisher,sector:'animal-care',offers:[offer]})
  await assert.rejects(provider.execute(replacement), /catalog_revision_conflict/)
  const foreignDocument = structuredClone(document)
  foreignDocument.data[0].attributes.publisher = {id:'foreign-publisher',name:'Foreign publisher'}
  await assert.rejects(provider.execute({...replacement,expectedRevision:2,document:foreignDocument}), /public_offering_catalog_invalid/)
  assert.deepEqual(await provider.execute({kind:'read'}),published)

  await provider.execute({kind:'save',expectedRevision:2,resources:[previous]})
  assert.deepEqual((await provider.execute({kind:'read'})).publishedOfferings,published.publishedOfferings)
  await provider.execute({...replacement,expectedRevision:3,document:{...document,data:[{...document.data[0],id:'replacement-device'}]}})
  assert.deepEqual((await provider.execute({kind:'read'})).publishedOfferings.map(offering=>offering.id),['replacement-device'])
})

test('publishes a reviewed Demo product batch as one write and preserves other public offerings',async()=>{
  const store=new TransactionalMemoryVaultRepository()
  const organizationReference=`Organization/${safe.demoOrganizationUuids.animalCare}`
  const publisher={id:organizationReference,name:'Demo animal provider'}
  const provider=new OrganizationCatalogVaultProvider({store,collection:'catalog-test',organizationReference,
    expiresAt:Date.now()+60_000,publication:{publisher,sector:'animal-care',demo:true}})
  const offer={id:'spain',seller:publisher,eligibleRegions:[{country:'ES',regions:[]}],deliveryCountries:[],supportCountries:[],operationCountries:[]}
  const resource=(id,type,name)=>({id,type,attributes:{name,category:'equipment',description:name,offers:[offer]}})
  const service=resource('support','Service','Local equipment support')
  const tracker=resource('tracker','Product','Initial tracker')
  const collar=resource('collar','Product','Reviewed collar')
  await provider.execute({kind:'replace-offering-catalogue',expectedRevision:0,document:{data:[service,tracker]}})
  const command={kind:'upsert-offering-batch',expectedRevision:1,document:{data:[{...tracker,attributes:{...tracker.attributes,name:'Reviewed tracker'}},collar]}}
  await assert.rejects(provider.execute({...command,document:{data:[tracker,service]}}),/catalog_offering_batch_mixed_types/)
  const receipt=await provider.execute(command)
  assert.equal(receipt.publicationCount,2)
  const saved=await provider.execute({kind:'read'})
  assert.deepEqual(saved.publishedOfferings.map(item=>item.id),['support','tracker'])
  assert.deepEqual(saved.reviewedOfferings.map(item=>[item.id,item.name]),[['tracker','Reviewed tracker'],['collar','Reviewed collar']])
  await assert.rejects(provider.execute(command),/catalog_revision_conflict/)

  const overlappingService=resource('tracker','Service','Support for tracker')
  const second=await provider.execute({kind:'upsert-offering-batch',expectedRevision:2,document:{data:[overlappingService]}})
  assert.deepEqual(second.reviewedOfferings.map(item=>[item.type,item.id]),[
    ['Product','tracker'],['Product','collar'],['Service','tracker'],
  ])
  const manualUpdate={resourceType:'Product',id:'tracker',meta:{claims:{'org.schema.Product.name':'Manual update'}}}
  const manual=await provider.execute({kind:'save',expectedRevision:3,resources:[manualUpdate]})
  assert.deepEqual(manual.reviewedOfferings.map(item=>[item.type,item.id]),[['Product','collar'],['Service','tracker']])
})

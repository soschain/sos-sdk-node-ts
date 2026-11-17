// Flow contract: authenticated public discovery uses one handler in every portal/mode; invalid filters fail before source access, location and NIF are never cached in HTTP responses, and upstream errors disclose no internal details.
import test from 'node:test'
import assert from 'node:assert/strict'
import {createPublicRegistryHttpHandler,reviewedRegistryCoordinates} from '../dist/public-registry-http.js'
test('authenticates before parsing and rejects invalid coordinates before searching',async()=>{
 let calls=0
 const search=async()=>{calls++;return {entries:[],total:0,unlocatedCount:0,nearbyAvailable:false}}
 const denied=createPublicRegistryHttpHandler({authorize:async()=>{throw new Error('denied')},search})
 assert.equal((await denied(new Request('https://example.invalid/api/clinic-directory'))).status,401)
 const handle=createPublicRegistryHttpHandler({authorize:async()=>{},search})
 const invalid=await handle(new Request('https://example.invalid/api/clinic-directory?latitude=91&longitude=0&radiusKm=1'))
 assert.equal(invalid.status,400);assert.equal(calls,0)
 const result=await handle(new Request('https://example.invalid/api/clinic-directory?municipality=Example'))
 assert.equal(result.status,200);assert.equal(calls,1);assert.match(result.headers.get('cache-control'),/no-store/)
 const unavailable=createPublicRegistryHttpHandler({authorize:async()=>{},search:async()=>{throw new Error('private details')}})
 const response=await unavailable(new Request('https://example.invalid/api/clinic-directory'))
 assert.equal(response.status,503);assert.equal((await response.text()).includes('private details'),false)
})
test('requires explicit reviewed coordinate metadata and validates every point',()=>{
 assert.equal(reviewedRegistryCoordinates(undefined),undefined)
 assert.throws(()=>reviewedRegistryCoordinates(JSON.stringify({coordinates:{EX:{latitude:40,longitude:-3}}})))
 const resolver=reviewedRegistryCoordinates(JSON.stringify({crs:'EPSG:4326',evidence:'https://example.invalid/review',coordinates:{EX:{latitude:40,longitude:-3}}}))
 assert.deepEqual(resolver('EX'),{latitude:40,longitude:-3});assert.equal(resolver('absent'),undefined)
 assert.throws(()=>reviewedRegistryCoordinates(JSON.stringify({crs:'EPSG:4326',evidence:'https://example.invalid/review',coordinates:{EX:{latitude:442175,longitude:4479466}}})))
})

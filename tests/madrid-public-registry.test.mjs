// Flow contract: the shared source reader serves real public clinic discovery in every access mode; no names, membership, contacts or coordinates are invented; exact NIF indexes are private and duplicate conflicts fail closed.
import test from 'node:test'
import assert from 'node:assert/strict'
import {normalizeMadridPublicRegistry,createMadridPublicRegistryReader} from '../dist/madrid-public-registry.js'
const row={centro_nro_registro:'EX-1',centro_tipo:'Clínica dental',oferta_asistecial:'Odontología/Estomatología',municipio_nombre:'Example municipality',direccion_vial_tipo:'CALLE',direccion_vial_nombre:'Example',direccion_vial_nro:'1',direccion_codigo_postal:'00000',NIF:'SYNTHETIC-IDENTIFIER',localizacion_coordenada_x:'442175',localizacion_coordenada_y:'4479466'}
const checkedAt='2026-11-17T00:00:00Z'
test('groups care units; indexes NIF privately and retains provenance without inventing GPS or names',()=>{
 const snapshot=normalizeMadridPublicRegistry({data:[row,{...row,oferta_asistecial:'U.44'}]},checkedAt,'digest')
 assert.equal(snapshot.entries.length,1)
 assert.equal(snapshot.entries[0].geo,undefined)
 assert.equal(snapshot.entries[0].name,undefined)
 assert.equal(snapshot.entries[0].source.hash,'digest')
 assert.equal(JSON.stringify(snapshot.entries).includes(row.NIF),false)
 assert.deepEqual([...snapshot.identifiers.get(row.NIF)],['ES-MD:EX-1'])
 assert.throws(()=>normalizeMadridPublicRegistry({data:[row,{...row,NIF:'CONFLICT'}]},checkedAt),/conflict/)
 assert.throws(()=>normalizeMadridPublicRegistry({data:[row,{...row,direccion_vial_nro:'2'}]},checkedAt),/conflict/)
})
test('accepts only an explicit reviewed coordinate resolver',()=>{
 const snapshot=normalizeMadridPublicRegistry({data:[row]},checkedAt,undefined,()=>({latitude:40,longitude:-3}))
 assert.deepEqual(snapshot.entries[0].geo,{latitude:40,longitude:-3})
 assert.throws(()=>normalizeMadridPublicRegistry({data:[row]},checkedAt,undefined,()=>({latitude:442175,longitude:4479466})),/coordinates/)
})
test('coalesces downloads, reuses bounded source cache, searches NIF and does not cache a failure',async()=>{
 let calls=0
 const reader=createMadridPublicRegistryReader({fetchImpl:async()=>{calls++;return new Response(JSON.stringify({data:[row]}))}})
 const [a,b]=await Promise.all([reader({identifier:row.NIF}),reader({address:'Example'})])
 assert.equal(calls,1);assert.equal(a.total,1);assert.equal(b.total,1)
 await reader({municipality:'example'});assert.equal(calls,1)
 assert.equal(JSON.stringify(a).includes(row.NIF),false)
 await assert.rejects(reader({near:{latitude:40,longitude:-3,radiusKm:5}}),/coordinates_unavailable/)
 let failures=0
 const retry=createMadridPublicRegistryReader({fetchImpl:async()=>++failures===1?new Response('',{status:503}):new Response(JSON.stringify({data:[row]}))})
 await assert.rejects(retry({}));assert.equal((await retry({})).total,1)
})

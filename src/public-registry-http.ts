import {parsePublicRegistryQuery,distanceKm,type PublicRegistryQuery,type PublicRegistrySearchResult,type GeographicPoint} from 'antifraud-data-utils-ts/public-registry-search'
import type {RegistryCoordinateResolver} from './madrid-public-registry.js'

/** Public read-only evidence: it conveys no subject access, membership, activation or service capability. */
export function createPublicRegistryHttpHandler(options:Readonly<{
  authorize:(request:Request)=>Promise<unknown>
  search:(query:PublicRegistryQuery)=>Promise<PublicRegistrySearchResult>
}>){
  return async(request:Request):Promise<Response>=>{
    const respond=(body:unknown,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'private, no-store','Referrer-Policy':'no-referrer'}})
    try{await options.authorize(request)}catch{return respond({error:'registry_sign_in_required'},401)}
    let query:PublicRegistryQuery
    try{query=parsePublicRegistryQuery(new URL(request.url).searchParams)}catch{return respond({error:'registry_query_invalid'},400)}
    try{return respond(await options.search(query))}
    catch(error){return respond({error:error instanceof Error&&error.message==='registry_coordinates_unavailable'?'registry_coordinates_unavailable':'registry_source_unavailable'},503)}
  }
}

/** Optional deployment-owned reviewed WGS84 enrichment; absent evidence never enables guessed coordinates. */
export function reviewedRegistryCoordinates(value:string|undefined):RegistryCoordinateResolver|undefined {
  if(!value)return undefined
  if(value.length>2_000_000)throw new TypeError('registry_coordinate_configuration_too_large')
  const input=JSON.parse(value) as {crs?:string;evidence?:string;coordinates?:Record<string,GeographicPoint>}
  if(input.crs!=='EPSG:4326'||!input.evidence?.startsWith('https://')||!input.coordinates||typeof input.coordinates!=='object'||Array.isArray(input.coordinates))throw new TypeError('registry_coordinate_review_required')
  const points=new Map<string,GeographicPoint>()
  for(const [id,point] of Object.entries(input.coordinates)){
    if(!/^[A-Za-z0-9._-]{1,80}$/u.test(id))throw new TypeError('registry_coordinate_registration_invalid')
    distanceKm(point,point);points.set(id,Object.freeze({latitude:point.latitude,longitude:point.longitude}))
  }
  return id=>points.get(id)
}

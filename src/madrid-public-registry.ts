import {createHash} from 'node:crypto'
import {distanceKm,searchPublicRegistry,type PublicRegistryEntry,type PublicRegistryQuery,type GeographicPoint} from 'antifraud-data-utils-ts/public-registry-search'

export const MADRID_PUBLIC_REGISTRY_URL='https://datos.comunidad.madrid/dataset/d8a0a444-adf5-4c04-8999-0eac3de52cb7/resource/94090084-2276-4a07-87b4-cd028ea6b46d/download/centros_servicios_establecimientos_sanitarios.json'
const SOURCE_PAGE='https://datos.comunidad.madrid/dataset/centros_servicios_establecimientos_sanitarios'
const MAX_BYTES=64*1024*1024
type Snapshot=Readonly<{entries:readonly PublicRegistryEntry[];identifiers:ReadonlyMap<string,ReadonlySet<string>>}>
/** Reviewed enrichment must be keyed to a registration, never guessed from an address or unlabelled X/Y. */
export type RegistryCoordinateResolver=(registrationNumber:string)=>GeographicPoint|undefined

export function normalizeMadridPublicRegistry(payload:unknown,checkedAt:string,hash?:string,coordinates?:RegistryCoordinateResolver):Snapshot {
  const rows=(payload as {data?:unknown})?.data
  if(!Array.isArray(rows)||!rows.length||rows.length>150_000||!Number.isFinite(Date.parse(checkedAt)))throw new TypeError('registry_source_schema_invalid')
  const records=new Map<string,PublicRegistryEntry>(),identifiers=new Map<string,Set<string>>(),nifs=new Map<string,string>()
  for(const raw of rows){
    if(!raw||typeof raw!=='object')throw new TypeError('registry_source_row_invalid')
    const row=raw as Record<string,unknown>,registrationNumber=text(row.centro_nro_registro),type=text(row.centro_tipo),unit=text(row.oferta_asistecial)
    if(!registrationNumber||!type)throw new TypeError('registry_source_row_invalid')
    if(!/(?:^|[^\d.])C\.2\.5\.1(?:$|[^\d.])/iu.test(type)&&!/(?:^|[^\d.])U\.44(?:$|[^\d.])/iu.test(unit)&&!/clinica(?:s)? dental(?:es)?/u.test(fold(type))&&!/odontologia|estomatologia/u.test(fold(unit)))continue
    if(!/^[A-Za-z0-9._-]{1,80}$/u.test(registrationNumber))throw new TypeError('registry_source_registration_invalid')
    const id=`ES-MD:${registrationNumber}`,nif=text(row.NIF).toUpperCase(),geo=coordinates?.(registrationNumber)
    if(geo)distanceKm(geo,geo)
    const entry:PublicRegistryEntry={id,registrationNumber,
      address:[row.direccion_vial_tipo,row.direccion_vial_nombre,row.direccion_vial_nro,row.direccion_informacon_adicional].map(text).filter(Boolean).join(' '),
      municipality:text(row.municipio_nombre),postalCode:text(row.direccion_codigo_postal),classification:'Odontología/Estomatología',
      source:{authority:'Comunidad de Madrid',url:SOURCE_PAGE,checkedAt,...(hash?{hash}:{})},...(geo?{geo:{...geo}}:{})}
    const previous=records.get(id)
    if(previous&&(JSON.stringify(previous)!==JSON.stringify(entry)||nifs.get(id)!==nif))throw new TypeError('registry_source_conflict')
    records.set(id,entry);nifs.set(id,nif)
    if(nif){if(!identifiers.has(nif))identifiers.set(nif,new Set());identifiers.get(nif)!.add(id)}
  }
  if(!records.size)throw new TypeError('registry_source_empty')
  return {entries:[...records.values()],identifiers}
}

/** Shared by BFF composition roots in all modes. Caches only the public source, never a user's query/location. */
export function createMadridPublicRegistryReader(options:Readonly<{fetchImpl?:typeof fetch;coordinates?:RegistryCoordinateResolver;now?:()=>number}>={}){
  let cached:Snapshot|undefined,expiresAt=0,inflight:Promise<Snapshot>|undefined
  const now=options.now??Date.now
  async function download():Promise<Snapshot>{
    const response=await (options.fetchImpl??fetch)(MADRID_PUBLIC_REGISTRY_URL,{headers:{Accept:'application/json'},redirect:'error',signal:AbortSignal.timeout(12_000),cache:'no-store'})
    if(!response.ok)throw new Error('registry_source_unavailable')
    if(Number(response.headers.get('content-length'))>MAX_BYTES)throw new Error('registry_source_too_large')
    const reader=response.body?.getReader();if(!reader)throw new Error('registry_source_empty')
    const chunks:Uint8Array[]=[];let size=0
    try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>MAX_BYTES)throw new Error('registry_source_too_large');chunks.push(value)}}finally{await reader.cancel().catch(()=>{})}
    const body=Buffer.concat(chunks)
    return normalizeMadridPublicRegistry(JSON.parse(body.toString('utf8').replace(/^\uFEFF/u,'')),new Date(now()).toISOString(),createHash('sha256').update(body).digest('hex'),options.coordinates)
  }
  return async(query:PublicRegistryQuery)=>{
    // Validate untrusted input before starting an upstream request.
    if(query.near){distanceKm(query.near,query.near);if(!Number.isFinite(query.near.radiusKm)||query.near.radiusKm<=0||query.near.radiusKm>200)throw new TypeError('registry_radius_invalid')}
    if(!cached||now()>=expiresAt){
      inflight??=download().then(snapshot=>{cached=snapshot;expiresAt=now()+86_400_000;return snapshot}).finally(()=>{inflight=undefined})
      await inflight
    }
    return searchPublicRegistry(cached!.entries,query,cached!.identifiers)
  }
}
function text(value:unknown):string{return typeof value==='string'?value.trim():typeof value==='number'?String(value):''}
function fold(value:string){return value.normalize('NFD').replace(/\p{M}/gu,'').toLowerCase()}

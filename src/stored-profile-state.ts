type Row=Record<string,unknown>
/** Internal parsing failure; no public custody handle or policy callback. */
export class StoredProfileStateInvalidError extends Error{
 constructor(){super('stored_profile_signing_binding_denied')}
}
const denied=()=>new StoredProfileStateInvalidError()
export function text(value:unknown,maximum=4096):string{
 if(typeof value!=='string'||!value||value.trim()!==value||value.length>maximum||value.includes('\0'))throw denied()
 return value
}
export function own(value:unknown):Row{
 if(!value||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value))||Object.getOwnPropertySymbols(value).length)throw denied()
 const result:Row=Object.create(null)
 for(const[name,entry]of Object.entries(Object.getOwnPropertyDescriptors(value))){if(!('value'in entry))throw denied();result[name]=entry.value}
 return result
}
export function json(value:unknown,seen=new Set<object>()):unknown{
 if(value===null||typeof value==='string'||typeof value==='boolean')return value
 if(typeof value==='number'&&Number.isFinite(value))return value
 if(!value||typeof value!=='object'||seen.has(value))throw denied()
 seen.add(value)
 try{
  if(Array.isArray(value)){
   if(Object.getPrototypeOf(value)!==Array.prototype)throw denied()
   const fields=Object.getOwnPropertyDescriptors(value),out:unknown[]=[]
   for(let index=0;index<value.length;index++){const field=fields[String(index)];if(!field||!('value'in field))throw denied();out.push(json(field.value,seen))}
   return out
  }
  const result:Row=Object.create(null)
  for(const[name,entry]of Object.entries(own(value)))result[name]=json(entry,seen)
  return result
 }finally{seen.delete(value)}
}
export function pick(value:Row,names:readonly string[]):Row{
 const result:Row=Object.create(null)
 for(const name of names)if(value[name]!==undefined)result[name]=json(value[name])
 return result
}
export function fingerprint(value:unknown):string{
 if(Array.isArray(value))return `[${value.map(fingerprint).join(',')}]`
 if(value&&typeof value==='object')return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${fingerprint((value as Row)[key])}`).join(',')}}`
 return JSON.stringify(value)
}
export function revision(value:unknown):number{
 if(value===undefined)return 0
 if(typeof value!=='number'||!Number.isSafeInteger(value)||value<0)throw denied()
 return value
}
export const profileFields=['id','profileId','ownerId','actorKind','actorMode','actorDid','profileDid','providerDid','routeContext','allowedSubjectDids','clientId','clientInstanceId','deviceDid','publicJwks','storagePublicJwk','confidentialStorageProfile','walletKeyDerivationId','protectedWalletSeed','protectedVpToken','failedUnlocks','lockedUntil','createdAt','updatedAt','attester','clinicalCreatorBinding','tenantIssuer','credentialRevision'] as const
export const sessionFields=['id','sessionId','ownerId','profileId','subjectDid','selectedSubjectDid','scopes','authorizedSubjectDids','authorizedSubjects','actorMode','attester','sealedUnlockedWalletSeed','sealedUnlockedVpToken','sealedAccessToken','sealedWalletSeed','expiresAt','credentialRevision'] as const

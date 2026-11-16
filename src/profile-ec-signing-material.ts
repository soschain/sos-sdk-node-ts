import {createECDH,createHash,createPrivateKey,type KeyObject} from 'node:crypto'

type PublicKey=Readonly<Record<string,unknown>>
/** Internal Node adapter for the already-owned ES384 derivation transcript. */
export function deriveProfileEcSigningMaterial(seed:string,owner:string,purpose:'actor-signing'|'openid-id-token-signing'|'vp-token-signing'):{publicJwk:PublicKey;key:KeyObject}{
 const namespace=`${owner}:${purpose}`,material=`${seed}:${namespace}`
 for(let attempt=0;attempt<256;attempt++){
  const scalar=createHash('sha512').update(`${material}:${namespace}:${attempt}:0`,'utf8').digest().subarray(0,48)
  const curve=createECDH('secp384r1')
  try{curve.setPrivateKey(scalar)}catch{scalar.fill(0);continue}
  const encoded=curve.getPublicKey(undefined,'uncompressed'),privateBytes=curve.getPrivateKey()
  try{
   const x=encoded.subarray(1,49).toString('base64url'),y=encoded.subarray(49,97).toString('base64url')
   const canonical=JSON.stringify({crv:'P-384',kty:'EC',x,y})
   const kid=`urn:ietf:params:oauth:jwk-thumbprint:sha-256:${createHash('sha256').update(canonical,'utf8').digest('base64url')}`
   const publicJwk=Object.freeze({kty:'EC',crv:'P-384',alg:'ES384',use:'sig',kid,x,y})
   return {publicJwk,key:createPrivateKey({key:{...publicJwk,d:privateBytes.toString('base64url')},format:'jwk'})}
  }finally{scalar.fill(0);privateBytes.fill(0)}
 }
 throw new Error('server_profile_ec_derivation_failed')
}

import {decodeSoschainSmartHealthCardQr} from 'sos-data-utils-ts/clinical-document-shc'

const maxInput=128*1024
function record(value:unknown):value is Record<string,unknown>{return value!==null&&typeof value==='object'&&!Array.isArray(value)}

/** Internal transport normalization only: no issuer trust or signature claim. */
export function clinicalDocumentCompactInput(input:string|readonly string[],invalid:()=>never):string{
 let compact:string
 if(Array.isArray(input)){
  if(!input.length||input.length>100||input.some(value=>typeof value!=='string')||input.reduce((length,value)=>length+value.length,0)>maxInput)return invalid()
  try{compact=decodeSoschainSmartHealthCardQr(input)}catch{return invalid()}
 }else{
  if(typeof input!=='string'||Buffer.byteLength(input)>maxInput)return invalid()
  if(input.startsWith('shc:/')){try{compact=decodeSoschainSmartHealthCardQr([input])}catch{return invalid()}}
  else if(input.startsWith('{')){
   let wrapper:unknown;try{wrapper=JSON.parse(input)}catch{return invalid()}
   if(!record(wrapper)||!Array.isArray(wrapper.verifiableCredential)||wrapper.verifiableCredential.length!==1||typeof wrapper.verifiableCredential[0]!=='string'||wrapper.verifiableCredential[0].startsWith('{'))return invalid()
   return clinicalDocumentCompactInput(wrapper.verifiableCredential[0],invalid)
  }else compact=input
 }
 if(Buffer.byteLength(compact)>maxInput)return invalid()
 return compact
}

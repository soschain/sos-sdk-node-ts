import type {WorkforceClient} from 'sos-sdk-node-ts/workforce-client'
import type {LicenseListSummary,OrganizationEmployeeLifecycleRecord} from 'sos-data-utils-ts/employee-routing'
import type {OrganizationLifecycleSnapshot,OrganizationPurgeReceipt} from 'sos-data-utils-ts/organization-lifecycle-contract'
export async function inspect(client:WorkforceClient){
 const inventory=await client.getAdministration()
 const summary:LicenseListSummary=inventory.licenses
 const employees:OrganizationEmployeeLifecycleRecord[]=inventory.employees
 for(const employee of employees){
  const occupation:string|undefined=employee.occupationResourceId
  if(employee.contactKind==='phone'){
   const telephone:string=employee.telephone
   // @ts-expect-error Phone inventory does not invent an email string.
   const email:string=employee.email
   void [telephone,email]
  }
  void occupation
 }
 const quote=await client.requestEmployeeLicenseOffer({quantity:1})
 const amount:string|number=quote.offer.price
 const currency:string=quote.offer.priceCurrency
 const quantity:number=quote.offer.quantity
 const lifecycle=await client.organizationLifecycle({action:'status'})
 if(lifecycle.action==='purge'){
  const receipt:OrganizationPurgeReceipt=lifecycle.purgeReceipt
  void receipt
 }else{
  const snapshot:OrganizationLifecycleSnapshot=lifecycle.snapshot
  void snapshot
 }
 return {summary,amount,currency,quantity}
}

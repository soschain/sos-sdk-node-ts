// Flow contract: the public Node purpose port extends existing Core input without accepting an arbitrary Encounter shape.
import type {PortalCareVaultProvider,PortalEmergencyRequestInput,PortalCareStoredResource,PortalCareOperation} from 'sos-sdk-node-ts/portal-care-vault';
import type {EmergencyRequestInput} from 'sos-sdk-core-ts/care-emergency-alert-orchestration';
import type {FlatClaimResourceEntry} from 'fhir-data-utils-ts/flat-claim-resource-graph';
export async function submit(provider:PortalCareVaultProvider,input:EmergencyRequestInput,planned:FlatClaimResourceEntry){
 const request:PortalEmergencyRequestInput={...input,plannedEncounter:planned};
 const operation:PortalCareOperation={kind:'emergency',request};
 const resources:readonly PortalCareStoredResource[]=await provider.requestEmergency(operation.request);
 // @ts-expect-error A clinical resource entry cannot be replaced by an arbitrary string.
 const invalid:PortalEmergencyRequestInput={...input,plannedEncounter:'Encounter/one'};
 // @ts-expect-error The actual request retains the required Core intake.
 const missing:PortalEmergencyRequestInput={plannedEncounter:planned};
 void invalid;void missing;return resources;
}

# Organization registration source evaluation

The shared SOS Node SDK evaluated the existing clinical organization
registration runtime capability-by-capability. It did not copy a portal,
product policy or deployment configuration.

The current implementation uses SOS-owned verification/request contracts,
an owned encrypted HTTP submit/poll client and an owned communication wallet
backed by the independent Antifraud cryptography engine. Frozen packages serve
only as read-only compatibility evidence, not as runtime or test dependencies.
The reconstructed communication key material and key identifiers match that
evidence. Profile/identity signing keys remain supplied by the owning workflow;
the transport wallet creates only its scoped communication keys.

| Capability | Decision | Shared boundary |
| --- | --- | --- |
| deterministic controller bootstrap-wallet reconstruction | adopted | trusted Node SDK |
| encrypted DIDComm form transport to SOS Gateway | adopted | trusted Node SDK |
| organization verification and credential reissuance submission | adopted | trusted Node SDK |
| exact accepted Offer continuation through Order | adopted | trusted Node SDK |
| terminal nested `OperationOutcome` rejection | adopted | trusted Node SDK |
| host DID document route and recipient key resolution | adopted | trusted Node SDK |
| host organization search and lifecycle | already equivalent | existing host-directory client |
| application form, localization and product branding | rejected | hosting/controller presentation |
| sector and jurisdiction admission policy | rejected | trusted portal BFF and ICA |
| application, PIN and controller-profile persistence | rejected | trusted portal BFF |
| user authentication and account recovery | rejected | portal identity boundary |
| payment adapter and commercial policy | rejected | marketplace and billing boundary |
| professional groups, subjects, services, studies and scheduling | rejected | delegated professional workflows |
| tenant, host, network, credentials and deployment values | rejected | private deployment configuration |

This extraction is a transport prerequisite, not proof of an organization
onboarding journey. A consumer still has to prove application submission,
review, verification, Offer, Order, activation, device registration and
authoritative readback through its real BFF and Gateway environment.

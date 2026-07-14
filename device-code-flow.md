# Device Code Flow, Device Identity Abuse, and the Conditional Access Gap
I came across the Cyderes Howler Cell red team writeup on Entra device identity abuse, and pretty much right after the Forg365 PhaaS article showing the same device code flow getting weaponized in the wild. Reading them back to back, it's the same trick on both sides of the fence  a red team walking a blocked credential all the way to Global Admin, and a criminal subscription service selling the phishing version of it. So let's break down both chains, why Conditional Access keeps missing them, and how to actually shut the door.

## Quick background: what device code flow even is
Device code flow is the OAuth 2.0 Device Authorization Grant (RFC 8628). It exists so you can sign in on something that can't really do a browser login — smart TVs, printers, IoT gear, CLI tools, conference-room / Teams devices. The device shows a short code, you punch that code into a browser on your phone or laptop, and MFA happens there.

That "go authenticate somewhere else" split is the whole problem. Nothing ties the code to the person who asked for it. So if an attacker kicks off the flow and gets *you* to enter the code, congratulations — you just authorized *their* session. It's authorization abuse, not credential theft, which is exactly why resetting the password afterward does nothing.

It also runs on Microsoft first-party public client IDs (like the Azure CLI client `04b07795-8ddb-461a-bbee-02f9e1bf7b46`), so there's no app registration and no client secret needed to fire it off.

![Device code prompt from az login](images/01-device-code-.png)


## Why a Linux box can pass as a "trusted" device
Both chains lean on the same weak spot: the trust model behind device registration and Primary Refresh Tokens.

**Device registration is basically a software transaction.** Joining a device to Entra means generating an RSA keypair locally, sending a Certificate Signing Request to the Device Registration Service (DRS) with a valid user token, and getting a signed device cert back. That's the whole thing. The assumption is that only real, IT-managed machines go through this — but **DRS checks the token, not the caller.** It never confirms you're a real Windows machine.
**Nobody's enforcing hardware attestation** By default, Entra doesn't require the device key to live in a TPM or prove it with attestation. This isn't some "Linux dodges the TPM requirement" trick — there's no TPM requirement to dodge. Windows *uses* a TPM when there's one available, but registration happily falls back to a software key when there isn't, and nothing tenant-side forces the issue. So the attacker just uses a **device with no TPM**, keeps the private key in software, and walks away with a cert that's cryptographically indistinguishable from a real corporate endpoint's. Linux makes the story vivid, but the attacker's own Windows box with a software key works just as well.
**That device identity is your ticket to a PRT.** Once registered, the "device" can request a **Primary Refresh Token** — the long-lived token that carries device claims and drives SSO across Microsoft. And here's the kicker: the PRT can carry **joined/compliant device claims that satisfy the exact Conditional Access conditions** meant to keep unmanaged devices out. You're literally forging the trust signal the policy was looking for.


### So why does the TPM actually matter here?
The PRT isn't just a bare token. When a device registers it gets a couple of asymmetric keys, and when the PRT is issued Entra also hands over a session key  a proof of possession key that has to sign every request made with the PRT (the nonce-signing / PRT-cookie dance). The PRT is only useful to whoever can actually use that session key, and that's the hinge the TPM sits on. It protects the PRT in **two different directions**:

**Forgery** A TPM lets a device *prove* its key is hardware-backed (attestation). If the tenant requires that proof before issuing a PRT, the attacker's software-key device can't produce it and never gets a trusted PRT. But since attestation isn't required by default, the fake device sails through and grabs a valid PRT with compliance claims baked in. This is the exact gap Cyderes and Forg365 exploit — they're not stealing a real device's PRT, they're *building* a device and asking for a brand-new one.
**Theft / replay.** On a box with a TPM the transport and session keys are generated in hardware and are non-exportable an attacker sitting on that machine can ask the TPM to sign while they're there, but they can't lift the PRT and its session key and replay them from their own laptop. Without a TPM, those keys live in software (DPAPI-protected on Windows, but pullable with enough access), so tooling like ROADtools or Mimikatz can grab the PRT + session key and replay them anywhere. And since a PRT is the master SSO credential — it mints tokens for any app and carries MFA and device-compliance claims — that's basically full session takeover that shrugs off a password reset until someone actually revokes the session.

So the TPM binds the PRT to real hardware in both directions: with attestation on, a fake device can never get a PRT, and a real device's PRT can't be ripped out and replayed elsewhere.

**The fix** is to flip the default: require TPM 2.0 attestation before a PRT gets issued and validate device health externally ( instead of trusting self-reported compliance — so a software-key device with no TPM can't produce or export a trusted PRT anymore. To be straight about it, this raises the bar a lot but isn't a silver bullet on its own; it's one control sitting alongside blocking device code flow, phishing-resistant MFA, and token-theft detection. What it specifically kills is the "software-key device mints a PRT" move.


## Attack chain 1 — Device identity abuse to Global Admin (Cyderes Howler Cell)

An authorized red team engagement against a production tenant. The starting point: a single valid credential that Conditional Access had already blocked (`AADSTS53003`). That should've been game over. It wasn't.

**The chain:**
 **Front door's locked.** Normal sign-in with the valid credential gets blocked by CA requiring a compliant/hybrid-joined device. ROPC is blocked too.
 **Find the door nobody guarded.** CA can target auth flows individually. Device code flow — which hits the Device Registration Service (DRS) instead of the standard token endpoint — wasn't covered by an enforced policy. Auth succeeds down that path. *(MITRE ATT&CK T1556.009 – Modify Authentication Process: Conditional Access Policies.)*
 **Register a phantom device.** DRS validates the token but doesn't bother checking that the caller is a real Windows machine. Using public tooling (`roadtx` from Dirk-Jan Mollema's roadtools), the team generates a keypair, sends a CSR to DRS, and gets a signed Azure AD device cert — a fully registered device identity from a Linux box. No TPM, no hardware, no admin approval. *(T1098.005 – Account Manipulation: Device Registration.)*
 **Mint a PRT with fake claims.** The registered "device" is now trusted enough to request a **Primary Refresh Token** carrying the device claims that satisfy the very compliance conditions that blocked step 1.
 **Escalate through hybrid identity.** Separate from the device spoofing, the tenant had a pile of on-prem accounts synced to the cloud holding privileged roles, including Global Admin (the writeup counts 255 highly privileged directory roles). Pop one synced on-prem privileged account and you can reset cloud Global Admin passwords — full tenant takeover, no cloud-specific exploit required.

**Where it ends:** Global Administrator, no malware, no corporate endpoint touched. The bug isn't in any one component it's the trust chain between device registration and identity services.


## Attack chain 2 — Device code phishing as a service (Forg365)
Forg365 is a phishing-as-a-service platform — Telegram-distributed, ~$400/month or $3,800/year, documented by ZeroBEC. It's a Kali365-class kit with Sneaky 2FA-style AiTM overlap, and it basically productizes the criminal version of the same flow.

**The chain:**

 **Lure.** A business-document / remittance-approval email, delivered through legit infrastructure (Amazon SES for sending, SendGrid-hosted tracking content) so it blends into normal SaaS mail traffic.
 **Redirect + cloaking.** The redirect chain runs you through an AntiBot layer (AES-encrypted SVG redirectors, sandbox/VM/debugger checks). VPN or low-trust traffic gets punted to a harmless decoy (a SpaceX page, in the observed case) to throw off automated analysis.
 **Device-auth branch.** The victim hits a Microsoft-styled verification code page and gets nudged into the real Microsoft Authentication Broker sign-in. They're looking at genuine Microsoft surfaces, they complete MFA, they enter the code — and they've just authorized an attacker-controlled session. The attacker never touches the password.
 **Token vaulting.** Captured tokens drop into the operator panel's Token Vault.
 **Device registration.** The campaign backend (a Kyiv-hosted node in the observed case) ran Microsoft Graph and device-registration activity — spinning up Entra joined devices with `Forg365-` prefixed names. Same DRS pattern as chain 1.
 **Persistence via ForgCookie.** A Manifest V3 browser extension (`ForgCookie`, v1.0.21) that runs in the operator's browser. It targets the `x-ms-RefreshTokenCredential` cookie on `login.microsoftonline.com` and drives a silent `prompt=none` refresh loop through `substrate.office.com`, keeping the session alive and **surviving password resets** by replaying refresh-token material.
 **Post-compromise.** Account Intel, Keyword Listener mailbox keyword alerts, Viewer Links expiring read-only mailbox shares— a full BEC operation, not a smash-and-grab.

One telemetry detail worth flagging: the device-code branch showed up from a Comcast/Xfinity residential IP, not an obvious cloud VPS  a deliberate way to duck reputation-based blocking.


## The common thread
Both chains ride on the same two facts:

- Device code flow reaches DRS and is frequently not covered by an enforced CA policy.
- DRS trusts the token but not the caller, so a Linux box can register as a "device" and pull a PRT.
                              

## Legitimate use — why you can't just nuke it
Device code flow is a real, needed thing: input constrained hardware (smart TVs, printers, IoT), headless/CLI tooling (`az login --use-device-code`), SDKs, and Teams room devices, which need it for initial provisioning and some reauth scenarios. So the play is scoping, not a global kill switch — though the posture Microsoft actually recommends is to get as close to a full block as your environment will let you.


## The fix — Conditional Access, done right
Microsoft classifies device code flow as a high-risk auth method and recommends blocking it wherever you can. The control lives in the Authentication flows condition.

**What the policy should look like:**
**Users:** All users (exclude your break-glass / emergency access accounts and any genuine service accounts).
**Target resources:** **All resources.** This is the part people get wrong — since early September 2024, Microsoft only enforces authentication-flows policies against DRS when the policy targets all resources in the resource picker**. Scope it to specific apps and DRS is left wide open, which is precisely the door chain 1 strolled through.
**Conditions > Authentication Flows:** Configure = Yes -> Device code flow.
**Grant:** **Block access.**
**Enable:** Start in **Report-only**, sanity-check with sign-in logs / the What-If tool, then flip it to On.

**The Report-only trap.** In the Cyderes engagement, the tenant *had* policies to block device code flow and require MFA for device registration  they were just left in Report-only. So they dutifully logged every malicious step and blocked exactly none of it. Logging an attack isn't stopping an attack.

**Scoped exceptions.** For the legit stuff (Teams room devices, say), block everywhere and grant a persistent, account-scoped exception  just know the exception is account-wide, not scenario-specific. If DRS itself has to be reachable for a scenario its client ID is `01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9` for explicit include/exclude handling.

**Then verify it.** CISA's SCuBA project added an Entra baseline policy and a ScubaGear check specifically for blocking device-code phishing. 

## Detection & hunting
Entra sign-in logs are where this all shows up. Signals worth watching:

`originalTransferMethod = deviceCodeFlow` — filter for it, especially paired with a device registration right after. That combo is the core Storm-2372 / Forg365 tell.
**Microsoft Authentication Broker** sign-ins followed by device registration.
**Non-interactive Graph activity** from an IP that has nothing to do with the user; node-style / `node-fetch` user agents.
New device objects with sketchy naming (e.g. `Forg365-*` — kit-specific, cheap to check right now).
Sessions that survive a password reset — a strong hint refresh-token material is being replayed. Fix it by revoking sessions and refresh tokens  at the identity layer, not endpoint-side.
Post-event mailbox artifacts: inbox rules, forwarding, new OAuth grants, viewer links.


## Sources
Cyderes / Howler Cell — *One Password, No Device, Full Tenant: Dismantling Azure AD Conditional Access Through Device Identity Abuse* — https://www.cyderes.com/howler-cell/azure-ad-conditional-access-device-identity-abuse
The Hacker News — *Forg365 PhaaS Targets Microsoft 365 with Device Code and AitM Session Theft* — https://thehackernews.com/2026/07/forg365-phaas-targets-microsoft-365.html
ZeroBEC — *Inside Forg365: A Telegram-Distributed Sneaky 2FA-Style PhaaS Targeting Microsoft 365* — https://zerobec.com/blog/inside-forg365-telegram-distributed-sneaky2fa-style-phaas
Microsoft Learn — *Authentication flows as a condition in Conditional Access* — https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows
Microsoft Learn — *Block authentication flows with Conditional Access policy* — https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows
CISA — *Secure Cloud Business Applications (SCuBA) / M365 Entra ID baseline* — https://www.cisa.gov/resources-tools/services/m365-entra-id

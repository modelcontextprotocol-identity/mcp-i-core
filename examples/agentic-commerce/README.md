# From agent-visible to agent-actionable

**A shopping agent reads what a merchant accepts, presents a delegation scoped to one GS1 Digital Link product class, and is revoked mid-session by its Responsible Party. Every verdict is produced by the published `@kya-os/mcp` verifier. Nothing is mocked.**

Built for the W3C/GS1 workshop *E-Commerce for Humans and AI Agents* (Zurich, September 2026) as the live demonstration behind the position statement of the same name. It is the [REVOKED](../revoked/) example — the DEF CON 34 on-chain kill switch — re-shaped for a room of retailers: a merchant checkout instead of a wallet, a `did:web` Responsible Party instead of a chain, a GS1 Digital Link instead of a token symbol, and a hub-hosted StatusList2021 the merchant verifies on every call.

> An offer an agent can find but cannot safely act on is a listing, not a sale. The trust layer is what makes an offer *actionable*: proof of who is calling, under whose authority, for exactly what, up to how much, until when — and a way to take that authority back.

## The cast

| Party | Identity | Holds | Runs |
|---|---|---|---|
| **Responsible Party** — the shopper's own hub | `did:web` | the issuing key, the revocation list, the authenticator ceremony | `:4950` |
| **Merchant edge** — the verifier, the seller | `did:key` | the receipt-signing key, the discovery document, the catalog | `:4949` |
| **Shopping agent** — the thing being governed | `did:key` | its own request-signing key and the delegation | a real MCP client (Claude Desktop through a gateway, or the console's simulated agent) |

Three processes worth of separation in one `npm run demo`: the merchant trusts the Responsible Party's **signature**, resolved through its DID, not the hub and not this page.

## Try it in 90 seconds

```bash
cd examples/agentic-commerce
npm install
npm run setup          # keys for all three parties, the RP's did.json, the all-clear list, the first grant
npm run demo           # RP hub on :4950, merchant edge on :4949
open http://localhost:4949/
```

Then, on the console, press the number keys in order: `0` discover · `1` order · `2` wrong product · `3` over cap · `5` stolen credential · `K` revoke · `4` try again · `V` re-verify the receipt in Python · `R` reset. `P` is presenter mode, `C` high contrast.

The same beats from a terminal, if you prefer to read JSON:

```bash
npm run agent -- discover
npm run agent -- order --product risotto --quantity 2      # ALLOWED, CHF 39.80, signed receipt
npm run agent -- order --product risotto-lot               # ALLOWED — a lot beneath the class is in scope
npm run agent -- order --product olive-oil                 # DENIED · PRODUCT_OUT_OF_SCOPE
npm run agent -- order --product risotto --quantity 5      # DENIED · SPEND_CAP_EXCEEDED (CHF 99.50 > 50.00)
npm run agent -- order --product risotto --forge           # DENIED · holder_binding_failed (right credential, wrong key)
npm run revoke -- --index 94                               # the Responsible Party flips one bit and re-signs
npm run agent -- order --product risotto                   # DENIED · Credential revoked via StatusList2021
```


## What each beat proves

**0 · Discover.** The agent fetches the merchant's `/.well-known/mcp` before presenting anything: the merchant's DID (the audience the proof will be bound to), its proof algorithms and DID methods, its clock-skew tolerance, and — the block this example proposes for the publisher-side agent surface — `acceptedTrustSchemes`: which authority schemes it verifies, whether holder binding is required, how revocation is checked and what happens when the list is unreachable. Everything declared there is what the verifier enforces.

**1 · Authorized order.** The agent calls `place_order` with its W3C Delegation Credential and a per-request holder proof signed by its own key. The shipped gate verifies, in this order: the credential's signature against the Responsible Party's resolved DID document, its validity window and audience, its **revocation status** (the RP's list is fetched and its signature verified on this call), the **holder key** (the caller holds the subject's key), and the flat scope. The merchant handler then reads two things out of the same credential: the **product class** — `scopeSatisfies(productUri, credential)` with the credential's own `prefix` matcher on the GS1 Digital Link — and the **cap**. The response carries a detached-JWS receipt signed by the merchant: an evidence record any party can verify.

**2 · Wrong noun.** Another GTIN, refused by the scope matcher. The authorization is written in the Digital Link grammar: the class URI is the grant; `/10/<lot>` and `/21/<serial>` beneath it match for free; anything else does not.

**3 · Over the cap.** The cap lives in the signed credential; the merchant enforces it. The trust layer never touches the payment.

**5 · Stolen credential.** The real credential replayed under a thief's key: `holder_binding_failed`, refused before the handler runs. Not a bearer token.

**K · The kill.** The Responsible Party sets one bit, re-signs the list, publishes the next version. With `KEY_WEBAUTHN=1` that needs a physical touch: the WebAuthn challenge *is* the SHA-256 of the revocation intent (this list, this index), so the assertion authorizes this revocation and nothing else. The agent's next request is refused — `Credential revoked via StatusList2021` — in one round trip.

**V · Any merchant, any language.** `scripts/verify-receipt.py` re-verifies the receipt with zero dependencies: the merchant's key derived from its `did:key`, the Ed25519 signature with RFC 8032 math, both bound hashes recomputed over RFC 8785 canonical JSON. No SDK.


Two beats the stage does not show but the tests do: the hub going **down** (status unresolvable → refused; this merchant's policy is fail-closed, and that choice is the merchant's, not the protocol's), and `OFFLINE=1` (the RP's DID document served from the hub's mirror, signatures still verified).

## Stage setup

### The Responsible Party's DID: public or local

The default `RP_DID=did:web:localhost%3A4950` resolves to the hub on this laptop, which is what you want for rehearsal and for a venue with no network. The merchant rewrites `https://localhost:4950/…` to `http://` for loopback only (`ALLOW_INSECURE_LOCALHOST=1`); nothing else is downgraded.

For a public identity, before `npm run setup`:

```bash
echo 'RP_DID=did:web:hub.example.com' >> .env.local      # a domain you control
npm run setup                                           # writes var/rp/did.json for that DID
# publish var/rp/did.json at https://hub.example.com/.well-known/did.json
```

The hub keeps serving the same document at `/.well-known/did.json`, and `RP_DID_MIRROR_URL` (default: the hub's copy) is used when the network fails or `OFFLINE=1` is set. The console says where the document came from. Changing `RP_DID` after setup is fine: re-run `npm run setup` and it re-derives the key id, the DID document, the list and the first grant for the new DID (the signing key is kept).

### The authenticator (any FIDO2 key, or Touch ID)

```bash
KEY_SETUP=1 npm run demo         # then open http://localhost:4949/setup-key.html
```

Register more than one — a security key, a conference badge, the laptop's platform authenticator — with a label each; whichever is in your hand on stage works. Then:

```bash
KEY_WEBAUTHN=1 npm run demo      # revocation now requires a touch
DEMO_BYPASS_WEBAUTHN=1 KEY_WEBAUTHN=1 npm run demo   # software path, if a key misbehaves
```

WebAuthn works on `localhost` without TLS; keep the console there.

### Claude Desktop as the agent (optional)

Merge `docs/claude_desktop_config.json` into your Claude Desktop config (absolute paths, as the comment explains), restart Claude, and ask it to check its authority and order two boxes of risotto. Claude sees `browse_catalog`, `my_authority`, `place_order` — no crypto arguments. The gateway holds the agent's key and the delegation and signs every call; the console lights the same gates because the merchant has a single emission point. The simulated agent is deterministic; use it for the timed beats and Claude for colour.

### Presenter notes

`P` hides the controls and enlarges the signal for a projector or a Meet screen share; `C` adds contrast for washed-out rooms. Rehearse once at 1280×720 — half the audience is remote. `R` issues a fresh grant at the next status-list index without restarting anything; `npm run revoke -- --index N --restore` clears a bit if you need the same index back.

## What is real and what is a demo convenience

- The gate is the published middleware (`createKyaOsMiddleware` with `holderBinding: 'enforce'` and a `StatusListResolver`). The console's six gates follow the middleware's actual order; the last two are the merchant handler's own reads of the verified credential.
- `HttpStatusListResolver` (`src/lib/http-statuslist-resolver.ts`) is this example's implementation of the shipped `StatusListResolver` seam, modelled on the SDK's `CheqdStatusListResolver`: it verifies the list's Ed25519Signature2020 proof against the issuer's resolved DID document and fails closed on everything else. It is not yet in the SDK.
- `acceptedTrustSchemes` in the discovery document is a **proposal** for the publisher-side agent surface, not a KYA-OS specification field. The rest of the document follows `schemas/well-known-mcpi.json`.
- The GS1 Digital Link scope is a **profile** of the existing CRISP scope (`{ resource, matcher: 'prefix' }`): no new mechanism, one convention. The handler adds a path-boundary re-check so `prefix` can never admit a longer GTIN.
- The status list is hosted by the hub over plain HTTP on this laptop. Where you host it — your domain, a registry, a ledger (REVOKED anchored the same signed document on cheqd) — is policy; the protocol needs a URL and a signature. The hub keeps an append-only version history locally; a ledger makes that history one nobody can rewrite.
- Payment is out of scope by design. The receipt says `authorized-for-capture`; spend enforcement and settlement stay with the merchant/PSP.

## Layout

```
src/lib/        wiring (env, keys, paths) · mirror-capable fetch provider · HttpStatusListResolver · GS1 Digital Link + catalog
src/rp/         the Responsible Party's hub: did.json, status list, issue, revoke, WebAuthn ceremony
src/merchant/   the merchant edge: MCP server + shipped gate, place_order, discovery document, console API
src/agent/      the agent: discover, order (MCP client + holder proof), Claude Desktop gateway
web/            the console (index.html) and authenticator registration (setup-key.html)
scripts/        setup.ts · verify-receipt.py (stdlib Python) · screenshot-run.py (headless smoke test)
tests/          product/scope decisions · resolver fail-closed matrix · every beat end to end, incl. hub-down and offline
```

`npm test` runs all of it in-process on ephemeral ports.

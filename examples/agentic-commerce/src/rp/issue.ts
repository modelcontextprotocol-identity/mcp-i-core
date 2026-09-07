#!/usr/bin/env npx tsx
/**
 * Issue the shopping agent's DelegationCredential.
 *
 *   issuer   = the Responsible Party's did:web (the shopper's own hub)
 *   subject  = the agent's did:key (its Ed25519 request-signing key)
 *   scope    = ONE GS1 Digital Link product class, prefix-matched, so every
 *              /10/<lot> and /21/<serial> beneath it is in scope and every
 *              other GTIN is not
 *   cap      = SPEND_CAP SPEND_CURRENCY per order — inside the signed credential
 *   window   = notBefore/notAfter (VALID_HOURS)
 *   audience = the merchant's DID — this grant is for THIS merchant
 *   status   = StatusList2021Entry → the RP-hosted list, one index per grant
 *
 * Usage: npm run issue [-- --index 95] [--valid-hours 48]
 */
import path from 'node:path';
import {
  DelegationCredentialIssuer,
  type CredentialStatus,
  type DelegationCredential,
} from '@kya-os/mcp';
import {
  SCOPE_PRODUCT_CLASS,
  SPEND_CAP,
  SPEND_CURRENCY,
  STATUS_LIST_URL,
  VALID_HOURS,
  VAR_DIR,
  env,
  loadRpIdentity,
  makeVcSigningFunction,
  readJson,
  requiredEnv,
  writeJson,
  type KeyedIdentity,
} from '../lib/wiring.js';
import { parseDigitalLink } from '../lib/product.js';

export const ACTIVE_INDEX_FILE = path.join(VAR_DIR, 'active-index.json');
export const delegationFile = (index: number): string => path.join(VAR_DIR, `delegation-${index}.json`);

export interface IssueOptions {
  index: number;
  agentDid: string;
  audience: string;
  productClass?: string;
  cap?: string;
  currency?: string;
  validHours?: number;
  identity?: KeyedIdentity;
  statusListUrl?: string;
}

export async function issueDelegation(options: IssueOptions): Promise<DelegationCredential> {
  const identity = options.identity ?? loadRpIdentity();
  const productClass = options.productClass ?? SCOPE_PRODUCT_CLASS;
  const cap = options.cap ?? SPEND_CAP;
  const currency = options.currency ?? SPEND_CURRENCY;
  const validHours = options.validHours ?? VALID_HOURS;
  const statusListUrl = options.statusListUrl ?? STATUS_LIST_URL;

  const dl = parseDigitalLink(productClass);
  if (!dl || dl.lot || dl.serial) {
    throw new Error(`SCOPE_PRODUCT_CLASS must be a product-class Digital Link (https://<host>/01/<GTIN>), got "${productClass}"`);
  }

  const signingFunction = makeVcSigningFunction(identity.privateKeyBase64);
  const issuer = new DelegationCredentialIssuer(
    { getDid: () => identity.did, getKeyId: () => identity.kid, getPrivateKey: () => identity.privateKeyBase64 },
    signingFunction,
  );

  const credentialStatus: CredentialStatus = {
    id: `${statusListUrl}#${options.index}`,
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: String(options.index),
    statusListCredential: statusListUrl,
  };

  const nowSec = Math.floor(Date.now() / 1000);
  return issuer.createAndIssueDelegation(
    {
      id: `agentic-commerce-${options.index}-${Date.now()}`,
      issuerDid: identity.did,
      subjectDid: options.agentDid,
      constraints: {
        scopes: ['commerce.order'],
        audience: options.audience,
        notBefore: nowSec - 60,
        notAfter: nowSec + validHours * 3600,
        crisp: {
          scopes: [
            {
              // The noun: a GS1 Digital Link product class. `prefix` covers the
              // GS1 hierarchy beneath it (/10/<lot>, /21/<serial>).
              resource: dl.classUri,
              matcher: 'prefix',
              constraints: {
                maxAmount: cap,
                currency,
                per: 'order',
                identifierScheme: 'gs1:digital-link',
                gtin: dl.gtin,
              },
            },
          ],
        },
      },
      metadata: { tool: 'place_order', event: 'w3c-gs1-ecommerce-workshop-2026' },
    },
    { credentialStatus },
  );
}

/** Issue at an index, persist as the agent's active credential. */
export async function issueAndActivate(options: IssueOptions): Promise<{ file: string; vc: DelegationCredential }> {
  const vc = await issueDelegation(options);
  const file = delegationFile(options.index);
  writeJson(file, vc);
  writeJson(ACTIVE_INDEX_FILE, { index: options.index, file, issuedAt: new Date().toISOString() });
  return { file, vc };
}

export function activeIndex(): number {
  return readJson<{ index: number }>(ACTIVE_INDEX_FILE)?.index ?? 94;
}

export function activeCredential(): DelegationCredential {
  const index = activeIndex();
  const vc = readJson<DelegationCredential>(delegationFile(index));
  if (!vc) throw new Error(`No credential at ${delegationFile(index)} — run: npm run setup`);
  return vc;
}

const isMain = process.argv[1]?.endsWith('issue.ts');
if (isMain) {
  const indexArg = process.argv.indexOf('--index');
  const index = Number(indexArg > -1 ? process.argv[indexArg + 1]! : env('STATUSLIST_INDEX', '94'));
  const hoursArg = process.argv.indexOf('--valid-hours');
  const validHours = hoursArg > -1 ? Number(process.argv[hoursArg + 1]) : undefined;
  issueAndActivate({
    index,
    agentDid: requiredEnv('AGENT_DID'),
    audience: requiredEnv('MERCHANT_DID'),
    ...(validHours ? { validHours } : {}),
  })
    .then(({ file, vc }) => {
      const scope = vc.credentialSubject.delegation.constraints.crisp?.scopes?.[0];
      console.log(JSON.stringify({
        file,
        issuer: vc.issuer,
        subject: vc.credentialSubject.id,
        audience: vc.credentialSubject.delegation.constraints.audience,
        scope: scope ? `${scope.resource} (${scope.matcher})` : null,
        cap: scope?.constraints ? `${(scope.constraints as Record<string, string>)['currency']} ${(scope.constraints as Record<string, string>)['maxAmount']} per order` : null,
        expires: vc.expirationDate,
        statusListIndex: vc.credentialStatus?.statusListIndex,
        statusListCredential: vc.credentialStatus?.statusListCredential,
      }, null, 2));
    })
    .catch((err) => { console.error(err); process.exit(1); });
}

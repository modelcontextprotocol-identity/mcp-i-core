/**
 * Delegation Issuer Factory
 *
 * Creates a DelegationCredentialIssuer from an identity config.
 * Used by both consent-server.ts and tests.
 *
 * Related Spec: MCP-I §3.1 (VC structure), §4.1 (DelegationRecord)
 */

import { DelegationCredentialIssuer } from '../../../src/delegation/vc-issuer.js';
import type { VCSigningFunction } from '../../../src/delegation/vc-issuer.js';
import type { Proof } from '../../../src/types/protocol.js';
import type { CryptoProvider } from '../../../src/providers/base.js';
import { base64urlEncodeFromBytes } from '../../../src/utils/base64.js';

export interface AgentIdentityConfig {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
}

export interface DelegationIssuerFactory {
  issuer: DelegationCredentialIssuer;
  identity: AgentIdentityConfig;
}

export function createDelegationIssuerFromIdentity(
  crypto: CryptoProvider,
  identity: AgentIdentityConfig,
): DelegationIssuerFactory {
  const signingFunction: VCSigningFunction = async (
    canonicalVC: string,
    _issuerDid: string,
    kid: string,
  ): Promise<Proof> => {
    const data = new TextEncoder().encode(canonicalVC);
    const sigBytes = await crypto.sign(data, identity.privateKey);
    const proofValue = base64urlEncodeFromBytes(sigBytes);
    return {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      verificationMethod: kid,
      proofPurpose: 'assertionMethod',
      proofValue,
    };
  };

  const issuer = new DelegationCredentialIssuer(
    {
      getDid: () => identity.did,
      getKeyId: () => identity.kid,
      getPrivateKey: () => identity.privateKey,
    },
    signingFunction,
  );

  return { issuer, identity };
}

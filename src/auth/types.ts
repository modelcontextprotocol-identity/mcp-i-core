/**
 * Authorization types for the auth module.
 *
 * Minimal interfaces required by the auth handshake.
 */

import type { DelegationRecord } from '../types/protocol.js';

export interface VerifyDelegationResult {
  valid: boolean;
  delegation?: DelegationRecord;
  credential?: {
    agent_did: string;
    user_did: string;
    scopes: string[];
    authorization: {
      type:
        | 'oauth'
        | 'oauth2'
        | 'password'
        | 'credential'
        | 'webauthn'
        | 'siwe'
        | 'none';
      provider?: string;
      credentialType?: string;
      rpId?: string;
      userVerification?: 'required' | 'preferred' | 'discouraged';
      chainId?: number;
      domain?: string;
    };
    [key: string]: unknown;
  };
  reason?: string;
  cached?: boolean;
}

export interface DelegationVerifier {
  verify(agentDid: string, scopes: string[]): Promise<VerifyDelegationResult>;
}

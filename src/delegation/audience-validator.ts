/**
 * Delegation Audience Validation
 *
 * Validates if a delegation's audience matches the server DID.
 * Supports both single server DID and multiple server DIDs.
 */

import type { DelegationRecord } from '../types/protocol.js';

export function verifyDelegationAudience(
  delegation: DelegationRecord,
  serverDid: string
): boolean {
  if (!delegation.constraints.audience) {
    return true;
  }

  const audience = delegation.constraints.audience;
  if (typeof audience === 'string') {
    return audience === serverDid;
  }

  return audience.includes(serverDid);
}

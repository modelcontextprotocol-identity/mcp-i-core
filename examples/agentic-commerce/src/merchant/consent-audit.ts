/** Consent joins the existing merchant ledger using its published event catalog. */
import { createHash } from 'node:crypto';
import { canonicalizeJSON } from '@kya-os/mcp';
import type { AuditTrailEventInput } from '@kya-os/mcp/audit';
import type { MerchantAudit } from './audit.js';
import type { ConsentFlowStore } from '../rp/consent-store.js';

export const consentDigest = (value: unknown): `sha256:${string}` =>
  `sha256:${createHash('sha256').update(canonicalizeJSON(value)).digest('hex')}`;

/** Serialize ingestion so overlapping HTTP requests cannot duplicate RP events. */
export function createConsentAuditBridge(audit: MerchantAudit, store: ConsentFlowStore, responsibleParty: string) {
  let tail: Promise<void> = Promise.resolve();
  const recorded = new Set<string>();
  async function record(input: AuditTrailEventInput) {
    const result = await audit.record(input);
    if (result.status !== 'recorded') throw new Error('AUDIT_UNAVAILABLE: consent could not be recorded');
  }
  const flush = (): Promise<void> => {
    const next = tail.then(async () => {
      for (const event of store.pendingEvents()) {
        if (!recorded.has(event.id)) {
          const payload = event.payload as Record<string, unknown>;
          const delegation = event.type.startsWith('delegation.');
          // Older persisted queues used this label for a WebAuthn assertion.
          const legacyAuthenticatorProof = event.type === 'credential.verified';
          const phase = event.type.slice(event.type.indexOf('.') + 1);
          const credentialId = String(payload['credentialId'] ?? 'unknown');
          const scope = String(payload['productClass'] ?? payload['scope'] ?? 'commerce.order');
          const cap = String(payload['cap'] ?? '');
          const currency = String(payload['currency'] ?? 'CHF');
          const demoConsent = payload['demoConsent'] as { consentRef?: string } | undefined;
          // Authentication is evidence inside consent.approved, not a delegation credential verification.
          const consentRef = consentDigest(payload['resumeTokenHash'] ?? event.id);
          const actionName = delegation ? `place_order; index=${String(payload['index'] ?? '')}; MaxAmount=${currency} ${cap}` : 'place_order';
          await record({
            eventType: legacyAuthenticatorProof ? 'proof.verified' : event.type,
            actor: { kind: 'public_did', did: event.actor },
            responsibleParty: { kind: 'public_did', did: responsibleParty },
            correlationId: demoConsent?.consentRef ?? consentDigest(payload['resumeTokenHash'] ?? event.id),
            action: { category: delegation ? 'delegation' : 'consent', name: actionName },
            resource: { kind: 'keyed_commitment', value: consentDigest(payload), keyId: 'consent-grant-bindings' },
            outcome: phase === 'denied' ? 'denied' : 'succeeded',
            ...(phase === 'denied' ? { reason: { code: 'CONSENT_DENIED' } } : {}),
            ...(delegation ? { authorization: { source: 'delegation' as const, decision: phase === 'revoked' ? 'denied' as const : 'allowed' as const, scopeId: scope, delegationRef: credentialId } } : {}),
            evidence: [],
            details: legacyAuthenticatorProof
              ? { family: 'proof', phase: 'verified', verificationCode: 'WEBAUTHN_ASSERTION_VERIFIED' }
              : delegation
              ? { family: 'delegation', phase: phase as 'issued' | 'revoked', delegationRef: credentialId }
              : { family: 'consent', phase: phase as 'requested' | 'approved' | 'denied', consentRef },
          });
          recorded.add(event.id);
        }
        store.acknowledgeEvents([event.id]);
      }
    });
    tail = next.catch(() => {});
    return next;
  };
  return { flush, record };
}

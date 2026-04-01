/**
 * Graph-Revocation Round-Trip Audit Tests
 *
 * Tests the delegation graph → cascading revocation pipeline with real
 * StatusList2021 bitstring encoding/decoding and real gzip compression.
 * No mocking of graph storage, status lists, or compression.
 */

import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { DelegationGraphManager } from '../../delegation/delegation-graph.js';
import { CascadingRevocationManager } from '../../delegation/cascading-revocation.js';
import type { AgentIdentity } from '../../providers/base.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealStatusListManager,
  MemoryDelegationGraphStorage,
  type RealStatusListSetup,
} from './helpers/crypto-helpers.js';
import { NodeCryptoProvider } from '../utils/node-crypto-provider.js';

describe('Graph-Revocation Round-Trip Audit', () => {
  let crypto: NodeCryptoProvider;
  let issuerIdentity: AgentIdentity;
  let graph: DelegationGraphManager;
  let graphStorage: MemoryDelegationGraphStorage;
  let statusListSetup: RealStatusListSetup;
  let revocationManager: CascadingRevocationManager;

  // Create identities for chain: issuer -> agentA -> agentB -> agentC
  let agentA: AgentIdentity;
  let agentB: AgentIdentity;
  let agentC: AgentIdentity;

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    issuerIdentity = await createRealIdentity(crypto);
    agentA = await createRealIdentity(crypto);
    agentB = await createRealIdentity(crypto);
    agentC = await createRealIdentity(crypto);
  });

  beforeEach(async () => {
    graphStorage = new MemoryDelegationGraphStorage();
    graph = new DelegationGraphManager(graphStorage);

    statusListSetup = createRealStatusListManager(crypto, issuerIdentity, {
      statusListBaseUrl: 'https://status.test.example.com',
    });

    revocationManager = new CascadingRevocationManager(graph, statusListSetup.manager);
  });

  // Helper: register a delegation and allocate a status entry
  async function registerWithStatus(
    id: string,
    parentId: string | null,
    issuerDid: string,
    subjectDid: string
  ): Promise<string> {
    const statusEntry = await statusListSetup.manager.allocateStatusEntry('revocation');
    await graph.registerDelegation({
      id,
      parentId,
      issuerDid,
      subjectDid,
      credentialStatusId: statusEntry.id,
    });
    return statusEntry.id;
  }

  // ── Chain Validation ──────────────────────────────────────────

  describe('chain validation with real graph', () => {
    it('should validate a correctly chained delegation', async () => {
      // issuer -> agentA -> agentB -> agentC
      await registerWithStatus('del-root', null, issuerIdentity.did, agentA.did);
      await registerWithStatus('del-child', 'del-root', agentA.did, agentB.did);
      await registerWithStatus('del-grandchild', 'del-child', agentB.did, agentC.did);

      const result = await graph.validateChain('del-grandchild');
      expect(result.valid).toBe(true);
    });

    it('should reject chain with issuer/subject mismatch', async () => {
      // root: issuer -> agentA, child: agentC -> agentB (mismatch: agentC != agentA)
      await registerWithStatus('del-root', null, issuerIdentity.did, agentA.did);
      await registerWithStatus('del-child', 'del-root', agentC.did, agentB.did);

      const result = await graph.validateChain('del-child');
      expect(result.valid).toBe(false);
      expect(result.reason).toBeDefined();
    });
  });

  // ── Cascading Revocation ──────────────────────────────────────

  describe('cascading revocation with real StatusList2021', () => {
    it('should revoke root and cascade to all descendants via StatusList', async () => {
      const rootStatusId = await registerWithStatus('del-root', null, issuerIdentity.did, agentA.did);
      const childStatusId = await registerWithStatus('del-child', 'del-root', agentA.did, agentB.did);
      const grandchildStatusId = await registerWithStatus('del-gc', 'del-child', agentB.did, agentC.did);

      const events = await revocationManager.revokeDelegation('del-root');

      expect(events.length).toBe(3);
      expect(events[0]!.isRoot).toBe(true);

      // Verify via real StatusList that all are revoked
      const rootRevoked = await revocationManager.isRevoked('del-root');
      const childRevoked = await revocationManager.isRevoked('del-child');
      const gcRevoked = await revocationManager.isRevoked('del-gc');

      expect(rootRevoked.revoked).toBe(true);
      expect(childRevoked.revoked).toBe(true);
      expect(gcRevoked.revoked).toBe(true);
    });

    it('should only revoke descendants, not siblings or ancestors', async () => {
      await registerWithStatus('del-root', null, issuerIdentity.did, agentA.did);
      await registerWithStatus('del-child1', 'del-root', agentA.did, agentB.did);
      await registerWithStatus('del-child2', 'del-root', agentA.did, agentC.did);

      // Revoke child1 only
      await revocationManager.revokeDelegation('del-child1');

      const child1 = await revocationManager.isRevoked('del-child1');
      const child2 = await revocationManager.isRevoked('del-child2');
      const root = await revocationManager.isRevoked('del-root');

      expect(child1.revoked).toBe(true);
      expect(child2.revoked).toBe(false);
      expect(root.revoked).toBe(false);
    });

    // BUG: isRevoked() can't distinguish "directly revoked" from "cascade revoked"
    // because cascading revocation sets bits on ALL descendants. chain.reverse()
    // finds the child's own bit first, so revokedAncestor is never populated.
    // See: https://github.com/modelcontextprotocol-identity/mcp-i-core/issues/30
    it.skip('should detect ancestor revocation through chain walk — see #30', async () => {
      await registerWithStatus('del-root', null, issuerIdentity.did, agentA.did);
      await registerWithStatus('del-child', 'del-root', agentA.did, agentB.did);

      await revocationManager.revokeDelegation('del-root');

      const childStatus = await revocationManager.isRevoked('del-child');
      expect(childStatus.revoked).toBe(true);
      expect(childStatus.revokedAncestor).toBe('del-root');
    });
  });

  // ── Restore Behavior ──────────────────────────────────────────

  describe('restore delegation', () => {
    it('should restore root but NOT restore cascaded children', async () => {
      await registerWithStatus('del-root', null, issuerIdentity.did, agentA.did);
      await registerWithStatus('del-child', 'del-root', agentA.did, agentB.did);

      // Revoke root (cascades to child)
      await revocationManager.revokeDelegation('del-root');

      const rootBefore = await revocationManager.isRevoked('del-root');
      const childBefore = await revocationManager.isRevoked('del-child');
      expect(rootBefore.revoked).toBe(true);
      expect(childBefore.revoked).toBe(true);

      // Restore root only
      await revocationManager.restoreDelegation('del-root');

      const rootAfter = await revocationManager.isRevoked('del-root');
      const childAfter = await revocationManager.isRevoked('del-child');

      expect(rootAfter.revoked).toBe(false);
      // Child should STILL be revoked — restore is not recursive
      expect(childAfter.revoked).toBe(true);
    });
  });

  // ── Dry-Run ───────────────────────────────────────────────────

  describe('dry-run mode', () => {
    it('should not modify StatusList bits in dry-run', async () => {
      await registerWithStatus('del-root', null, issuerIdentity.did, agentA.did);
      await registerWithStatus('del-child', 'del-root', agentA.did, agentB.did);

      const events = await revocationManager.revokeDelegation('del-root', { dryRun: true });

      expect(events.length).toBe(2);

      // Nothing should actually be revoked
      const root = await revocationManager.isRevoked('del-root');
      const child = await revocationManager.isRevoked('del-child');

      expect(root.revoked).toBe(false);
      expect(child.revoked).toBe(false);
    });
  });

  // ── Deep Chain ────────────────────────────────────────────────

  describe('deep chain cascading', () => {
    it('should cascade through a depth-10 chain', async () => {
      // Build chain of depth 10
      const dids = [issuerIdentity, agentA, agentB, agentC];
      let parentId: string | null = null;

      for (let i = 0; i < 10; i++) {
        const issuerIdx = i % dids.length;
        const subjectIdx = (i + 1) % dids.length;
        const id = `del-depth-${i}`;

        await registerWithStatus(
          id,
          parentId,
          dids[issuerIdx]!.did,
          dids[subjectIdx]!.did
        );
        parentId = id;
      }

      // Revoke root — all 9 descendants should be revoked
      const events = await revocationManager.revokeDelegation('del-depth-0');
      expect(events.length).toBe(10);

      for (let i = 0; i < 10; i++) {
        const status = await revocationManager.isRevoked(`del-depth-${i}`);
        expect(status.revoked).toBe(true);
      }
    });
  });

  // ── Concurrent Revocation ─────────────────────────────────────

  describe('concurrent revocation', () => {
    it('should handle concurrent revocation of sibling subtrees', async () => {
      await registerWithStatus('del-root', null, issuerIdentity.did, agentA.did);
      await registerWithStatus('del-child1', 'del-root', agentA.did, agentB.did);
      await registerWithStatus('del-gc1', 'del-child1', agentB.did, agentC.did);
      await registerWithStatus('del-child2', 'del-root', agentA.did, agentC.did);
      await registerWithStatus('del-gc2', 'del-child2', agentC.did, agentB.did);

      // Revoke both subtrees concurrently
      const [events1, events2] = await Promise.all([
        revocationManager.revokeDelegation('del-child1'),
        revocationManager.revokeDelegation('del-child2'),
      ]);

      expect(events1.length).toBeGreaterThanOrEqual(2);
      expect(events2.length).toBeGreaterThanOrEqual(2);

      // All 4 nodes should be revoked
      for (const id of ['del-child1', 'del-gc1', 'del-child2', 'del-gc2']) {
        const status = await revocationManager.isRevoked(id);
        expect(status.revoked).toBe(true);
      }

      // Root should not be revoked
      const root = await revocationManager.isRevoked('del-root');
      expect(root.revoked).toBe(false);
    });
  });

  // ── validateDelegation ────────────────────────────────────────

  describe('validateDelegation', () => {
    it('should return valid for non-revoked, well-formed chain', async () => {
      await registerWithStatus('del-root', null, issuerIdentity.did, agentA.did);
      await registerWithStatus('del-child', 'del-root', agentA.did, agentB.did);

      const result = await revocationManager.validateDelegation('del-child');
      expect(result.valid).toBe(true);
    });

    it('should return invalid after ancestor revocation', async () => {
      await registerWithStatus('del-root', null, issuerIdentity.did, agentA.did);
      await registerWithStatus('del-child', 'del-root', agentA.did, agentB.did);

      await revocationManager.revokeDelegation('del-root');

      const result = await revocationManager.validateDelegation('del-child');
      expect(result.valid).toBe(false);
    });
  });
});

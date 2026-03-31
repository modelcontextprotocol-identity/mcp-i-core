/**
 * StatusList2021 + Bitstring Round-Trip Audit Tests
 *
 * Tests the full lifecycle: allocate status entry → check (not revoked) →
 * revoke → check (revoked), using real gzip compression and bitstring encoding.
 */

import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import type { AgentIdentity } from '../../providers/base.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealStatusListManager,
  type RealStatusListSetup,
} from './helpers/crypto-helpers.js';
import { NodeCryptoProvider } from '../utils/node-crypto-provider.js';

describe('StatusList Bitstring Round-Trip Audit', () => {
  let crypto: NodeCryptoProvider;
  let identity: AgentIdentity;
  let setup: RealStatusListSetup;

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    identity = await createRealIdentity(crypto);
  });

  beforeEach(() => {
    setup = createRealStatusListManager(crypto, identity);
  });

  it('should allocate, check not revoked, revoke, then check revoked', async () => {
    const statusEntry = await setup.manager.allocateStatusEntry('revocation');

    // Initially not revoked
    const beforeRevoke = await setup.manager.checkStatus(statusEntry);
    expect(beforeRevoke).toBe(false);

    // Revoke
    await setup.manager.updateStatus(statusEntry, true);

    // Now revoked
    const afterRevoke = await setup.manager.checkStatus(statusEntry);
    expect(afterRevoke).toBe(true);
  });

  it('should selectively revoke entries in the same status list', async () => {
    // Allocate 5 entries
    const entries = [];
    for (let i = 0; i < 5; i++) {
      entries.push(await setup.manager.allocateStatusEntry('revocation'));
    }

    // Revoke entries at index 1 and 3
    await setup.manager.updateStatus(entries[1]!, true);
    await setup.manager.updateStatus(entries[3]!, true);

    // Check all 5
    const statuses = await Promise.all(
      entries.map((e) => setup.manager.checkStatus(e))
    );

    expect(statuses[0]).toBe(false);
    expect(statuses[1]).toBe(true);
    expect(statuses[2]).toBe(false);
    expect(statuses[3]).toBe(true);
    expect(statuses[4]).toBe(false);
  });

  it('should report revoked indices correctly via getRevokedIndices', async () => {
    const entries = [];
    for (let i = 0; i < 6; i++) {
      entries.push(await setup.manager.allocateStatusEntry('revocation'));
    }

    // Revoke indices 0, 2, 5
    await setup.manager.updateStatus(entries[0]!, true);
    await setup.manager.updateStatus(entries[2]!, true);
    await setup.manager.updateStatus(entries[5]!, true);

    const statusListId = `${setup.manager.getStatusListBaseUrl()}/revocation/v1`;
    const revoked = await setup.manager.getRevokedIndices(statusListId);

    expect(revoked).toContain(0);
    expect(revoked).toContain(2);
    expect(revoked).toContain(5);
    expect(revoked).not.toContain(1);
    expect(revoked).not.toContain(3);
    expect(revoked).not.toContain(4);
  });

  it('should re-sign the status list credential after update', async () => {
    const entry = await setup.manager.allocateStatusEntry('revocation');

    const statusListId = `${setup.manager.getStatusListBaseUrl()}/revocation/v1`;
    const credBefore = await setup.storage.getStatusList(statusListId);
    const proofBefore = credBefore?.proof?.proofValue;

    // Revoke — triggers re-signing
    await setup.manager.updateStatus(entry, true);

    const credAfter = await setup.storage.getStatusList(statusListId);
    const proofAfter = credAfter?.proof?.proofValue;

    expect(proofBefore).toBeDefined();
    expect(proofAfter).toBeDefined();
    expect(proofAfter).not.toBe(proofBefore);
  });

  it('should handle bits at byte boundaries correctly (index 7 and 8)', async () => {
    // Allocate enough entries to reach index 7 and 8
    const entries = [];
    for (let i = 0; i < 9; i++) {
      entries.push(await setup.manager.allocateStatusEntry('revocation'));
    }

    // Index 7 = last bit of byte 0, Index 8 = first bit of byte 1
    await setup.manager.updateStatus(entries[7]!, true);
    await setup.manager.updateStatus(entries[8]!, true);

    expect(await setup.manager.checkStatus(entries[6]!)).toBe(false);
    expect(await setup.manager.checkStatus(entries[7]!)).toBe(true);
    expect(await setup.manager.checkStatus(entries[8]!)).toBe(true);
  });

  it('should un-revoke (restore) an entry by setting status to false', async () => {
    const entry = await setup.manager.allocateStatusEntry('revocation');

    await setup.manager.updateStatus(entry, true);
    expect(await setup.manager.checkStatus(entry)).toBe(true);

    await setup.manager.updateStatus(entry, false);
    expect(await setup.manager.checkStatus(entry)).toBe(false);
  });
});

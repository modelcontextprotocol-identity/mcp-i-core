/**
 * Base Provider Classes
 *
 * Abstract classes that define the provider interfaces for
 * platform-specific implementations.
 */

import type { DIDDocument } from '../delegation/vc-verifier.js';
import type { StatusList2021Credential, DelegationRecord } from '../types/protocol.js';

export abstract class CryptoProvider {
  abstract sign(data: Uint8Array, privateKey: string): Promise<Uint8Array>;
  abstract verify(data: Uint8Array, signature: Uint8Array, publicKey: string): Promise<boolean>;
  abstract generateKeyPair(): Promise<{ privateKey: string; publicKey: string }>;
  /**
   * Compute SHA-256 hash of data.
   * Returns "sha256:<hex>" format for cross-platform parity.
   */
  abstract hash(data: Uint8Array): Promise<string>;
  abstract randomBytes(length: number): Promise<Uint8Array>;
}

export abstract class ClockProvider {
  abstract now(): number;
  abstract isWithinSkew(timestamp: number, skewSeconds: number): boolean;
  abstract hasExpired(expiresAt: number): boolean;
  abstract calculateExpiry(ttlSeconds: number): number;
  abstract format(timestamp: number): string;
}

export abstract class FetchProvider {
  abstract resolveDID(did: string): Promise<DIDDocument | null>;
  abstract fetchStatusList(url: string): Promise<StatusList2021Credential | null>;
  abstract fetchDelegationChain(id: string): Promise<DelegationRecord[]>;
  abstract fetch(url: string, options?: unknown): Promise<Response>;
}

export abstract class StorageProvider {
  abstract get(key: string): Promise<string | null>;
  abstract set(key: string, value: string): Promise<void>;
  abstract delete(key: string): Promise<void>;
  abstract exists(key: string): Promise<boolean>;
  abstract list(prefix?: string): Promise<string[]>;
}

export abstract class NonceCacheProvider {
  abstract has(nonce: string, agentDid?: string): Promise<boolean>;
  abstract add(nonce: string, ttlSeconds: number, agentDid?: string): Promise<void>;
  abstract cleanup(): Promise<void>;
  abstract destroy(): Promise<void>;
}

export interface AgentIdentity {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
  createdAt: string;
  type: 'development' | 'production';
  metadata?: Record<string, unknown>;
}

export abstract class IdentityProvider {
  abstract getIdentity(): Promise<AgentIdentity>;
  abstract saveIdentity(identity: AgentIdentity): Promise<void>;
  abstract rotateKeys(): Promise<AgentIdentity>;
  abstract deleteIdentity(): Promise<void>;
}

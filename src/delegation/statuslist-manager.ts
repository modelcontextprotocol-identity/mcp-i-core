/**
 * StatusList2021 Manager
 *
 * Manages StatusList2021 credentials for efficient delegation revocation.
 *
 * Related Spec: W3C StatusList2021
 */

import type {
  StatusList2021Credential,
  CredentialStatus,
} from '../types/protocol.js';
import { BitstringManager, type CompressionFunction, type DecompressionFunction } from './bitstring.js';
import type { VCSigningFunction } from './vc-issuer.js';
import { canonicalizeJSON } from './utils.js';

export interface StatusListStorageProvider {
  getStatusList(statusListId: string): Promise<StatusList2021Credential | null>;
  setStatusList(statusListId: string, credential: StatusList2021Credential): Promise<void>;
  allocateIndex(statusListId: string): Promise<number>;
}

export interface StatusListIdentityProvider {
  getDid(): string;
  getKeyId(): string;
}

export class StatusList2021Manager {
  private statusListBaseUrl: string;
  private defaultListSize: number;

  constructor(
    private storage: StatusListStorageProvider,
    private identity: StatusListIdentityProvider,
    private signingFunction: VCSigningFunction,
    private compressor: CompressionFunction,
    private decompressor: DecompressionFunction,
    options?: {
      statusListBaseUrl?: string;
      defaultListSize?: number;
    }
  ) {
    this.statusListBaseUrl = options?.statusListBaseUrl || 'https://status.example.com';
    this.defaultListSize = options?.defaultListSize || 131072;
  }

  async allocateStatusEntry(purpose: 'revocation' | 'suspension'): Promise<CredentialStatus> {
    const statusListId = `${this.statusListBaseUrl}/${purpose}/v1`;

    const index = await this.storage.allocateIndex(statusListId);

    await this.ensureStatusListExists(statusListId, purpose);

    const credentialStatus: CredentialStatus = {
      id: `${statusListId}#${index}`,
      type: 'StatusList2021Entry',
      statusPurpose: purpose,
      statusListIndex: index.toString(),
      statusListCredential: statusListId,
    };

    return credentialStatus;
  }

  async updateStatus(credentialStatus: CredentialStatus, revoked: boolean): Promise<void> {
    const { statusListCredential, statusListIndex } = credentialStatus;

    const statusList = await this.storage.getStatusList(statusListCredential);
    if (!statusList) {
      throw new Error(`Status list not found: ${statusListCredential}`);
    }

    const manager = await BitstringManager.decode(
      statusList.credentialSubject.encodedList,
      this.compressor,
      this.decompressor
    );

    const index = parseInt(statusListIndex, 10);
    manager.setBit(index, revoked);

    const encodedList = await manager.encode();

    const updatedCredential: StatusList2021Credential = {
      ...statusList,
      credentialSubject: {
        ...statusList.credentialSubject,
        encodedList,
      },
    };

    const unsignedCredential = { ...updatedCredential };
    delete (unsignedCredential as Record<string, unknown>)['proof'];

    const canonicalVC = canonicalizeJSON(unsignedCredential);
    const proof = await this.signingFunction(
      canonicalVC,
      this.identity.getDid(),
      this.identity.getKeyId()
    );

    const signedCredential: StatusList2021Credential = {
      ...updatedCredential,
      proof,
    };

    await this.storage.setStatusList(statusListCredential, signedCredential);
  }

  async checkStatus(credentialStatus: CredentialStatus): Promise<boolean> {
    const { statusListCredential, statusListIndex } = credentialStatus;

    const statusList = await this.storage.getStatusList(statusListCredential);
    if (!statusList) {
      throw new Error(
        `Status list not found: ${statusListCredential} — cannot determine revocation status`
      );
    }

    const manager = await BitstringManager.decode(
      statusList.credentialSubject.encodedList,
      this.compressor,
      this.decompressor
    );

    const index = parseInt(statusListIndex, 10);
    return manager.getBit(index);
  }

  async getRevokedIndices(statusListId: string): Promise<number[]> {
    const statusList = await this.storage.getStatusList(statusListId);
    if (!statusList) {
      return [];
    }

    const manager = await BitstringManager.decode(
      statusList.credentialSubject.encodedList,
      this.compressor,
      this.decompressor
    );

    return manager.getSetBits();
  }

  private async ensureStatusListExists(
    statusListId: string,
    purpose: 'revocation' | 'suspension'
  ): Promise<void> {
    const existing = await this.storage.getStatusList(statusListId);
    if (existing) {
      return;
    }

    const manager = new BitstringManager(
      this.defaultListSize,
      this.compressor,
      this.decompressor
    );
    const encodedList = await manager.encode();

    const unsignedCredential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/vc/status-list/2021/v1',
      ] as [string, string],
      id: statusListId,
      type: ['VerifiableCredential', 'StatusList2021Credential'] as [string, string],
      issuer: this.identity.getDid(),
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: `${statusListId}#list`,
        type: 'StatusList2021' as const,
        statusPurpose: purpose,
        encodedList,
      },
    };

    const canonicalVC = canonicalizeJSON(unsignedCredential);
    const proof = await this.signingFunction(
      canonicalVC,
      this.identity.getDid(),
      this.identity.getKeyId()
    );

    const signedCredential: StatusList2021Credential = {
      ...unsignedCredential,
      proof,
    };

    await this.storage.setStatusList(statusListId, signedCredential);
  }

  getStatusListBaseUrl(): string {
    return this.statusListBaseUrl;
  }

  getDefaultListSize(): number {
    return this.defaultListSize;
  }
}

export function createStatusListManager(
  storage: StatusListStorageProvider,
  identity: StatusListIdentityProvider,
  signingFunction: VCSigningFunction,
  compressor: CompressionFunction,
  decompressor: DecompressionFunction,
  options?: {
    statusListBaseUrl?: string;
    defaultListSize?: number;
  }
): StatusList2021Manager {
  return new StatusList2021Manager(
    storage,
    identity,
    signingFunction,
    compressor,
    decompressor,
    options
  );
}

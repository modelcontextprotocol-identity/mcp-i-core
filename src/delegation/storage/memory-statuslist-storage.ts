/**
 * In-Memory StatusList Storage Provider
 *
 * Memory-based implementation for testing and development.
 * NOT suitable for production (no persistence).
 */

import type { StatusList2021Credential } from '../../types/protocol.js';
import type { StatusListStorageProvider } from '../statuslist-manager.js';

export class MemoryStatusListStorage implements StatusListStorageProvider {
  private statusLists = new Map<string, StatusList2021Credential>();
  private indexCounters = new Map<string, number>();

  async getStatusList(statusListId: string): Promise<StatusList2021Credential | null> {
    return this.statusLists.get(statusListId) || null;
  }

  async setStatusList(statusListId: string, credential: StatusList2021Credential): Promise<void> {
    this.statusLists.set(statusListId, credential);
  }

  async allocateIndex(statusListId: string): Promise<number> {
    const current = this.indexCounters.get(statusListId) || 0;
    const allocated = current;
    this.indexCounters.set(statusListId, current + 1);
    return allocated;
  }

  getIndexCount(statusListId: string): number {
    return this.indexCounters.get(statusListId) || 0;
  }

  clear(): void {
    this.statusLists.clear();
    this.indexCounters.clear();
  }

  getAllStatusListIds(): string[] {
    return Array.from(this.statusLists.keys());
  }
}

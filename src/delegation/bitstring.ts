/**
 * Bitstring Utilities for StatusList2021
 *
 * Implements GZIP compression + base64url encoding for efficient status lists.
 * Per W3C StatusList2021 spec, each bit represents credential status:
 * - 0: Not revoked/suspended
 * - 1: Revoked/suspended
 *
 * Related Spec: W3C StatusList2021
 */

export interface CompressionFunction {
  compress(data: Uint8Array): Promise<Uint8Array>;
}

export interface DecompressionFunction {
  decompress(data: Uint8Array): Promise<Uint8Array>;
}

export class BitstringManager {
  private bits: Uint8Array;
  private size: number;

  constructor(
    size: number,
    private compressor: CompressionFunction,
    private decompressor: DecompressionFunction
  ) {
    this.size = size;
    const byteCount = Math.ceil(size / 8);
    this.bits = new Uint8Array(byteCount);
  }

  setBit(index: number, value: boolean): void {
    if (index < 0 || index >= this.size) {
      throw new Error(`Bit index ${index} out of range (0-${this.size - 1})`);
    }

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    if (value) {
      this.bits[byteIndex]! |= 1 << bitIndex;
    } else {
      this.bits[byteIndex]! &= ~(1 << bitIndex);
    }
  }

  getBit(index: number): boolean {
    if (index < 0 || index >= this.size) {
      throw new Error(`Bit index ${index} out of range (0-${this.size - 1})`);
    }

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    return (this.bits[byteIndex]! & (1 << bitIndex)) !== 0;
  }

  getSetBits(): number[] {
    const setBits: number[] = [];
    for (let i = 0; i < this.size; i++) {
      if (this.getBit(i)) {
        setBits.push(i);
      }
    }
    return setBits;
  }

  async encode(): Promise<string> {
    const compressed = await this.compressor.compress(this.bits);
    return this.base64urlEncode(compressed);
  }

  static async decode(
    encodedList: string,
    compressor: CompressionFunction,
    decompressor: DecompressionFunction
  ): Promise<BitstringManager> {
    const compressed = BitstringManager.base64urlDecode(encodedList);
    const decompressed = await decompressor.decompress(compressed);

    const size = decompressed.length * 8;
    const manager = new BitstringManager(size, compressor, decompressor);
    manager.bits = decompressed;
    return manager;
  }

  getRawBits(): Uint8Array {
    return this.bits;
  }

  getSize(): number {
    return this.size;
  }

  private base64urlEncode(data: Uint8Array): string {
    const base64 = this.bytesToBase64(data);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private static base64urlDecode(encoded: string): Uint8Array {
    let base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    return BitstringManager.base64ToBytes(base64);
  }

  private bytesToBase64(bytes: Uint8Array): string {
    const binary = Array.from(bytes)
      .map((byte) => String.fromCharCode(byte))
      .join('');
    return btoa(binary);
  }

  private static base64ToBytes(base64: string): Uint8Array {
    let standardBase64 = base64.replace(/-/g, '+').replace(/_/g, '/');
    const paddingNeeded = (4 - (standardBase64.length % 4)) % 4;
    standardBase64 += '='.repeat(paddingNeeded);

    const binary = atob(standardBase64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  static fromSetBits(
    size: number,
    setBits: number[],
    compressor: CompressionFunction,
    decompressor: DecompressionFunction
  ): BitstringManager {
    const manager = new BitstringManager(size, compressor, decompressor);
    for (const index of setBits) {
      manager.setBit(index, true);
    }
    return manager;
  }
}

export async function isIndexSet(
  encodedList: string,
  index: number,
  decompressor: DecompressionFunction
): Promise<boolean> {
  const compressed = (BitstringManager as unknown as { base64urlDecode: (s: string) => Uint8Array })['base64urlDecode'](encodedList);
  const decompressed = await decompressor.decompress(compressed);

  const byteIndex = Math.floor(index / 8);
  const bitIndex = index % 8;

  if (byteIndex >= decompressed.length) {
    return false;
  }

  return (decompressed[byteIndex]! & (1 << bitIndex)) !== 0;
}

import { describe, it, expect, beforeEach } from "vitest";
import {
  BitstringManager,
  isIndexSet,
  type CompressionFunction,
  type DecompressionFunction,
} from "../bitstring.js";

// Mock compression functions for testing
class MockCompressor implements CompressionFunction {
  async compress(data: Uint8Array): Promise<Uint8Array> {
    // Simple mock: just return data as-is (no actual compression)
    return data;
  }
}

class MockDecompressor implements DecompressionFunction {
  async decompress(data: Uint8Array): Promise<Uint8Array> {
    // Simple mock: just return data as-is
    return data;
  }
}

describe("BitstringManager", () => {
  let compressor: CompressionFunction;
  let decompressor: DecompressionFunction;

  beforeEach(() => {
    compressor = new MockCompressor();
    decompressor = new MockDecompressor();
  });

  describe("constructor", () => {
    it("should create manager with specified size", () => {
      const manager = new BitstringManager(16, compressor, decompressor);
      expect(manager.getSize()).toBe(16);
    });

    it("should allocate correct number of bytes", () => {
      const manager = new BitstringManager(16, compressor, decompressor);
      // 16 bits = 2 bytes
      expect(manager.getRawBits().length).toBe(2);
    });

    it("should handle size that requires extra byte", () => {
      const manager = new BitstringManager(17, compressor, decompressor);
      // 17 bits = 3 bytes (ceil(17/8) = 3)
      expect(manager.getRawBits().length).toBe(3);
    });
  });

  describe("setBit", () => {
    it("should set bit to 1", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      expect(manager.getBit(0)).toBe(true);
    });

    it("should set bit to 0", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      manager.setBit(0, false);
      expect(manager.getBit(0)).toBe(false);
    });

    it("should set multiple bits independently", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      manager.setBit(2, true);
      manager.setBit(4, true);

      expect(manager.getBit(0)).toBe(true);
      expect(manager.getBit(1)).toBe(false);
      expect(manager.getBit(2)).toBe(true);
      expect(manager.getBit(3)).toBe(false);
      expect(manager.getBit(4)).toBe(true);
    });

    it("should handle bits across byte boundaries", () => {
      const manager = new BitstringManager(16, compressor, decompressor);
      manager.setBit(7, true); // Last bit of first byte
      manager.setBit(8, true); // First bit of second byte

      expect(manager.getBit(7)).toBe(true);
      expect(manager.getBit(8)).toBe(true);
    });

    it("should throw error for negative index", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(() => manager.setBit(-1, true)).toThrow("out of range");
    });

    it("should throw error for index >= size", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(() => manager.setBit(8, true)).toThrow("out of range");
    });
  });

  describe("getBit", () => {
    it("should return false for unset bits", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(manager.getBit(0)).toBe(false);
    });

    it("should return true for set bits", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(3, true);
      expect(manager.getBit(3)).toBe(true);
    });

    it("should throw error for negative index", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(() => manager.getBit(-1)).toThrow("out of range");
    });

    it("should throw error for index >= size", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(() => manager.getBit(8)).toThrow("out of range");
    });
  });

  describe("getSetBits", () => {
    it("should return empty array when no bits are set", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(manager.getSetBits()).toEqual([]);
    });

    it("should return array of set bit indices", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      manager.setBit(2, true);
      manager.setBit(5, true);

      const setBits = manager.getSetBits();
      expect(setBits).toContain(0);
      expect(setBits).toContain(2);
      expect(setBits).toContain(5);
      expect(setBits.length).toBe(3);
    });

    it("should return indices in order", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(5, true);
      manager.setBit(1, true);
      manager.setBit(3, true);

      const setBits = manager.getSetBits();
      expect(setBits).toEqual([1, 3, 5]);
    });
  });

  describe("encode", () => {
    it("should encode bitstring to base64url", async () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      manager.setBit(2, true);

      const encoded = await manager.encode();
      expect(typeof encoded).toBe("string");
      expect(encoded.length).toBeGreaterThan(0);
      // Base64url should not contain +, /, or =
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
      expect(encoded).not.toContain("=");
    });

    it("should produce consistent encoding", async () => {
      const manager1 = new BitstringManager(8, compressor, decompressor);
      manager1.setBit(0, true);
      manager1.setBit(2, true);

      const manager2 = new BitstringManager(8, compressor, decompressor);
      manager2.setBit(0, true);
      manager2.setBit(2, true);

      const encoded1 = await manager1.encode();
      const encoded2 = await manager2.encode();
      expect(encoded1).toBe(encoded2);
    });
  });

  describe("decode", () => {
    it("should decode encoded bitstring", async () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      manager.setBit(2, true);
      manager.setBit(5, true);

      const encoded = await manager.encode();
      const decoded = await BitstringManager.decode(
        encoded,
        compressor,
        decompressor
      );

      expect(decoded.getSize()).toBe(8);
      expect(decoded.getBit(0)).toBe(true);
      expect(decoded.getBit(2)).toBe(true);
      expect(decoded.getBit(5)).toBe(true);
      expect(decoded.getBit(1)).toBe(false);
    });

    it("should handle round-trip encoding/decoding", async () => {
      const original = new BitstringManager(16, compressor, decompressor);
      original.setBit(0, true);
      original.setBit(7, true);
      original.setBit(8, true);
      original.setBit(15, true);

      const encoded = await original.encode();
      const decoded = await BitstringManager.decode(
        encoded,
        compressor,
        decompressor
      );

      expect(decoded.getSize()).toBe(original.getSize());
      for (let i = 0; i < original.getSize(); i++) {
        expect(decoded.getBit(i)).toBe(original.getBit(i));
      }
    });
  });

  describe("fromSetBits", () => {
    it("should create manager from set bit indices", () => {
      const manager = BitstringManager.fromSetBits(
        8,
        [0, 2, 5],
        compressor,
        decompressor
      );

      expect(manager.getSize()).toBe(8);
      expect(manager.getBit(0)).toBe(true);
      expect(manager.getBit(2)).toBe(true);
      expect(manager.getBit(5)).toBe(true);
      expect(manager.getBit(1)).toBe(false);
    });

    it("should handle empty set bits array", () => {
      const manager = BitstringManager.fromSetBits(
        8,
        [],
        compressor,
        decompressor
      );

      expect(manager.getSize()).toBe(8);
      expect(manager.getSetBits()).toEqual([]);
    });

    it("should handle bits across byte boundaries", () => {
      const manager = BitstringManager.fromSetBits(
        16,
        [7, 8, 15],
        compressor,
        decompressor
      );

      expect(manager.getBit(7)).toBe(true);
      expect(manager.getBit(8)).toBe(true);
      expect(manager.getBit(15)).toBe(true);
    });
  });

  describe("getRawBits", () => {
    it("should return raw byte array", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      const raw = manager.getRawBits();

      expect(raw).toBeInstanceOf(Uint8Array);
      expect(raw.length).toBe(1); // 8 bits = 1 byte
    });

    it("should return reference to internal bits array", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      const raw1 = manager.getRawBits();
      manager.setBit(0, true);
      const raw2 = manager.getRawBits();

      // getRawBits returns a reference, so raw1 and raw2 are the same array
      expect(raw1).toBe(raw2);
      // Setting a bit should change the raw bits (same reference)
      expect(raw1[0]).toBe(raw2[0]);
      expect(raw1[0]).not.toBe(0); // Bit 0 is now set
    });
  });

  describe("getSize", () => {
    it("should return correct size", () => {
      const manager = new BitstringManager(32, compressor, decompressor);
      expect(manager.getSize()).toBe(32);
    });
  });
});

describe("isIndexSet", () => {
  let decompressor: DecompressionFunction;

  beforeEach(() => {
    decompressor = new MockDecompressor();
  });

  it("should return true for set bit", async () => {
    const manager = new BitstringManager(8, new MockCompressor(), decompressor);
    manager.setBit(3, true);
    const encoded = await manager.encode();

    const result = await isIndexSet(encoded, 3, decompressor);
    expect(result).toBe(true);
  });

  it("should return false for unset bit", async () => {
    const manager = new BitstringManager(8, new MockCompressor(), decompressor);
    manager.setBit(0, true);
    manager.setBit(2, true);
    const encoded = await manager.encode();

    const result = await isIndexSet(encoded, 1, decompressor);
    expect(result).toBe(false);
  });

  it("should return false for out of range index", async () => {
    const manager = new BitstringManager(8, new MockCompressor(), decompressor);
    const encoded = await manager.encode();

    const result = await isIndexSet(encoded, 100, decompressor);
    expect(result).toBe(false);
  });

  it("should handle multiple bits", async () => {
    const manager = new BitstringManager(16, new MockCompressor(), decompressor);
    manager.setBit(0, true);
    manager.setBit(7, true);
    manager.setBit(8, true);
    manager.setBit(15, true);
    const encoded = await manager.encode();

    expect(await isIndexSet(encoded, 0, decompressor)).toBe(true);
    expect(await isIndexSet(encoded, 7, decompressor)).toBe(true);
    expect(await isIndexSet(encoded, 8, decompressor)).toBe(true);
    expect(await isIndexSet(encoded, 15, decompressor)).toBe(true);
    expect(await isIndexSet(encoded, 1, decompressor)).toBe(false);
  });
});


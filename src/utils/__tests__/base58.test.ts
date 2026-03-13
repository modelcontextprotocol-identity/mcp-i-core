/**
 * Tests for Base58 Utilities
 */

import { describe, it, expect } from "vitest";
import { base58Encode, base58Decode, isValidBase58 } from "../base58.js";

describe("Base58 Utilities", () => {
  describe("base58Encode", () => {
    it("should encode bytes to Base58", () => {
      const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const encoded = base58Encode(bytes);

      expect(encoded).toBeDefined();
      expect(typeof encoded).toBe("string");
      expect(encoded.length).toBeGreaterThan(0);
    });

    it("should encode empty bytes to empty string", () => {
      const bytes = new Uint8Array(0);
      const encoded = base58Encode(bytes);

      expect(encoded).toBe("");
    });

    it("should encode single byte", () => {
      const bytes = new Uint8Array([42]);
      const encoded = base58Encode(bytes);

      expect(encoded).toBeDefined();
      expect(encoded.length).toBeGreaterThan(0);
    });

    it("should encode bytes with leading zeros", () => {
      const bytes = new Uint8Array([0, 0, 1, 2, 3]);
      const encoded = base58Encode(bytes);

      // Leading zeros should be encoded as '1'
      expect(encoded.startsWith("1")).toBe(true);
    });

    it("should encode all zero bytes", () => {
      const bytes = new Uint8Array([0, 0, 0]);
      const encoded = base58Encode(bytes);

      expect(encoded).toBeDefined();
      // All zeros should result in multiple '1' characters
      expect(encoded.length).toBeGreaterThan(0);
    });

    it("should produce deterministic output", () => {
      const bytes = new Uint8Array([1, 2, 3, 4, 5]);
      const encoded1 = base58Encode(bytes);
      const encoded2 = base58Encode(bytes);

      expect(encoded1).toBe(encoded2);
    });
  });

  describe("base58Decode", () => {
    it("should decode Base58 to bytes", () => {
      const original = new Uint8Array([72, 101, 108, 108, 111]);
      const encoded = base58Encode(original);
      const decoded = base58Decode(encoded);

      expect(decoded).toEqual(original);
    });

    it("should decode empty string to empty bytes", () => {
      const decoded = base58Decode("");

      expect(decoded).toEqual(new Uint8Array(0));
    });

    it("should decode string with leading '1' characters", () => {
      // Leading '1' characters represent leading zeros
      const encoded = "11ABC";
      const decoded = base58Decode(encoded);

      expect(decoded).toBeDefined();
      expect(decoded[0]).toBe(0);
      expect(decoded[1]).toBe(0);
    });

    it("should round-trip encode and decode", () => {
      const testCases = [
        new Uint8Array([1, 2, 3]),
        new Uint8Array([255, 255, 255]),
        new Uint8Array([0, 1, 2]),
        new Uint8Array([128, 64, 32]),
      ];

      for (const bytes of testCases) {
        const encoded = base58Encode(bytes);
        const decoded = base58Decode(encoded);

        expect(decoded).toEqual(bytes);
      }
    });

    it("should throw error for invalid Base58 character", () => {
      expect(() => {
        base58Decode("invalid@base58");
      }).toThrow("Invalid base58 character");
    });

    it("should throw error for character '0'", () => {
      expect(() => {
        base58Decode("ABC0DEF");
      }).toThrow("Invalid base58 character");
    });

    it("should throw error for character 'O'", () => {
      expect(() => {
        base58Decode("ABCODEF");
      }).toThrow("Invalid base58 character");
    });

    it("should throw error for character 'I'", () => {
      expect(() => {
        base58Decode("ABCDIEF");
      }).toThrow("Invalid base58 character");
    });

    it("should throw error for character 'l'", () => {
      expect(() => {
        base58Decode("ABCDlEF");
      }).toThrow("Invalid base58 character");
    });
  });

  describe("isValidBase58", () => {
    it("should return true for valid Base58 string", () => {
      const valid = base58Encode(new Uint8Array([1, 2, 3]));
      expect(isValidBase58(valid)).toBe(true);
    });

    it("should return true for empty string", () => {
      expect(isValidBase58("")).toBe(true);
    });

    it("should return false for string with invalid character '0'", () => {
      expect(isValidBase58("ABC0DEF")).toBe(false);
    });

    it("should return false for string with invalid character 'O'", () => {
      expect(isValidBase58("ABCODEF")).toBe(false);
    });

    it("should return false for string with invalid character 'I'", () => {
      expect(isValidBase58("ABCDIEF")).toBe(false);
    });

    it("should return false for string with invalid character 'l'", () => {
      expect(isValidBase58("ABCDlEF")).toBe(false);
    });

    it("should return false for string with special characters", () => {
      expect(isValidBase58("ABC@DEF")).toBe(false);
      expect(isValidBase58("ABC-DEF")).toBe(false);
      expect(isValidBase58("ABC DEF")).toBe(false);
    });

    it("should return true for all valid Base58 characters", () => {
      const validChars =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
      expect(isValidBase58(validChars)).toBe(true);
    });

    it("should return true for string with only '1' characters", () => {
      expect(isValidBase58("1111")).toBe(true);
    });
  });

  describe("Edge Cases", () => {
    it("should handle large byte arrays", () => {
      const largeArray = new Uint8Array(100);
      for (let i = 0; i < 100; i++) {
        largeArray[i] = i % 256;
      }

      const encoded = base58Encode(largeArray);
      const decoded = base58Decode(encoded);

      expect(decoded).toEqual(largeArray);
    });

    it("should handle bytes with maximum values", () => {
      const maxBytes = new Uint8Array([255, 255, 255, 255]);
      const encoded = base58Encode(maxBytes);
      const decoded = base58Decode(encoded);

      expect(decoded).toEqual(maxBytes);
    });

    it("should handle single byte encoding/decoding", () => {
      for (let i = 0; i < 256; i++) {
        const bytes = new Uint8Array([i]);
        const encoded = base58Encode(bytes);
        const decoded = base58Decode(encoded);

        expect(decoded).toEqual(bytes);
      }
    });

    it("should handle mixed leading zeros and non-zero bytes", () => {
      const testCases = [
        new Uint8Array([0, 1]),
        new Uint8Array([0, 0, 1]),
        new Uint8Array([0, 255]),
        new Uint8Array([0, 0, 0, 1, 2, 3]),
      ];

      for (const bytes of testCases) {
        const encoded = base58Encode(bytes);
        const decoded = base58Decode(encoded);

        expect(decoded).toEqual(bytes);
      }
    });

    it("should produce shorter output for small values", () => {
      const small = new Uint8Array([1]);
      const large = new Uint8Array([255, 255, 255]);

      const smallEncoded = base58Encode(small);
      const largeEncoded = base58Encode(large);

      // Small values should produce shorter Base58 strings
      expect(smallEncoded.length).toBeLessThan(largeEncoded.length);
    });
  });

  describe("Real-world DID:key Examples", () => {
    it("should encode/decode Ed25519 public key bytes", () => {
      // Example Ed25519 public key (32 bytes)
      const ed25519Key = new Uint8Array([
        0xed,
        0x01, // Ed25519 multicodec prefix
        0x12,
        0x34,
        0x56,
        0x78,
        0x9a,
        0xbc,
        0xde,
        0xf0,
        0x12,
        0x34,
        0x56,
        0x78,
        0x9a,
        0xbc,
        0xde,
        0xf0,
        0x12,
        0x34,
        0x56,
        0x78,
        0x9a,
        0xbc,
        0xde,
        0xf0,
        0x12,
        0x34,
        0x56,
        0x78,
        0x9a,
        0xbc,
        0xde,
        0xf0,
      ]);

      const encoded = base58Encode(ed25519Key);
      expect(isValidBase58(encoded)).toBe(true);

      const decoded = base58Decode(encoded);
      expect(decoded).toEqual(ed25519Key);
    });
  });
});

import { describe, it, expect } from "vitest";
import {
  createDidKeyResolver,
  isEd25519DidKey,
  extractPublicKeyFromDidKey,
  publicKeyToJwk,
  resolveDidKeySync,
} from "../did-key-resolver";
import { base58Encode, base58Decode, isValidBase58 } from "../../utils/base58";

/**
 * Tests for did:key resolver and base58 utilities
 *
 * These tests verify the Phase 3 VC verification infrastructure:
 * - Base58 encoding/decoding for multibase keys
 * - did:key resolution to DID Documents
 * - Ed25519 public key extraction
 */

describe("Base58 Utilities", () => {
  describe("base58Encode", () => {
    it("should encode empty bytes", () => {
      expect(base58Encode(new Uint8Array([]))).toBe("");
    });

    it("should encode single byte", () => {
      expect(base58Encode(new Uint8Array([0]))).toBe("1");
      expect(base58Encode(new Uint8Array([1])).length).toBeGreaterThan(0);
    });

    it("should encode known values", () => {
      // 'Hello' in bytes
      const helloBytes = new TextEncoder().encode("Hello");
      const encoded = base58Encode(helloBytes);
      expect(encoded.length).toBeGreaterThan(0);
      expect(isValidBase58(encoded)).toBe(true);
    });

    it("should handle leading zeros", () => {
      const withLeadingZeros = new Uint8Array([0, 0, 1, 2, 3]);
      const encoded = base58Encode(withLeadingZeros);
      // Leading zeros become '1' in base58
      expect(encoded.startsWith("11")).toBe(true);
    });
  });

  describe("base58Decode", () => {
    it("should decode empty string", () => {
      expect(base58Decode("")).toEqual(new Uint8Array([]));
    });

    it("should decode leading '1' as zero bytes", () => {
      const result = base58Decode("111");
      expect(result).toEqual(new Uint8Array([0, 0, 0]));
    });

    it("should throw on invalid characters", () => {
      // '0', 'O', 'I', 'l' are not in base58 alphabet
      expect(() => base58Decode("0invalid")).toThrow("Invalid base58 character");
      expect(() => base58Decode("testO")).toThrow("Invalid base58 character");
      expect(() => base58Decode("testI")).toThrow("Invalid base58 character");
      expect(() => base58Decode("testl")).toThrow("Invalid base58 character");
    });

    it("should roundtrip with base58Encode", () => {
      const originalBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const encoded = base58Encode(originalBytes);
      const decoded = base58Decode(encoded);
      expect(decoded).toEqual(originalBytes);
    });

    it("should roundtrip Ed25519 key bytes", () => {
      // Simulate a 32-byte Ed25519 public key with multicodec prefix
      const ed25519Prefix = new Uint8Array([0xed, 0x01]);
      const mockPublicKey = new Uint8Array(32).fill(42);
      const fullBytes = new Uint8Array([...ed25519Prefix, ...mockPublicKey]);

      const encoded = base58Encode(fullBytes);
      const decoded = base58Decode(encoded);
      expect(decoded).toEqual(fullBytes);
    });
  });

  describe("isValidBase58", () => {
    it("should return true for empty string", () => {
      expect(isValidBase58("")).toBe(true);
    });

    it("should return true for valid base58 strings", () => {
      expect(isValidBase58("123456789")).toBe(true);
      expect(isValidBase58("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")).toBe(true);
    });

    it("should return false for invalid characters", () => {
      expect(isValidBase58("0")).toBe(false);
      expect(isValidBase58("O")).toBe(false);
      expect(isValidBase58("I")).toBe(false);
      expect(isValidBase58("l")).toBe(false);
    });
  });
});

describe("did:key Resolver", () => {
  // Known test vector for Ed25519 did:key
  // This creates a deterministic did:key from known public key bytes
  const createTestDidKey = (publicKeyBytes: Uint8Array): string => {
    const prefix = new Uint8Array([0xed, 0x01]); // Ed25519 multicodec
    const fullBytes = new Uint8Array([...prefix, ...publicKeyBytes]);
    return `did:key:z${base58Encode(fullBytes)}`;
  };

  describe("isEd25519DidKey", () => {
    it("should return true for Ed25519 did:key", () => {
      // Ed25519 keys start with z6Mk
      expect(isEd25519DidKey("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")).toBe(true);
    });

    it("should return false for non-did:key", () => {
      expect(isEd25519DidKey("did:web:example.com")).toBe(false);
      expect(isEd25519DidKey("did:example:123")).toBe(false);
    });

    it("should return false for non-Ed25519 did:key", () => {
      // Secp256k1 keys start with z6Ls or other prefixes
      expect(isEd25519DidKey("did:key:z7r8os")).toBe(false);
      expect(isEd25519DidKey("did:key:zQ3s")).toBe(false);
    });

    it("should return false for invalid did:key format", () => {
      expect(isEd25519DidKey("did:key:")).toBe(false);
      expect(isEd25519DidKey("did:key:invalid")).toBe(false);
    });
  });

  describe("extractPublicKeyFromDidKey", () => {
    it("should extract public key bytes from valid did:key", () => {
      const mockPublicKey = new Uint8Array(32).map((_, i) => i);
      const didKey = createTestDidKey(mockPublicKey);

      const extractedKey = extractPublicKeyFromDidKey(didKey);
      expect(extractedKey).not.toBeNull();
      expect(extractedKey).toEqual(mockPublicKey);
    });

    it("should return null for non-did:key", () => {
      expect(extractPublicKeyFromDidKey("did:web:example.com")).toBeNull();
    });

    it("should return null for invalid multicodec prefix", () => {
      // Create a did:key with wrong prefix (not Ed25519)
      const wrongPrefix = new Uint8Array([0x00, 0x00]); // Not Ed25519
      const mockPublicKey = new Uint8Array(32).fill(1);
      const fullBytes = new Uint8Array([...wrongPrefix, ...mockPublicKey]);
      const invalidDid = `did:key:z${base58Encode(fullBytes)}`;

      expect(extractPublicKeyFromDidKey(invalidDid)).toBeNull();
    });

    it("should return null for too short key", () => {
      const shortBytes = new Uint8Array([0xed, 0x01, 1, 2, 3]); // Only 3 bytes of key
      const shortDid = `did:key:z${base58Encode(shortBytes)}`;

      expect(extractPublicKeyFromDidKey(shortDid)).toBeNull();
    });
  });

  describe("publicKeyToJwk", () => {
    it("should convert public key bytes to JWK format", () => {
      const publicKeyBytes = new Uint8Array(32).map((_, i) => i);
      const jwk = publicKeyToJwk(publicKeyBytes);

      expect(jwk.kty).toBe("OKP");
      expect(jwk.crv).toBe("Ed25519");
      expect(jwk.x).toBeDefined();
      expect(typeof jwk.x).toBe("string");
    });

    it("should produce base64url-encoded x value", () => {
      const publicKeyBytes = new Uint8Array(32).fill(0);
      const jwk = publicKeyToJwk(publicKeyBytes);

      // Base64url should not contain +, /, or =
      expect(jwk.x).not.toMatch(/[+/=]/);
    });
  });

  describe("createDidKeyResolver", () => {
    it("should resolve Ed25519 did:key to DID Document", async () => {
      const mockPublicKey = new Uint8Array(32).map((_, i) => i);
      const didKey = createTestDidKey(mockPublicKey);

      const resolver = createDidKeyResolver();
      const didDoc = await resolver.resolve(didKey);

      expect(didDoc).not.toBeNull();
      expect(didDoc?.id).toBe(didKey);
      expect(didDoc?.verificationMethod).toHaveLength(1);
      expect(didDoc?.verificationMethod?.[0].type).toBe("Ed25519VerificationKey2020");
      expect(didDoc?.verificationMethod?.[0].controller).toBe(didKey);
      expect(didDoc?.verificationMethod?.[0].publicKeyJwk).toBeDefined();
      expect(didDoc?.authentication).toContain(`${didKey}#keys-1`);
      expect(didDoc?.assertionMethod).toContain(`${didKey}#keys-1`);
    });

    it("should return null for non-Ed25519 did:key", async () => {
      const resolver = createDidKeyResolver();
      const result = await resolver.resolve("did:key:z7r8os");

      expect(result).toBeNull();
    });

    it("should return null for non-did:key DIDs", async () => {
      const resolver = createDidKeyResolver();
      const result = await resolver.resolve("did:web:example.com");

      expect(result).toBeNull();
    });
  });

  describe("resolveDidKeySync", () => {
    it("should synchronously resolve Ed25519 did:key", () => {
      const mockPublicKey = new Uint8Array(32).map((_, i) => i);
      const didKey = createTestDidKey(mockPublicKey);

      const didDoc = resolveDidKeySync(didKey);

      expect(didDoc).not.toBeNull();
      expect(didDoc?.id).toBe(didKey);
      expect(didDoc?.verificationMethod).toHaveLength(1);
    });

    it("should return null for invalid DIDs", () => {
      expect(resolveDidKeySync("did:web:example.com")).toBeNull();
      expect(resolveDidKeySync("did:key:invalid")).toBeNull();
    });
  });
});

describe("VC-JWT Roundtrip Integration", () => {
  it("should correctly resolve did:key generated by UserDidManager pattern", async () => {
    // This test simulates the pattern used in UserDidManager.generateKeyPair()
    // which creates did:key DIDs for users

    // Simulate generating a random Ed25519 key (32 bytes)
    const mockPublicKey = crypto.getRandomValues(new Uint8Array(32));

    // Encode as did:key (same pattern as UserDidManager)
    const multicodecPrefix = new Uint8Array([0xed, 0x01]);
    const multicodecBytes = new Uint8Array([...multicodecPrefix, ...mockPublicKey]);
    const multibaseEncoded = base58Encode(multicodecBytes);
    const didKey = `did:key:z${multibaseEncoded}`;

    // Verify we can resolve this did:key back to get the public key
    const resolver = createDidKeyResolver();
    const didDoc = await resolver.resolve(didKey);

    expect(didDoc).not.toBeNull();
    expect(didDoc?.id).toBe(didKey);
    expect(didDoc?.verificationMethod?.[0]?.publicKeyJwk).toBeDefined();

    // Extract public key and verify it matches
    const extractedKey = extractPublicKeyFromDidKey(didKey);
    expect(extractedKey).toEqual(mockPublicKey);
  });
});

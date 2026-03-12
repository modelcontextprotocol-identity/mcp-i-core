/**
 * Ed25519 Key Format Constants
 *
 * DER-encoded headers for Ed25519 key formats per RFC 8410 and RFC 5958.
 */

/**
 * DER-encoded PKCS#8 header for Ed25519 private keys (RFC 8410 §7, RFC 5958).
 * Prepended to the 32-byte Ed25519 seed to form a valid PKCS#8 private key.
 */
export const ED25519_PKCS8_DER_HEADER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
  0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * DER-encoded SPKI header for Ed25519 public keys (RFC 8410 §4).
 * The 32-byte public key follows after this header.
 */
export const ED25519_SPKI_DER_HEADER_LENGTH = 12;

/** Ed25519 raw key size in bytes */
export const ED25519_KEY_SIZE = 32;

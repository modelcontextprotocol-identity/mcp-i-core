/**
 * Base58 Utilities (Bitcoin alphabet)
 *
 * Encoding and decoding utilities for Base58 (Bitcoin alphabet).
 * Used for did:key multibase encoding (with 'z' prefix for base58btc).
 *
 * The Bitcoin alphabet excludes ambiguous characters (0, O, I, l).
 */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ALPHABET_MAP = new Map<string, number>();

// Build reverse lookup map
for (let i = 0; i < ALPHABET.length; i++) {
  const char = ALPHABET[i];
  if (char !== undefined) {
    ALPHABET_MAP.set(char, i);
  }
}

/**
 * Encode bytes to Base58 (Bitcoin alphabet)
 *
 * @param bytes - Bytes to encode
 * @returns Base58-encoded string
 */
export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Convert bytes to big integer
  let num = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte !== undefined) {
      num = num * BigInt(256) + BigInt(byte);
    }
  }

  // Convert to base58
  let result = '';
  while (num > 0) {
    result = ALPHABET[Number(num % BigInt(58))] + result;
    num = num / BigInt(58);
  }

  // Add leading zeros (encoded as '1' in base58)
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    result = '1' + result;
  }

  return result;
}

/**
 * Decode Base58 (Bitcoin alphabet) to bytes
 *
 * @param encoded - Base58-encoded string
 * @returns Decoded bytes
 * @throws Error if input contains invalid characters
 */
export function base58Decode(encoded: string): Uint8Array {
  if (encoded.length === 0) return new Uint8Array(0);

  // Convert base58 to big integer
  let num = BigInt(0);
  for (const char of encoded) {
    const value = ALPHABET_MAP.get(char);
    if (value === undefined) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    num = num * BigInt(58) + BigInt(value);
  }

  // Convert big integer to bytes
  const bytes: number[] = [];
  while (num > 0) {
    bytes.unshift(Number(num % BigInt(256)));
    num = num / BigInt(256);
  }

  // Count leading zeros in input (encoded as '1')
  let leadingZeros = 0;
  for (const char of encoded) {
    if (char === '1') {
      leadingZeros++;
    } else {
      break;
    }
  }

  // Prepend leading zero bytes
  const result = new Uint8Array(leadingZeros + bytes.length);
  // Leading zeros are already 0 in Uint8Array
  result.set(bytes, leadingZeros);

  return result;
}

/**
 * Validate a Base58 string
 *
 * @param encoded - String to validate
 * @returns true if valid Base58, false otherwise
 */
export function isValidBase58(encoded: string): boolean {
  if (encoded.length === 0) return true;

  for (const char of encoded) {
    if (!ALPHABET_MAP.has(char)) {
      return false;
    }
  }

  return true;
}

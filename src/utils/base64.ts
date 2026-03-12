/**
 * Base64URL Encoding/Decoding Utilities
 *
 * Environment-aware base64url helpers that work in both Node.js and Cloudflare Workers.
 * Uses Buffer in Node.js, TextEncoder/Decoder fallback for Workers.
 */

export function base64urlDecodeToString(input: string): string {
  const padded = addPadding(input);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');

  if (typeof Buffer !== 'undefined') {
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(base64)) {
      throw new Error('Invalid base64url string: contains invalid characters');
    }
    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  if (typeof atob !== 'undefined') {
    const binaryString = atob(base64);
    if (typeof TextDecoder !== 'undefined') {
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return new TextDecoder().decode(bytes);
    }
    return binaryString;
  }

  throw new Error('Neither Buffer nor atob is available');
}

export function base64urlDecodeToBytes(input: string): Uint8Array {
  const padded = addPadding(input);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');

  if (typeof atob !== 'undefined') {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }

  return new Uint8Array(Buffer.from(base64, 'base64'));
}

export function base64urlEncodeFromString(input: string): string {
  if (typeof Buffer !== 'undefined') {
    const base64 = Buffer.from(input, 'utf-8').toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  if (typeof btoa !== 'undefined') {
    const utf8Bytes = new TextEncoder().encode(input);
    const binaryString = Array.from(utf8Bytes)
      .map((byte) => String.fromCharCode(byte))
      .join('');
    const base64 = btoa(binaryString);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  throw new Error('Neither Buffer nor btoa is available');
}

export function base64urlEncodeFromBytes(bytes: Uint8Array): string {
  if (typeof btoa !== 'undefined') {
    const binaryString = Array.from(bytes)
      .map((byte) => String.fromCharCode(byte))
      .join('');
    const base64 = btoa(binaryString);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  const base64 = Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa !== 'undefined') {
    const binaryString = Array.from(bytes)
      .map((byte) => String.fromCharCode(byte))
      .join('');
    return btoa(binaryString);
  }

  return Buffer.from(bytes).toString('base64');
}

export function base64ToBytes(base64: string): Uint8Array {
  let standardBase64 = base64.replace(/-/g, '+').replace(/_/g, '/');
  const paddingNeeded = (4 - (standardBase64.length % 4)) % 4;
  standardBase64 += '='.repeat(paddingNeeded);

  if (typeof atob !== 'undefined') {
    const binaryString = atob(standardBase64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }

  return new Uint8Array(Buffer.from(standardBase64, 'base64'));
}

function addPadding(input: string): string {
  const remainder = input.length % 4;
  if (remainder === 0) {
    return input;
  }
  return input + '='.repeat((4 - remainder) % 4);
}

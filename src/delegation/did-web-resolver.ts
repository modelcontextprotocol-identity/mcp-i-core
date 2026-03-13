/**
 * DID:web Resolver
 *
 * Resolves did:web DIDs by fetching /.well-known/did.json from the domain.
 * Supports both root domain DIDs and path-based DIDs.
 *
 * Examples:
 *   did:web:example.com → https://example.com/.well-known/did.json
 *   did:web:example.com:agents:bot1 → https://example.com/agents/bot1/did.json
 *
 * @see https://w3c-ccg.github.io/did-method-web/
 */

import type { FetchProvider } from '../providers/base.js';
import type { DIDResolver, DIDDocument, VerificationMethod } from './vc-verifier.js';
import { logger } from '../logging/index.js';

/**
 * Parsed components of a did:web DID
 */
interface ParsedDidWeb {
  domain: string;
  path: string[];
}

/**
 * Type guard for checking if value is a valid DID Document structure
 */
function isValidDIDDocument(value: unknown): value is DIDDocument {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const doc = value as Record<string, unknown>;

  // id is required and must be a string
  if (typeof doc['id'] !== 'string' || doc['id'].length === 0) {
    return false;
  }

  // verificationMethod is optional but if present must be an array
  if (doc['verificationMethod'] !== undefined) {
    if (!Array.isArray(doc['verificationMethod'])) {
      return false;
    }

    // Each verification method must have required fields
    for (const vm of doc['verificationMethod']) {
      if (!isValidVerificationMethod(vm)) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Type guard for checking if value is a valid VerificationMethod
 */
function isValidVerificationMethod(value: unknown): value is VerificationMethod {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const vm = value as Record<string, unknown>;

  // id, type, and controller are required strings
  if (typeof vm['id'] !== 'string' || vm['id'].length === 0) {
    return false;
  }
  if (typeof vm['type'] !== 'string' || vm['type'].length === 0) {
    return false;
  }
  if (typeof vm['controller'] !== 'string' || vm['controller'].length === 0) {
    return false;
  }

  return true;
}

/**
 * Check if a DID is a did:web DID
 *
 * @param did - The DID to check
 * @returns true if it's a did:web DID
 */
export function isDidWeb(did: string): boolean {
  return did.startsWith('did:web:');
}

/**
 * Parse a did:web DID into its components
 *
 * @param did - The did:web DID to parse
 * @returns Parsed components or null if invalid
 */
export function parseDidWeb(did: string): ParsedDidWeb | null {
  if (!isDidWeb(did)) {
    return null;
  }

  // Remove the 'did:web:' prefix
  const remainder = did.slice(8);

  if (remainder.length === 0) {
    return null;
  }

  // Split by ':' to get domain and path components
  const parts = remainder.split(':');

  // First part is the domain (URL-decoded)
  const domain = decodeURIComponent(parts[0]!);

  if (domain.length === 0) {
    return null;
  }

  // Remaining parts form the path
  const path = parts.slice(1).map((p) => decodeURIComponent(p));

  return { domain, path };
}

/**
 * Convert a did:web DID to its resolution URL
 *
 * did:web:example.com → https://example.com/.well-known/did.json
 * did:web:example.com:path:to:doc → https://example.com/path/to/doc/did.json
 *
 * @param did - The did:web DID
 * @returns The resolution URL or null if invalid
 */
export function didWebToUrl(did: string): string | null {
  const parsed = parseDidWeb(did);

  if (!parsed) {
    return null;
  }

  const { domain, path } = parsed;

  // Build the URL
  // Note: did:web specification requires HTTPS
  let url = `https://${domain}`;

  if (path.length === 0) {
    // Root domain: use /.well-known/did.json
    url += '/.well-known/did.json';
  } else {
    // Path-based: use /path/to/resource/did.json
    url += '/' + path.join('/') + '/did.json';
  }

  return url;
}

/**
 * DID:web resolver implementation
 */
export class DidWebResolver implements DIDResolver {
  private fetchProvider: FetchProvider;
  private cache: Map<string, { document: DIDDocument; expiresAt: number }>;
  private cacheTtl: number;

  constructor(fetchProvider: FetchProvider, options?: { cacheTtl?: number }) {
    this.fetchProvider = fetchProvider;
    this.cache = new Map();
    this.cacheTtl = options?.cacheTtl ?? 300_000; // 5 minutes default
  }

  /**
   * Resolve a did:web DID to its DID Document
   *
   * @param did - The did:web DID to resolve
   * @returns The DID Document or null if resolution fails
   */
  async resolve(did: string): Promise<DIDDocument | null> {
    // Check if it's a did:web
    if (!isDidWeb(did)) {
      return null;
    }

    // Check cache
    const cached = this.cache.get(did);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.document;
    }

    // Convert to URL
    const url = didWebToUrl(did);
    if (!url) {
      logger.warn(`[DidWebResolver] Invalid did:web format: ${did}`);
      return null;
    }

    try {
      // Fetch the DID document
      const response = await this.fetchProvider.fetch(url);

      if (!response.ok) {
        logger.warn(`[DidWebResolver] HTTP ${response.status} fetching ${url}`);
        return null;
      }

      // Parse JSON
      let json: unknown;
      try {
        json = await response.json();
      } catch {
        logger.warn(`[DidWebResolver] Invalid JSON from ${url}`);
        return null;
      }

      // Validate structure
      if (!isValidDIDDocument(json)) {
        logger.warn(`[DidWebResolver] Invalid DID Document structure from ${url}`);
        return null;
      }

      // Verify the id matches the DID
      if (json.id !== did) {
        logger.warn(`[DidWebResolver] DID Document id mismatch: expected ${did}, got ${json.id}`);
        return null;
      }

      // Cache the result
      this.cache.set(did, {
        document: json,
        expiresAt: Date.now() + this.cacheTtl,
      });

      return json;
    } catch (error) {
      logger.warn(
        `[DidWebResolver] Error resolving ${did}: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      return null;
    }
  }

  /**
   * Clear the resolution cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Clear a specific entry from the cache
   */
  clearCacheEntry(did: string): void {
    this.cache.delete(did);
  }
}

/**
 * Create a did:web resolver with the given fetch provider
 *
 * @param fetchProvider - Provider for making HTTP requests
 * @param options - Optional configuration
 * @returns DIDResolver implementation for did:web
 */
export function createDidWebResolver(
  fetchProvider: FetchProvider,
  options?: { cacheTtl?: number }
): DIDResolver {
  return new DidWebResolver(fetchProvider, options);
}

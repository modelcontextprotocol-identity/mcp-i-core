import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  verifyOrHints,
  MemoryResumeTokenStore,
  type AuthHandshakeConfig,
} from '../handshake.js';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function createConfig(overrides?: {
  minReputationScore?: number;
  unknownAgentPolicy?: 'deny' | 'require-consent' | 'allow';
  reputationApiUrl?: string;
}): AuthHandshakeConfig {
  return {
    delegationVerifier: {
      verify: vi.fn().mockResolvedValue({ valid: false, reason: 'No delegation' }),
    },
    resumeTokenStore: new MemoryResumeTokenStore(),
    reputationService: {
      apiUrl: overrides?.reputationApiUrl ?? 'https://reputation.example.com',
    },
    authorization: {
      authorizationUrl: 'https://example.com/consent',
      minReputationScore: overrides?.minReputationScore ?? 30,
      unknownAgentPolicy: overrides?.unknownAgentPolicy,
    },
  };
}

function mockReputationResponse(score: number, status = 200) {
  mockFetch.mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: async () => ({ score }),
  });
}

function mockReputationNotFound() {
  mockFetch.mockResolvedValueOnce({
    ok: false,
    status: 404,
    statusText: 'Not Found',
  });
}

function mockReputationNetworkError() {
  mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));
}

describe('verifyOrHints — unknownAgentPolicy', () => {
  const agentDid = 'did:key:z6MkTest';
  const scopes = ['read:data'];

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('known agents (reputation service returns a score)', () => {
    it('should reject known agent with score below threshold', async () => {
      const config = createConfig({ minReputationScore: 30 });
      mockReputationResponse(10);

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Low reputation score');
      expect(result.reputation?.score).toBe(10);
    });

    it('should allow known agent with score above threshold to proceed to delegation', async () => {
      const config = createConfig({ minReputationScore: 30 });
      mockReputationResponse(80);

      const result = await verifyOrHints(agentDid, scopes, config);

      // Not authorized (no delegation), but passed reputation gate
      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('No delegation');
      expect(result.reputation?.score).toBe(80);
    });
  });

  describe('unknown agents (404 from reputation service)', () => {
    it('should deny unknown agent when policy is "deny"', async () => {
      const config = createConfig({ unknownAgentPolicy: 'deny' });
      mockReputationNotFound();

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Unknown agent — policy: deny');
      expect(result.reputation?.score).toBeNull();
    });

    it('should require consent for unknown agent when policy is "require-consent"', async () => {
      const config = createConfig({ unknownAgentPolicy: 'require-consent' });
      mockReputationNotFound();

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Unknown agent — policy: require-consent');
      expect(result.authError).toBeDefined();
      expect(result.reputation?.score).toBeNull();
    });

    it('should default to "require-consent" when no policy is set', async () => {
      const config = createConfig(); // no unknownAgentPolicy
      mockReputationNotFound();

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Unknown agent — policy: require-consent');
    });

    it('should allow unknown agent when policy is "allow"', async () => {
      const config = createConfig({ unknownAgentPolicy: 'allow' });
      mockReputationNotFound();

      const result = await verifyOrHints(agentDid, scopes, config);

      // Not authorized (no delegation), but passed reputation gate
      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('No delegation');
      expect(result.reputation?.score).toBeNull();
    });
  });

  describe('reputation service unreachable (network error)', () => {
    it('should treat network errors as unknown agent', async () => {
      const config = createConfig({ unknownAgentPolicy: 'deny' });
      mockReputationNetworkError();

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Unknown agent — policy: deny');
      expect(result.reputation?.score).toBeNull();
      expect(result.reputation?.riskLevel).toBe('unknown');
    });

    it('should route to consent on network error with default policy', async () => {
      const config = createConfig(); // default = require-consent
      mockReputationNetworkError();

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('Unknown agent — policy: require-consent');
      expect(result.authError).toBeDefined();
    });

    it('should allow through on network error when policy is "allow"', async () => {
      const config = createConfig({ unknownAgentPolicy: 'allow' });
      mockReputationNetworkError();

      const result = await verifyOrHints(agentDid, scopes, config);

      // Passes reputation gate, fails on delegation
      expect(result.authorized).toBe(false);
      expect(result.reason).toBe('No delegation');
    });
  });

  describe('no reputation service configured', () => {
    it('should skip reputation check entirely when no service configured', async () => {
      const config: AuthHandshakeConfig = {
        delegationVerifier: {
          verify: vi.fn().mockResolvedValue({ valid: false, reason: 'No delegation' }),
        },
        resumeTokenStore: new MemoryResumeTokenStore(),
        // No reputationService
        authorization: {
          authorizationUrl: 'https://example.com/consent',
          minReputationScore: 30,
        },
      };

      const result = await verifyOrHints(agentDid, scopes, config);

      expect(result.reputation).toBeUndefined();
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });
});

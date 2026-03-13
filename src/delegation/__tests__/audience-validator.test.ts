/**
 * Tests for Delegation Audience Validation
 */

import { describe, it, expect } from "vitest";
import { verifyDelegationAudience } from "../audience-validator.js";
import type { DelegationRecord } from "../../types/protocol.js";

describe("verifyDelegationAudience", () => {
  const serverDid = "did:web:server.example.com";

  it("should return true when delegation has no audience", () => {
    const delegation: DelegationRecord = {
      id: "del_001",
      issuerDid: "did:web:user.com",
      subjectDid: "did:key:zagent123",
      controller: "user_alice",
      vcId: "vc_001",
      constraints: {
        scopes: ["tool:execute"],
        // No audience field
      },
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600000,
    };

    expect(verifyDelegationAudience(delegation, serverDid)).toBe(true);
  });

  it("should return true when delegation audience matches server DID", () => {
    const delegation: DelegationRecord = {
      id: "del_002",
      issuerDid: "did:web:user.com",
      subjectDid: "did:key:zagent123",
      controller: "user_bob",
      vcId: "vc_002",
      constraints: {
        scopes: ["tool:execute"],
        audience: serverDid, // Matches server DID
      },
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600000,
    };

    expect(verifyDelegationAudience(delegation, serverDid)).toBe(true);
  });

  it("should return false when delegation audience does not match server DID", () => {
    const delegation: DelegationRecord = {
      id: "del_003",
      issuerDid: "did:web:user.com",
      subjectDid: "did:key:zagent123",
      controller: "user_charlie",
      vcId: "vc_003",
      constraints: {
        scopes: ["tool:execute"],
        audience: "did:web:other-server.com", // Different server
      },
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600000,
    };

    expect(verifyDelegationAudience(delegation, serverDid)).toBe(false);
  });

  it("should return true when server DID is in audience array", () => {
    const delegation: DelegationRecord = {
      id: "del_004",
      issuerDid: "did:web:user.com",
      subjectDid: "did:key:zagent123",
      controller: "user_dave",
      vcId: "vc_004",
      constraints: {
        scopes: ["tool:execute"],
        audience: [
          "did:web:server1.com",
          serverDid, // Server DID is in array
          "did:web:server3.com",
        ],
      },
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600000,
    };

    expect(verifyDelegationAudience(delegation, serverDid)).toBe(true);
  });

  it("should return false when server DID is not in audience array", () => {
    const delegation: DelegationRecord = {
      id: "del_005",
      issuerDid: "did:web:user.com",
      subjectDid: "did:key:zagent123",
      controller: "user_eve",
      vcId: "vc_005",
      constraints: {
        scopes: ["tool:execute"],
        audience: [
          "did:web:server1.com",
          "did:web:server2.com",
          // serverDid not in array
        ],
      },
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600000,
    };

    expect(verifyDelegationAudience(delegation, serverDid)).toBe(false);
  });
});


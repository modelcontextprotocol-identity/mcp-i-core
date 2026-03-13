import { describe, it, expect, beforeEach, vi, Mock } from "vitest";
import {
  DelegationCredentialIssuer,
  createDelegationIssuer,
  type VCSigningFunction,
  type IdentityProvider,
  type IssueDelegationOptions,
} from "../vc-issuer.js";
import type {
  DelegationRecord,
  DelegationCredential,
  Proof,
} from "../../types/protocol.js";

// Mock the protocol functions (preserving all other exports)
vi.mock("../../types/protocol.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../types/protocol.js")>();
  return {
    ...actual,
    wrapDelegationAsVC: vi.fn(),
  };
});

vi.mock("../utils.js", () => ({
  canonicalizeJSON: vi.fn(),
}));

describe("DelegationCredentialIssuer", () => {
  let mockIdentity: IdentityProvider;
  let mockSigningFunction: Mock<VCSigningFunction>;
  let issuer: DelegationCredentialIssuer;

  const mockDelegationRecord: DelegationRecord = {
    id: "del-001",
    issuerDid: "did:web:example.com:issuer",
    subjectDid: "did:web:example.com:subject",
    vcId: "urn:uuid:del-001",
    parentId: undefined,
    constraints: {
      scopes: ["read:profile"],
    },
    signature: "vc-jwt-signed", // Placeholder - actual signature is in the VC-JWT
    status: "active",
    createdAt: Date.now(),
  };

  const mockProof: Proof = {
    type: "Ed25519Signature2020",
    created: "2024-01-01T00:00:00Z",
    verificationMethod: "did:web:example.com:issuer#key-1",
    proofPurpose: "assertionMethod",
    proofValue: "mock-proof-value",
  };

  beforeEach(async () => {
    vi.clearAllMocks();

    mockIdentity = {
      getDid: vi.fn().mockReturnValue("did:web:example.com:issuer"),
      getKeyId: vi.fn().mockReturnValue("key-123"),
      getPrivateKey: vi.fn().mockReturnValue("mock-private-key"),
    };

    mockSigningFunction = vi.fn().mockResolvedValue(mockProof);

    issuer = new DelegationCredentialIssuer(mockIdentity, mockSigningFunction);

    // Setup default mocks
    const { wrapDelegationAsVC } = await import("../../types/protocol.js");
    const { canonicalizeJSON } = await import("../utils.js");

    vi.mocked(wrapDelegationAsVC).mockReturnValue({
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      id: "urn:uuid:del-001",
      type: ["VerifiableCredential", "DelegationCredential"],
      issuer: "did:web:example.com:issuer",
      issuanceDate: "2024-01-01T00:00:00Z",
      credentialSubject: {
        id: "did:web:example.com:subject",
        delegation: {
          id: "del-001",
          issuerDid: "did:web:example.com:issuer",
          subjectDid: "did:web:example.com:subject",
          scopes: ["read:profile"],
          status: "active",
        },
      },
    } as any);

    vi.mocked(canonicalizeJSON).mockReturnValue('{"canonical":"json"}');
  });

  describe("constructor", () => {
    it("should create issuer with identity and signing function", () => {
      const newIssuer = new DelegationCredentialIssuer(
        mockIdentity,
        mockSigningFunction
      );
      expect(newIssuer).toBeInstanceOf(DelegationCredentialIssuer);
    });
  });

  describe("createDelegationIssuer", () => {
    it("should create an issuer instance", () => {
      const newIssuer = createDelegationIssuer(
        mockIdentity,
        mockSigningFunction
      );
      expect(newIssuer).toBeInstanceOf(DelegationCredentialIssuer);
    });
  });

  describe("issueDelegationCredential", () => {
    it("should issue a signed delegation credential", async () => {
      const result =
        await issuer.issueDelegationCredential(mockDelegationRecord);

      expect(result).toBeDefined();
      expect(result.proof).toEqual(mockProof);
      expect(mockSigningFunction).toHaveBeenCalled();
    });

    it("should call wrapDelegationAsVC with delegation record", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");

      await issuer.issueDelegationCredential(mockDelegationRecord);

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        mockDelegationRecord,
        expect.objectContaining({
          id: undefined,
          issuanceDate: undefined,
          expirationDate: undefined,
          credentialStatus: undefined,
        })
      );
    });

    it("should pass options to wrapDelegationAsVC", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");
      const options: IssueDelegationOptions = {
        id: "custom-vc-id",
        issuanceDate: "2024-01-01T00:00:00Z",
        expirationDate: "2025-01-01T00:00:00Z",
      };

      await issuer.issueDelegationCredential(mockDelegationRecord, options);

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        mockDelegationRecord,
        expect.objectContaining({
          id: "custom-vc-id",
          issuanceDate: "2024-01-01T00:00:00Z",
          expirationDate: "2025-01-01T00:00:00Z",
        })
      );
    });

    it("should add additional contexts if provided", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");
      const { canonicalizeJSON } = await import("../utils.js");

      const mockVC = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        id: "urn:uuid:del-001",
        type: ["VerifiableCredential"],
        issuer: "did:web:example.com:issuer",
        issuanceDate: "2024-01-01T00:00:00Z",
        credentialSubject: {},
      };

      vi.mocked(wrapDelegationAsVC).mockReturnValue(mockVC as any);

      const options: IssueDelegationOptions = {
        additionalContexts: ["https://example.com/context"],
      };

      const result = await issuer.issueDelegationCredential(
        mockDelegationRecord,
        options
      );

      expect(result["@context"]).toContain("https://example.com/context");
    });

    it("should canonicalize VC before signing", async () => {
      const { canonicalizeJSON } = await import("../utils.js");

      await issuer.issueDelegationCredential(mockDelegationRecord);

      expect(canonicalizeJSON).toHaveBeenCalled();
    });

    it("should call signing function with canonical VC, DID, and key ID", async () => {
      const { canonicalizeJSON } = await import("../utils.js");
      vi.mocked(canonicalizeJSON).mockReturnValue("canonical-json-string");

      await issuer.issueDelegationCredential(mockDelegationRecord);

      expect(mockSigningFunction).toHaveBeenCalledWith(
        "canonical-json-string",
        "did:web:example.com:issuer",
        "key-123"
      );
    });

    it("should include proof in returned credential", async () => {
      const result =
        await issuer.issueDelegationCredential(mockDelegationRecord);

      expect(result.proof).toBeDefined();
      expect(result.proof).toEqual(mockProof);
    });

    it("should handle credential status option", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");
      const credentialStatus = {
        id: "https://example.com/status#123",
        type: "StatusList2021Entry" as const,
        statusPurpose: "revocation" as const,
        statusListIndex: "123",
        statusListCredential: "https://example.com/status",
      };

      const options: IssueDelegationOptions = {
        credentialStatus,
      };

      await issuer.issueDelegationCredential(mockDelegationRecord, options);

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        mockDelegationRecord,
        expect.objectContaining({
          credentialStatus,
        })
      );
    });
  });

  describe("createAndIssueDelegation", () => {
    it("should create delegation record and issue as VC", async () => {
      const result = await issuer.createAndIssueDelegation({
        id: "del-new",
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        constraints: {
          scopes: ["read:profile"],
        },
      });

      expect(result).toBeDefined();
      expect(result.proof).toEqual(mockProof);
    });

    it("should use provided vcId or generate one", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");

      // Without custom ID
      await issuer.createAndIssueDelegation({
        id: "del-new",
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        constraints: {
          scopes: ["read:profile"],
        },
      });

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        expect.objectContaining({
          vcId: "urn:uuid:del-new",
        }),
        expect.any(Object)
      );

      // With custom ID
      vi.clearAllMocks();
      await issuer.createAndIssueDelegation(
        {
          id: "del-new",
          issuerDid: "did:web:example.com:issuer",
          subjectDid: "did:web:example.com:subject",
          constraints: {
            scopes: ["read:profile"],
          },
        },
        { id: "custom-vc-id" }
      );

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        expect.objectContaining({
          vcId: "custom-vc-id",
        }),
        expect.any(Object)
      );
    });

    it("should set default status to active", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");

      await issuer.createAndIssueDelegation({
        id: "del-new",
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        constraints: {
          scopes: ["read:profile"],
        },
      });

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        expect.objectContaining({
          status: "active",
        }),
        expect.any(Object)
      );
    });

    it("should use provided status if given", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");

      await issuer.createAndIssueDelegation({
        id: "del-new",
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        constraints: {
          scopes: ["read:profile"],
        },
        status: "active",
      });

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        expect.objectContaining({
          status: "active",
        }),
        expect.any(Object)
      );
    });

    it("should include parentId if provided", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");

      await issuer.createAndIssueDelegation({
        id: "del-child",
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        parentId: "del-parent",
        constraints: {
          scopes: ["read:profile"],
        },
      });

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        expect.objectContaining({
          parentId: "del-parent",
        }),
        expect.any(Object)
      );
    });

    it("should include metadata if provided", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");
      const metadata = { custom: "value" };

      await issuer.createAndIssueDelegation({
        id: "del-new",
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        constraints: {
          scopes: ["read:profile"],
        },
        metadata,
      });

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata,
        }),
        expect.any(Object)
      );
    });

    it("should set createdAt timestamp", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");
      const beforeTime = Date.now();

      await issuer.createAndIssueDelegation({
        id: "del-new",
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        constraints: {
          scopes: ["read:profile"],
        },
      });

      const afterTime = Date.now();

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        expect.objectContaining({
          createdAt: expect.any(Number),
        }),
        expect.any(Object)
      );

      const callArgs = vi.mocked(wrapDelegationAsVC).mock
        .calls[0][0] as DelegationRecord;
      expect(callArgs.createdAt).toBeGreaterThanOrEqual(beforeTime);
      expect(callArgs.createdAt).toBeLessThanOrEqual(afterTime);
    });

    it("should include controller if provided", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");

      await issuer.createAndIssueDelegation({
        id: "del-new",
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        controller: "did:web:example.com:controller",
        constraints: {
          scopes: ["read:profile"],
        },
      });

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        expect.objectContaining({
          controller: "did:web:example.com:controller",
        }),
        expect.any(Object)
      );
    });

    it("should handle empty signature field", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");

      await issuer.createAndIssueDelegation({
        id: "del-new",
        issuerDid: "did:web:example.com:issuer",
        subjectDid: "did:web:example.com:subject",
        constraints: {
          scopes: ["read:profile"],
        },
      });

      expect(wrapDelegationAsVC).toHaveBeenCalledWith(
        expect.objectContaining({
          signature: "", // Should be empty string by default
        }),
        expect.any(Object)
      );
    });
  });

  describe("getIssuerDid", () => {
    it("should return issuer DID from identity provider", () => {
      const did = issuer.getIssuerDid();
      expect(did).toBe("did:web:example.com:issuer");
      expect(mockIdentity.getDid).toHaveBeenCalled();
    });
  });

  describe("getIssuerKeyId", () => {
    it("should return key ID from identity provider", () => {
      const keyId = issuer.getIssuerKeyId();
      expect(keyId).toBe("key-123");
      expect(mockIdentity.getKeyId).toHaveBeenCalled();
    });
  });

  describe("error handling", () => {
    it("should propagate errors from signing function", async () => {
      mockSigningFunction.mockRejectedValue(new Error("Signing failed"));

      await expect(
        issuer.issueDelegationCredential(mockDelegationRecord)
      ).rejects.toThrow("Signing failed");
    });

    it("should propagate errors from wrapDelegationAsVC", async () => {
      const { wrapDelegationAsVC } = await import("../../types/protocol.js");
      vi.mocked(wrapDelegationAsVC).mockImplementation(() => {
        throw new Error("VC wrapping failed");
      });

      await expect(
        issuer.issueDelegationCredential(mockDelegationRecord)
      ).rejects.toThrow("VC wrapping failed");
    });
  });
});

import { describe, it, expect } from "vitest";
import {
  PROOF_VERIFICATION_ERROR_CODES,
  ProofVerificationError,
  createProofVerificationError,
} from "../errors.js";

describe("PROOF_VERIFICATION_ERROR_CODES", () => {
  it("should define all expected error code categories", () => {
    const codes = PROOF_VERIFICATION_ERROR_CODES;

    // Proof structure
    expect(codes.INVALID_PROOF_STRUCTURE).toBeDefined();
    expect(codes.MISSING_REQUIRED_FIELD).toBeDefined();

    // Security
    expect(codes.NONCE_REPLAY_DETECTED).toBeDefined();
    expect(codes.TIMESTAMP_SKEW_EXCEEDED).toBeDefined();

    // JWS
    expect(codes.INVALID_JWS_SIGNATURE).toBeDefined();
    expect(codes.INVALID_JWS_FORMAT).toBeDefined();

    // JWK
    expect(codes.INVALID_JWK_FORMAT).toBeDefined();

    // DID
    expect(codes.DID_RESOLUTION_FAILED).toBeDefined();
    expect(codes.DID_DOCUMENT_NOT_FOUND).toBeDefined();
  });
});

describe("ProofVerificationError", () => {
  it("should extend Error", () => {
    const err = new ProofVerificationError(
      PROOF_VERIFICATION_ERROR_CODES.NONCE_REPLAY_DETECTED,
      "Nonce reused",
    );

    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("ProofVerificationError");
    expect(err.message).toBe("Nonce reused");
    expect(err.code).toBe("NONCE_REPLAY_DETECTED");
  });

  it("should include optional details", () => {
    const err = new ProofVerificationError(
      PROOF_VERIFICATION_ERROR_CODES.DID_DOCUMENT_NOT_FOUND,
      "DID not found",
      { did: "did:key:z6MkTest" },
    );

    expect(err.details).toEqual({ did: "did:key:z6MkTest" });
  });

  it("should have undefined details when not provided", () => {
    const err = new ProofVerificationError(
      PROOF_VERIFICATION_ERROR_CODES.INVALID_JWS_FORMAT,
      "Bad format",
    );

    expect(err.details).toBeUndefined();
  });
});

describe("createProofVerificationError", () => {
  it("should create a ProofVerificationError instance", () => {
    const err = createProofVerificationError(
      PROOF_VERIFICATION_ERROR_CODES.TIMESTAMP_SKEW_EXCEEDED,
      "Clock skew too large",
      { skew: 300 },
    );

    expect(err).toBeInstanceOf(ProofVerificationError);
    expect(err.code).toBe("TIMESTAMP_SKEW_EXCEEDED");
    expect(err.message).toBe("Clock skew too large");
    expect(err.details).toEqual({ skew: 300 });
  });
});

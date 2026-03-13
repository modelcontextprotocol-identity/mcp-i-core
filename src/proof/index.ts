export {
  ProofGenerator,
  createProofResponse,
  extractCanonicalData,
  type ProofAgentIdentity,
  type ToolRequest,
  type ToolResponse,
  type ProofOptions,
} from './generator.js';

export {
  ProofVerifier,
  type ProofVerifierConfig,
  type ProofVerificationResult,
} from './verifier.js';

export {
  ProofVerificationError,
  PROOF_VERIFICATION_ERROR_CODES,
  createProofVerificationError,
  type ProofVerificationErrorCode,
} from './errors.js';

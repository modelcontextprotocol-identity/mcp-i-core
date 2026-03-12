/**
 * Dylan Hobbs
 * Delegation Credential Verifier (Platform-Agnostic)
 *
 * Progressive enhancement verification for W3C Delegation Credentials.
 *
 * Stage 1: Fast basic checks (no network, early rejection)
 * Stage 2: Parallel advanced checks (signature, status)
 * Stage 3: Combined results
 *
 * Related Spec: MCP-I §4.3, W3C VC Data Model 1.1
 */

import type {
  DelegationCredential,
  CredentialStatus,
} from "../types/protocol.js";
import {
  isDelegationCredentialExpired,
  isDelegationCredentialNotYetValid,
  validateDelegationCredential,
} from "../types/protocol.js";

export interface DelegationVCVerificationResult {
  valid: boolean;
  reason?: string;
  stage: "basic" | "signature" | "status" | "complete";
  cached?: boolean;
  metrics?: {
    basicCheckMs?: number;
    signatureCheckMs?: number;
    statusCheckMs?: number;
    totalMs: number;
  };
  checks?: {
    basicValid?: boolean;
    signatureValid?: boolean;
    statusValid?: boolean;
  };
}

export interface VerifyDelegationVCOptions {
  skipCache?: boolean;
  skipSignature?: boolean;
  skipStatus?: boolean;
  didResolver?: DIDResolver;
  statusListResolver?: StatusListResolver;
}

export interface DIDResolver {
  resolve(did: string): Promise<DIDDocument | null>;
}

export interface DIDDocument {
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: unknown;
  publicKeyBase58?: string;
  publicKeyMultibase?: string;
}

export interface StatusListResolver {
  checkStatus(status: CredentialStatus): Promise<boolean>;
}

export interface SignatureVerificationFunction {
  (
    vc: DelegationCredential,
    publicKeyJwk: unknown,
  ): Promise<{
    valid: boolean;
    reason?: string;
  }>;
}

export class DelegationCredentialVerifier {
  private didResolver?: DIDResolver;
  private statusListResolver?: StatusListResolver;
  private signatureVerifier?: SignatureVerificationFunction;
  private cache = new Map<
    string,
    { result: DelegationVCVerificationResult; expiresAt: number }
  >();
  private cacheTtl: number;

  constructor(options?: {
    didResolver?: DIDResolver;
    statusListResolver?: StatusListResolver;
    signatureVerifier?: SignatureVerificationFunction;
    cacheTtl?: number;
  }) {
    this.didResolver = options?.didResolver;
    this.statusListResolver = options?.statusListResolver;
    this.signatureVerifier = options?.signatureVerifier;
    this.cacheTtl = options?.cacheTtl || 60_000;
  }

  async verifyDelegationCredential(
    vc: DelegationCredential,
    options: VerifyDelegationVCOptions = {},
  ): Promise<DelegationVCVerificationResult> {
    const startTime = Date.now();

    if (!options.skipCache) {
      const cached = this.getFromCache(vc.id || "");
      if (cached) {
        return { ...cached, cached: true };
      }
    }

    const basicCheckStart = Date.now();
    const basicValidation = this.validateBasicProperties(vc);
    const basicCheckMs = Date.now() - basicCheckStart;

    if (!basicValidation.valid) {
      const result: DelegationVCVerificationResult = {
        valid: false,
        reason: basicValidation.reason,
        stage: "basic",
        metrics: {
          basicCheckMs,
          totalMs: Date.now() - startTime,
        },
        checks: {
          basicValid: false,
        },
      };
      return result;
    }

    const signaturePromise = !options.skipSignature
      ? this.verifySignature(vc, options.didResolver || this.didResolver)
      : Promise.resolve<{
          valid: boolean;
          reason?: string;
          durationMs?: number;
        }>({
          valid: true,
          durationMs: 0,
        });

    const statusPromise =
      !options.skipStatus && vc.credentialStatus
        ? this.checkCredentialStatus(
            vc.credentialStatus,
            options.statusListResolver || this.statusListResolver,
          )
        : Promise.resolve<{
            valid: boolean;
            reason?: string;
            durationMs?: number;
          }>({
            valid: true,
            durationMs: 0,
          });

    const [signatureResult, statusResult] = await Promise.all([
      signaturePromise,
      statusPromise,
    ]);

    const signatureCheckMs = signatureResult.durationMs || 0;
    const statusCheckMs = statusResult.durationMs || 0;

    const allValid =
      basicValidation.valid && signatureResult.valid && statusResult.valid;

    const result: DelegationVCVerificationResult = {
      valid: allValid,
      reason: !allValid
        ? signatureResult.reason || statusResult.reason || "Unknown failure"
        : undefined,
      stage: "complete",
      metrics: {
        basicCheckMs,
        signatureCheckMs,
        statusCheckMs,
        totalMs: Date.now() - startTime,
      },
      checks: {
        basicValid: basicValidation.valid,
        signatureValid: signatureResult.valid,
        statusValid: statusResult.valid,
      },
    };

    if (result.valid && vc.id) {
      this.setInCache(vc.id, result);
    }

    return result;
  }

  private validateBasicProperties(vc: DelegationCredential): {
    valid: boolean;
    reason?: string;
  } {
    const schemaValidation = validateDelegationCredential(vc);
    if (!schemaValidation.success) {
      return {
        valid: false,
        reason: `Schema validation failed: ${schemaValidation.error?.message}`,
      };
    }

    if (isDelegationCredentialExpired(vc)) {
      return { valid: false, reason: "Delegation credential expired" };
    }

    if (isDelegationCredentialNotYetValid(vc)) {
      return { valid: false, reason: "Delegation credential not yet valid" };
    }

    const delegation = vc.credentialSubject.delegation;
    if (delegation.status === "revoked") {
      return { valid: false, reason: "Delegation status is revoked" };
    }
    if (delegation.status === "expired") {
      return { valid: false, reason: "Delegation status is expired" };
    }

    if (!delegation.issuerDid || !delegation.subjectDid) {
      return { valid: false, reason: "Missing issuer or subject DID" };
    }

    if (!vc.proof) {
      return { valid: false, reason: "Missing proof" };
    }

    return { valid: true };
  }

  private async verifySignature(
    vc: DelegationCredential,
    didResolver?: DIDResolver,
  ): Promise<{ valid: boolean; reason?: string; durationMs?: number }> {
    const startTime = Date.now();

    try {
      const issuerDid =
        typeof vc.issuer === "string" ? vc.issuer : vc.issuer.id;

      if (!didResolver || !this.signatureVerifier) {
        return {
          valid: true,
          reason:
            "No DID resolver or signature verifier available, skipping signature verification",
          durationMs: Date.now() - startTime,
        };
      }

      const didDoc = await didResolver.resolve(issuerDid);
      if (!didDoc) {
        return {
          valid: false,
          reason: `Could not resolve issuer DID: ${issuerDid}`,
          durationMs: Date.now() - startTime,
        };
      }

      if (!vc.proof) {
        return {
          valid: false,
          reason: "Proof is missing",
          durationMs: Date.now() - startTime,
        };
      }

      const verificationMethodId = vc.proof["verificationMethod"];
      if (!verificationMethodId) {
        return {
          valid: false,
          reason: "Proof missing verificationMethod",
          durationMs: Date.now() - startTime,
        };
      }

      const verificationMethod = this.findVerificationMethod(
        didDoc,
        verificationMethodId as string,
      );
      if (!verificationMethod) {
        return {
          valid: false,
          reason: `Verification method ${verificationMethodId} not found`,
          durationMs: Date.now() - startTime,
        };
      }

      const publicKeyJwk = verificationMethod.publicKeyJwk;
      if (!publicKeyJwk) {
        return {
          valid: false,
          reason: "Verification method missing publicKeyJwk",
          durationMs: Date.now() - startTime,
        };
      }

      const verificationResult = await this.signatureVerifier(vc, publicKeyJwk);

      return {
        valid: verificationResult.valid,
        reason: verificationResult.reason,
        durationMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        valid: false,
        reason: `Signature verification error: ${error instanceof Error ? error.message : "Unknown error"}`,
        durationMs: Date.now() - startTime,
      };
    }
  }

  private async checkCredentialStatus(
    status: CredentialStatus,
    statusListResolver?: StatusListResolver,
  ): Promise<{ valid: boolean; reason?: string; durationMs?: number }> {
    const startTime = Date.now();

    try {
      if (!statusListResolver) {
        return {
          valid: true,
          reason: "No status list resolver available, skipping status check",
          durationMs: Date.now() - startTime,
        };
      }

      const isRevoked = await statusListResolver.checkStatus(status);

      if (isRevoked) {
        return {
          valid: false,
          reason: `Credential revoked via StatusList2021 (${status.statusPurpose})`,
          durationMs: Date.now() - startTime,
        };
      }

      return {
        valid: true,
        durationMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        valid: false,
        reason: `Status check error: ${error instanceof Error ? error.message : "Unknown error"}`,
        durationMs: Date.now() - startTime,
      };
    }
  }

  private findVerificationMethod(
    didDoc: DIDDocument,
    verificationMethodId: string,
  ): VerificationMethod | undefined {
    return didDoc.verificationMethod?.find(
      (vm) => vm.id === verificationMethodId,
    );
  }

  private getFromCache(id: string): DelegationVCVerificationResult | null {
    const entry = this.cache.get(id);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(id);
      return null;
    }

    return entry.result;
  }

  private setInCache(id: string, result: DelegationVCVerificationResult): void {
    this.cache.set(id, {
      result,
      expiresAt: Date.now() + this.cacheTtl,
    });
  }

  clearCache(): void {
    this.cache.clear();
  }

  clearCacheEntry(id: string): void {
    this.cache.delete(id);
  }
}

export function createDelegationVerifier(options?: {
  didResolver?: DIDResolver;
  statusListResolver?: StatusListResolver;
  signatureVerifier?: SignatureVerificationFunction;
  cacheTtl?: number;
}): DelegationCredentialVerifier {
  return new DelegationCredentialVerifier(options);
}

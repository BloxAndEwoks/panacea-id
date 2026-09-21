import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalJson } from "./canonical.js";
import { forbiddenKeysIn } from "./forbidden.js";
import type { StoredClaims } from "./policy.js";

const text = new TextEncoder();

export type Challenge = {
  id: string;
  nonce: string;
  origin: string;
  purpose: string;
  policyId: string;
  policyVersion: string;
  scope: string;
  expiresAt: string;
  binding: string;
};

export function challengeBinding(
  challenge: Omit<Challenge, "binding">,
): string {
  return bytesToHex(sha256(text.encode(canonicalJson(challenge))));
}

export function createChallenge(input: {
  id: string;
  nonce: string;
  origin: string;
  purpose: string;
  policyId: string;
  policyVersion: string;
  scope: string;
  expiresAt: Date;
}): Challenge {
  const unsigned = {
    id: input.id,
    nonce: input.nonce,
    origin: input.origin,
    purpose: input.purpose,
    policyId: input.policyId,
    policyVersion: input.policyVersion,
    scope: input.scope,
    expiresAt: input.expiresAt.toISOString(),
  };
  return { ...unsigned, binding: challengeBinding(unsigned) };
}

export function assertChallengeFresh(challenge: Challenge, now: Date): void {
  if (new Date(challenge.expiresAt).getTime() <= now.getTime()) {
    throw new Error("Challenge has expired");
  }
}

/**
 * App-specific pseudonym. The same document identifier becomes a different
 * subject when the origin or the scope changes, and the raw identifier is not
 * recoverable from this value.
 */
export function deriveSubjectId(origin: string, scope: string, uniqueIdentifier: string): string {
  const mac = hmac(
    sha256,
    text.encode(`panacea.subject.v1|${origin}|${scope}`),
    text.encode(uniqueIdentifier),
  );
  return bytesToHex(mac);
}

export type VerificationRecord = {
  subjectId: string;
  policyId: string;
  policyVersion: string;
  origin: string;
  purpose: string;
  scope: string;
  assurance: "development" | "zkpassport";
  claims: StoredClaims;
  verifiedAt: string;
};

export function sealVerificationRecord(record: VerificationRecord): VerificationRecord {
  const forbidden = forbiddenKeysIn(record);
  if (forbidden.length > 0) {
    throw new Error(`Verification record contains forbidden keys: ${forbidden.join(", ")}`);
  }
  return record;
}

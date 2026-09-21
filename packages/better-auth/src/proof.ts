import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalJson, type QueryResult } from "@panacea-id/protocol";

const text = new TextEncoder();

export type DevelopmentProof = {
  mode: "development";
  challengeId: string;
  binding: string;
  uniqueIdentifier: string;
  queryResult: QueryResult;
  signature: string;
};

export type ZkPassportProof = {
  mode: "zkpassport";
  challengeId: string;
  binding: string;
  proofs: unknown[];
  originalQuery: unknown;
  queryResult: QueryResult;
};

export type ProofEnvelope = DevelopmentProof | ZkPassportProof;

export function signDevelopmentProof(
  secret: string,
  proof: Omit<DevelopmentProof, "signature" | "mode"> & { mode?: "development" },
): DevelopmentProof {
  const unsigned = {
    mode: "development" as const,
    challengeId: proof.challengeId,
    binding: proof.binding,
    uniqueIdentifier: proof.uniqueIdentifier,
    queryResult: proof.queryResult,
  };
  return { ...unsigned, signature: mac(secret, unsigned) };
}

export function developmentProofIsAuthentic(secret: string, proof: DevelopmentProof): boolean {
  const { signature, ...unsigned } = proof;
  if (unsigned.mode !== "development") return false;
  return safeEqual(signature, mac(secret, unsigned));
}

function mac(secret: string, payload: unknown): string {
  return bytesToHex(hmac(sha256, text.encode(secret), text.encode(canonicalJson(payload))));
}

function safeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) {
    mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return mismatch === 0;
}

type ZkPassportConstructor = new (domain: string) => {
  verify: (args: {
    proofs: unknown[];
    originalQuery: unknown;
    queryResult: QueryResult;
    scope?: string;
  }) => Promise<{ verified: boolean; uniqueIdentifier?: string }>;
};

export async function verifyZkPassportProof(
  domain: string,
  proof: ZkPassportProof,
  scope: string,
): Promise<{ uniqueIdentifier: string; queryResult: QueryResult } | null> {
  const dynamicImport = new Function("specifier", "return import(specifier)") as (
    specifier: string,
  ) => Promise<{ ZKPassport: ZkPassportConstructor }>;
  const loaded = await dynamicImport("@zkpassport/sdk");
  const zk = new loaded.ZKPassport(domain);
  const result = await zk.verify({
    proofs: proof.proofs,
    originalQuery: proof.originalQuery,
    queryResult: proof.queryResult,
    scope,
  });
  if (!result.verified || !result.uniqueIdentifier) return null;
  return { uniqueIdentifier: result.uniqueIdentifier, queryResult: proof.queryResult };
}

import { APIError, createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import type { BetterAuthPlugin } from "better-auth";
import * as z from "zod";
import {
  assertChallengeFresh,
  compilePolicies,
  createChallenge,
  deriveSubjectId,
  minimumClaims,
  sealVerificationRecord,
  type Challenge,
  type PolicyDocument,
  type VerificationRecord,
} from "@panacea-id/protocol";
import {
  developmentProofIsAuthentic,
  verifyZkPassportProof,
  type ProofEnvelope,
} from "./proof.js";
import type { QueryResult } from "@panacea-id/protocol";

export type ZkPassportOptions = {
  /** Server-side verification is the only mode this plugin implements. */
  verifier?: "server-side";
  origin: string;
  purpose: string;
  policies: Record<string, (query: import("@panacea-id/protocol").QueryBuilder) => PolicyDocument>;
  /** When set, HMAC-signed development proofs are accepted and labeled as such. */
  developmentSecret?: string;
  /** Domain passed to @zkpassport/sdk when a phone proof is submitted. */
  zkPassportDomain?: string;
  challengeTtlMs?: number;
};

type ChallengeRow = {
  id: string;
  challengeId: string;
  nonce: string;
  origin: string;
  purpose: string;
  policyId: string;
  policyVersion: string;
  scope: string;
  expiresAt: string;
  binding: string;
  consumedAt: string;
};

const proofSchema = z.object({
  mode: z.enum(["development", "zkpassport"]),
  challengeId: z.string().min(1),
  binding: z.string().min(1),
  uniqueIdentifier: z.string().min(1).optional(),
  queryResult: z.record(z.string(), z.unknown()),
  signature: z.string().optional(),
  proofs: z.array(z.unknown()).optional(),
  originalQuery: z.unknown().optional(),
});

export function zkPassport(options: ZkPassportOptions) {
  if (options.verifier && options.verifier !== "server-side") {
    throw new Error("Panacea verifies ZKPassport proofs on the server");
  }
  const policies = compilePolicies(options.policies);
  const ttl = options.challengeTtlMs ?? 10 * 60 * 1000;

  return {
    id: "zk-passport",
    schema: {
      zkChallenge: {
        fields: {
          challengeId: { type: "string", required: true, unique: true },
          nonce: { type: "string", required: true },
          origin: { type: "string", required: true },
          purpose: { type: "string", required: true },
          policyId: { type: "string", required: true },
          policyVersion: { type: "string", required: true },
          scope: { type: "string", required: true },
          expiresAt: { type: "string", required: true },
          binding: { type: "string", required: true },
          consumedAt: { type: "string", required: false, defaultValue: "" },
        },
      },
      zkVerification: {
        fields: {
          subjectId: { type: "string", required: true, index: true },
          userId: { type: "string", required: true, index: true },
          policyId: { type: "string", required: true },
          policyVersion: { type: "string", required: true },
          origin: { type: "string", required: true },
          purpose: { type: "string", required: true },
          scope: { type: "string", required: true },
          assurance: { type: "string", required: true },
          claims: { type: "string", required: true },
          verifiedAt: { type: "string", required: true },
        },
      },
    },
    endpoints: {
      challenge: createAuthEndpoint(
        "/zk-passport/challenge",
        {
          method: "POST",
          body: z.object({
            policy: z.string().min(1),
            scope: z.string().min(1),
          }),
        },
        async (ctx) => {
          const requestOrigin = ctx.headers?.get("origin");
          if (requestOrigin && requestOrigin !== options.origin) {
            throw fail(403, "Challenge origin does not match this application");
          }
          const policy = policies[ctx.body.policy];
          if (!policy) throw fail(400, "Unknown policy");
          const challenge = createChallenge({
            id: crypto.randomUUID(),
            nonce: hexNonce(),
            origin: options.origin,
            purpose: options.purpose,
            policyId: policy.id,
            policyVersion: policy.version,
            scope: ctx.body.scope,
            expiresAt: new Date(Date.now() + ttl),
          });
          await ctx.context.adapter.create({
            model: "zkChallenge",
            data: {
              challengeId: challenge.id,
              nonce: challenge.nonce,
              origin: challenge.origin,
              purpose: challenge.purpose,
              policyId: challenge.policyId,
              policyVersion: challenge.policyVersion,
              scope: challenge.scope,
              expiresAt: challenge.expiresAt,
              binding: challenge.binding,
              consumedAt: "",
            },
          });
          return ctx.json(challenge);
        },
      ),
      verify: createAuthEndpoint(
        "/zk-passport/verify",
        {
          method: "POST",
          body: z.object({ proof: proofSchema }),
        },
        async (ctx) => {
          const proof = ctx.body.proof as ProofEnvelope;
          const row = (await ctx.context.adapter.findOne({
            model: "zkChallenge",
            where: [{ field: "challengeId", value: proof.challengeId, operator: "eq" }],
          })) as ChallengeRow | null;
          if (!row) throw fail(400, "Unknown challenge");
          if (row.consumedAt) throw fail(400, "Challenge was already used");
          const challenge = rowToChallenge(row);
          try {
            assertChallengeFresh(challenge, new Date());
          } catch {
            throw fail(400, "Challenge has expired");
          }
          if (proof.binding !== challenge.binding) throw fail(400, "Proof is bound to a different challenge");
          await ctx.context.adapter.update({
            model: "zkChallenge",
            where: [{ field: "id", value: row.id, operator: "eq" }],
            update: { consumedAt: new Date().toISOString() },
          });

          const checked = await checkProof(options, challenge, proof);
          const policy = policies[challenge.policyId];
          if (!policy || policy.version !== challenge.policyVersion) throw fail(400, "Policy version mismatch");
          let claims;
          try {
            claims = minimumClaims(policy, checked.queryResult);
          } catch (error) {
            throw fail(400, error instanceof Error ? error.message : "Policy was not satisfied");
          }
          const record = sealVerificationRecord({
            subjectId: deriveSubjectId(challenge.origin, challenge.scope, checked.uniqueIdentifier),
            policyId: policy.id,
            policyVersion: policy.version,
            origin: challenge.origin,
            purpose: challenge.purpose,
            scope: challenge.scope,
            assurance: checked.assurance,
            claims,
            verifiedAt: new Date().toISOString(),
          });
          const user = await upsertSubject(ctx.context.internalAdapter, record);
          await ctx.context.adapter.create({
            model: "zkVerification",
            data: {
              ...record,
              userId: user.id,
              claims: JSON.stringify(record.claims),
            },
          });
          const session = await ctx.context.internalAdapter.createSession(user.id);
          if (!session) throw fail(500, "Could not create a session");
          await setSessionCookie(ctx, { session, user });
          return ctx.json({ verification: record });
        },
      ),
      receipt: createAuthEndpoint(
        "/zk-passport/receipt",
        { method: "GET", use: [sessionMiddleware] },
        async (ctx) => {
          const row = (await ctx.context.adapter.findOne({
            model: "zkVerification",
            where: [{ field: "userId", value: ctx.context.session.user.id, operator: "eq" }],
          })) as { claims: string; assurance: string; policyId: string; scope: string; purpose: string } | null;
          if (!row) throw fail(404, "No verification is stored for this session");
          return ctx.json({
            assurance: row.assurance,
            policyId: row.policyId,
            scope: row.scope,
            purpose: row.purpose,
            claims: JSON.parse(row.claims) as VerificationRecord["claims"],
          });
        },
      ),
    },
  } satisfies BetterAuthPlugin;
}

async function checkProof(
  options: ZkPassportOptions,
  challenge: Challenge,
  proof: ProofEnvelope,
): Promise<{ uniqueIdentifier: string; queryResult: QueryResult; assurance: "development" | "zkpassport" }> {
  if (proof.mode === "development") {
    if (!options.developmentSecret) throw fail(400, "Development proofs are disabled");
    if (!proof.uniqueIdentifier || !developmentProofIsAuthentic(options.developmentSecret, proof)) {
      throw fail(400, "Development proof signature is invalid");
    }
    return {
      uniqueIdentifier: proof.uniqueIdentifier,
      queryResult: proof.queryResult,
      assurance: "development",
    };
  }
  if (!options.zkPassportDomain) throw fail(400, "ZKPassport domain is not configured");
  const verified = await verifyZkPassportProof(options.zkPassportDomain, proof, challenge.scope);
  if (!verified) throw fail(400, "ZKPassport proof did not verify");
  return { ...verified, assurance: "zkpassport" };
}

async function upsertSubject(
  internalAdapter: {
    findUserByEmail: (email: string) => Promise<{
      user: {
        id: string;
        email: string;
        name: string;
        emailVerified: boolean;
        createdAt: Date;
        updatedAt: Date;
        image?: string | null;
      };
    } | null>;
    createUser: (
      user: { email: string; name: string; emailVerified: boolean },
      source: { method: string },
    ) => Promise<{
      id: string;
      email: string;
      name: string;
      emailVerified: boolean;
      createdAt: Date;
      updatedAt: Date;
      image?: string | null;
    }>;
  },
  record: VerificationRecord,
) {
  const email = `${record.subjectId}@subjects.panacea.invalid`;
  const existing = await internalAdapter.findUserByEmail(email);
  if (existing) return existing.user;
  return internalAdapter.createUser(
    { email, name: "Participant", emailVerified: false },
    { method: "zk-passport" },
  );
}

function rowToChallenge(row: ChallengeRow): Challenge {
  return {
    id: row.challengeId,
    nonce: row.nonce,
    origin: row.origin,
    purpose: row.purpose,
    policyId: row.policyId,
    policyVersion: row.policyVersion,
    scope: row.scope,
    expiresAt: row.expiresAt,
    binding: row.binding,
  };
}

function hexNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fail(status: 400 | 403 | 404 | 500, message: string): never {
  const code = status === 403 ? "FORBIDDEN" : status === 404 ? "NOT_FOUND" : status === 500 ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST";
  throw APIError.fromStatus(code, { message, status });
}

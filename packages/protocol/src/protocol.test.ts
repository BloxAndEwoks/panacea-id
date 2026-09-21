import { describe, expect, it } from "vitest";
import {
  QueryBuilder,
  compilePolicies,
  createChallenge,
  deriveSubjectId,
  forbiddenKeysIn,
  minimumClaims,
  sealVerificationRecord,
} from "./index.js";

const policies = compilePolicies({
  adultCitizen: (query) => query.gte("age", 18).in("nationality", ["SV"]).done(),
});

describe("policy minimum claims", () => {
  it("refuses to disclose a document number", () => {
    const builder = new QueryBuilder("leaky");
    expect(() => builder.disclose("document_number")).toThrow(/document number/i);
  });

  it("stores predicate outcomes and drops raw age, document numbers, and extra disclosures", () => {
    const policy = policies.adultCitizen!;
    const claims = minimumClaims(policy, {
      age: { gte: { result: true, expected: 18 } },
      nationality: { in: { result: true, expected: ["SV"] } },
      document_number: { disclose: { result: "P123456" } },
      birthdate: { disclose: { result: "1990-01-01" } },
    });
    expect(claims).toEqual({
      age: { gte: 18, passed: true },
      nationality: { in: ["SV"], passed: true },
    });
    expect(JSON.stringify(claims)).not.toContain("P123456");
    expect(JSON.stringify(claims)).not.toContain("1990");
    expect(forbiddenKeysIn(claims)).toEqual([]);
  });

  it("rejects a proof whose expected age was swapped", () => {
    expect(() =>
      minimumClaims(policies.adultCitizen!, {
        age: { gte: { result: true, expected: 16 } },
        nationality: { in: { result: true, expected: ["SV"] } },
      }),
    ).toThrow(/does not satisfy/);
  });
});

describe("pseudonymous subjects", () => {
  it("changes the subject when the origin or scope changes and never echoes the identifier", () => {
    const identifier = "passport-nullifier-9f3a";
    const app = deriveSubjectId("https://harbor.example", "harbor-commons", identifier);
    const otherApp = deriveSubjectId("https://other.example", "harbor-commons", identifier);
    const otherScope = deriveSubjectId("https://harbor.example", "other-poll", identifier);
    expect(app).not.toBe(otherApp);
    expect(app).not.toBe(otherScope);
    expect(app).not.toContain(identifier);
  });
});

describe("challenges", () => {
  it("binds origin, purpose, and policy version", () => {
    const policy = policies.adultCitizen!;
    const challenge = createChallenge({
      id: "ch_1",
      nonce: "abc",
      origin: "https://harbor.example",
      purpose: "Harbor commons consultation",
      policyId: policy.id,
      policyVersion: policy.version,
      scope: "harbor-commons",
      expiresAt: new Date("2026-09-21T12:10:00.000Z"),
    });
    const moved = createChallenge({
      id: "ch_1",
      nonce: "abc",
      origin: "https://evil.example",
      purpose: "Harbor commons consultation",
      policyId: policy.id,
      policyVersion: policy.version,
      scope: "harbor-commons",
      expiresAt: new Date("2026-09-21T12:10:00.000Z"),
    });
    expect(challenge.binding).not.toBe(moved.binding);
    const record = sealVerificationRecord({
      subjectId: deriveSubjectId(challenge.origin, challenge.scope, "passport-nullifier-9f3a"),
      policyId: policy.id,
      policyVersion: policy.version,
      origin: challenge.origin,
      purpose: challenge.purpose,
      scope: challenge.scope,
      assurance: "development",
      claims: minimumClaims(policy, {
        age: { gte: { result: true, expected: 18 } },
        nationality: { in: { result: true, expected: ["SV"] } },
      }),
      verifiedAt: "2026-09-21T12:00:00.000Z",
    });
    expect(record.claims).not.toHaveProperty("uniqueIdentifier");
  });
});

import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { describe, expect, it } from "vitest";
import { signDevelopmentProof, zkPassport } from "./index.js";

const ORIGIN = "http://localhost:5173";
const DEVELOPMENT_SECRET = "development-verifier-secret-32b";
const IDENTIFIER = "passport-nullifier-VISIBLE-9f3a";

function createAuth(memory: Record<string, unknown[]>) {
  return betterAuth({
    baseURL: ORIGIN,
    secret: "better-auth-test-secret-32-chars-min",
    basePath: "/api/auth",
    database: memoryAdapter(memory),
    trustedOrigins: [ORIGIN],
    plugins: [
      zkPassport({
        verifier: "server-side",
        origin: ORIGIN,
        purpose: "Harbor commons consultation",
        developmentSecret: DEVELOPMENT_SECRET,
        policies: {
          adultCitizen: (query) => query.gte("age", 18).in("nationality", ["SV"]).done(),
        },
      }),
    ],
  });
}

async function post(
  auth: ReturnType<typeof createAuth>,
  path: string,
  body: unknown,
) {
  const response = await auth.handler(
    new Request(`${ORIGIN}/api/auth${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ORIGIN },
      body: JSON.stringify(body),
    }),
  );
  return { status: response.status, json: (await response.json()) as Record<string, never> & {
    id: string;
    binding: string;
    verification: { claims: unknown; assurance: string };
  } };
}

describe("zk passport plugin", () => {
  it("opens a session from a bound proof and stores only the policy outcomes", async () => {
    const memory: Record<string, unknown[]> = {
      user: [],
      session: [],
      account: [],
      verification: [],
    };
    const auth = createAuth(memory);
    const challenge = await post(auth, "/zk-passport/challenge", {
      policy: "adultCitizen",
      scope: "harbor-commons",
    });
    expect(challenge.status).toBe(200);
    const proof = signDevelopmentProof(DEVELOPMENT_SECRET, {
      challengeId: challenge.json.id,
      binding: challenge.json.binding,
      uniqueIdentifier: IDENTIFIER,
      queryResult: {
        age: { gte: { result: true, expected: 18 } },
        nationality: { in: { result: true, expected: ["SV"] } },
        document_number: { disclose: { result: "P123456" } },
      },
    });
    const verified = await post(auth, "/zk-passport/verify", { proof });
    expect(verified.status).toBe(200);
    expect(verified.json.verification.claims).toEqual({
      age: { gte: 18, passed: true },
      nationality: { in: ["SV"], passed: true },
    });
    expect(verified.json.verification.assurance).toBe("development");
    const stored = JSON.stringify(memory);
    expect(stored).not.toContain(IDENTIFIER);
    expect(stored).not.toContain("P123456");
    expect(stored).not.toContain("document_number");

    const replay = await post(auth, "/zk-passport/verify", { proof });
    expect(replay.status).toBe(400);

    const other = await post(auth, "/zk-passport/challenge", {
      policy: "adultCitizen",
      scope: "harbor-commons",
    });
    const rejected = await post(auth, "/zk-passport/verify", {
      proof: signDevelopmentProof(DEVELOPMENT_SECRET, {
        challengeId: other.json.id,
        binding: other.json.binding,
        uniqueIdentifier: "someone-else",
        queryResult: {
          age: { gte: { result: true, expected: 18 } },
          nationality: { in: { result: true, expected: ["FR"] } },
        },
      }),
    });
    expect(rejected.status).toBe(400);
    expect(JSON.stringify(memory)).not.toContain("someone-else");
  });
});

import { createAuthClient } from "better-auth/client";
import { zkPassportClient } from "@panacea-id/better-auth/client";
import type { Challenge } from "@panacea-id/protocol";
import type { ProofEnvelope } from "@panacea-id/better-auth";

export type DraftClaim = {
  age: number;
  nationality: string;
  personToken: string;
};

let draft: DraftClaim | null = null;

export function setDraftClaim(next: DraftClaim) {
  draft = next;
}

export function personToken(): string {
  const key = "panacea.person";
  const existing = localStorage.getItem(key);
  if (existing) return existing;
  const created = crypto.randomUUID();
  localStorage.setItem(key, created);
  return created;
}

export const authClient = createAuthClient({
  baseURL: window.location.origin,
  basePath: "/api/auth",
  fetchOptions: { credentials: "include" },
  plugins: [
    zkPassportClient({
      present: async (challenge: Challenge) => {
        if (!draft) throw new Error("Enter an age and a nationality first.");
        const response = await fetch("/api/demo/attest", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            challengeId: challenge.id,
            binding: challenge.binding,
            age: draft.age,
            nationality: draft.nationality,
            personToken: draft.personToken,
          }),
        });
        const body = (await response.json()) as ProofEnvelope & { message?: string };
        if (!response.ok) throw new Error(body.message ?? "The development verifier refused this claim.");
        return body;
      },
    }),
  ],
});

export async function proveEligibility(claim: DraftClaim) {
  setDraftClaim(claim);
  const client = authClient as typeof authClient & {
    zkPassport: {
      verify: (input: { policy: string; scope: string }) => Promise<unknown>;
    };
  };
  const result = await client.zkPassport.verify({
    policy: "adultCitizen",
    scope: "harbor-commons",
  });
  if (result && typeof result === "object" && "error" in result && result.error) {
    const error = result.error as { message?: string };
    throw new Error(error.message ?? "Eligibility was not accepted.");
  }
  return result;
}

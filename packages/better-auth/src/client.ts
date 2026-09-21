import type { BetterAuthClientPlugin } from "better-auth/client";
import type { Challenge } from "@panacea-id/protocol";
import type { zkPassport } from "./plugin.js";
import type { ProofEnvelope } from "./proof.js";

export function zkPassportClient(options?: {
  present?: (challenge: Challenge) => Promise<ProofEnvelope>;
}) {
  return {
    id: "zk-passport",
    $InferServerPlugin: {} as ReturnType<typeof zkPassport>,
    getActions: ($fetch: (path: string, options?: { method?: string; body?: unknown }) => Promise<unknown>) => ({
      zkPassport: {
        verify: async (input: { policy: string; scope: string; proof?: ProofEnvelope }) => {
          const challenge = await $fetch("/zk-passport/challenge", {
            method: "POST",
            body: { policy: input.policy, scope: input.scope },
          });
          const challengeData = unwrap<Challenge>(challenge);
          const proof = input.proof ?? (await options?.present?.(challengeData));
          if (!proof) throw new Error("No proof was presented for this challenge");
          return $fetch("/zk-passport/verify", {
            method: "POST",
            body: { proof },
          });
        },
      },
    }),
  } as BetterAuthClientPlugin;
}

function unwrap<T>(response: unknown): T {
  if (response && typeof response === "object" && "error" in response && response.error) {
    const error = response.error as { message?: string };
    throw new Error(error.message ?? "ZKPassport request failed");
  }
  if (response && typeof response === "object" && "data" in response) {
    const data = (response as { data: T | null }).data;
    if (data == null) throw new Error("ZKPassport request failed");
    return data;
  }
  return response as T;
}

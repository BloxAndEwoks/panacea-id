import { describe, expect, it } from "vitest";
import { createCivic, DEVELOPMENT_SECRET, ELECTION_ID, ORIGIN } from "./app.js";
import { blindCredential, createVotingKey, sealBallot, unblindCredential } from "@panacea-id/ballot";
import { signDevelopmentProof } from "@panacea-id/better-auth";

describe("harbor commons", () => {
  it("separates eligibility from the sealed count", async () => {
    const civic = createCivic();
    const person = "person-token-SHOULD-NOT-LEAK";
    const challenge = await civic.app.request(`${ORIGIN}/api/auth/zk-passport/challenge`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ORIGIN },
      body: JSON.stringify({ policy: "adultCitizen", scope: "harbor-commons" }),
    });
    expect(challenge.status).toBe(200);
    const issuedChallenge = (await challenge.json()) as { id: string; binding: string };
    const proof = signDevelopmentProof(DEVELOPMENT_SECRET, {
      challengeId: issuedChallenge.id,
      binding: issuedChallenge.binding,
      uniqueIdentifier: person,
      queryResult: {
        age: { gte: { result: true, expected: 18 } },
        nationality: { in: { result: true, expected: ["SV"] } },
      },
    });
    const verified = await civic.app.request(`${ORIGIN}/api/auth/zk-passport/verify`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ORIGIN },
      body: JSON.stringify({ proof }),
    });
    expect(verified.status).toBe(200);
    const cookie = verified.headers.getSetCookie().map((entry) => entry.split(";")[0]).join("; ");
    const voter = createVotingKey();
    const blinded = blindCredential(ELECTION_ID, voter.publicKey, civic.election.public.rsaPublicKey);
    const eligibility = await civic.app.request("/api/eligibility", {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: JSON.stringify({ blinded: blinded.blinded }),
    });
    expect(eligibility.status).toBe(200);
    const { signature } = (await eligibility.json()) as { signature: string };
    const ballot = sealBallot({
      election: civic.election.public,
      votingKey: voter.publicKey,
      signature: unblindCredential(signature, blinded.blinding, civic.election.public.rsaPublicKey),
      optionIndex: 0,
    });
    const cast = await civic.app.request("/api/ballots", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(ballot),
    });
    expect(cast.status).toBe(200);
    const again = await civic.app.request("/api/ballots", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(ballot),
    });
    expect(again.status).toBe(400);

    const stateBefore = await civic.app.request("/api/state");
    const published = await stateBefore.json();
    const serialized = JSON.stringify(published);
    expect(serialized).not.toContain(person);
    expect(serialized).not.toContain("subject");
    expect(JSON.stringify(civic.desk.log())).not.toContain(voter.publicKey);
    expect(JSON.stringify(civic.desk.log())).toContain("harbor-commons");

    for (const index of [1, 3]) {
      const released = await civic.app.request(`/api/trustees/${index}/release`, {
        method: "POST",
        headers: { "x-trustee-passphrase": index === 1 ? "release-harbor" : "release-assembly" },
      });
      expect(released.status).toBe(200);
    }
    const opened = (await (await civic.app.request("/api/state")).json()) as {
      tally: { counts: number[] };
    };
    expect(opened.tally.counts).toEqual([1, 0, 0, 0]);
  });
});

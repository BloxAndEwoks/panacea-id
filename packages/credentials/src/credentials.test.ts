import { generateRsaKeypair } from "@panacea-id/ballot/node";
import {
  BulletinBoard,
  blindCredential,
  createElection,
  createVotingKey,
  sealBallot,
  unblindCredential,
} from "@panacea-id/ballot";
import { describe, expect, it } from "vitest";
import { EligibilityDesk } from "./index.js";

describe("eligibility desk", () => {
  it("issues one blinded credential and keeps the voting key out of its log", () => {
    const keys = generateRsaKeypair();
    const desk = new EligibilityDesk(keys.privateKey, keys.publicKey, (subjectId) => subjectId === "subject-ada");
    const voter = createVotingKey();
    const blinded = blindCredential("harbor-commons", voter.publicKey, keys.publicKey);
    const { signature } = desk.issue({
      subjectId: "subject-ada",
      electionId: "harbor-commons",
      blinded: blinded.blinded,
    });
    expect(JSON.stringify(desk.log())).not.toContain(voter.publicKey);
    expect(JSON.stringify(desk.log())).not.toContain(blinded.blinded);
    expect(JSON.stringify(desk.log())).not.toContain(signature);

    const election = createElection({
      id: "harbor-commons",
      options: ["Mangrove nursery", "Night clinic"],
      threshold: 1,
      trustees: 1,
      rsaPublicKey: keys.publicKey,
    });
    const board = new BulletinBoard(election.public);
    board.submit(
      sealBallot({
        election: election.public,
        votingKey: voter.publicKey,
        signature: unblindCredential(signature, blinded.blinding, keys.publicKey),
        optionIndex: 1,
      }),
    );
    expect(JSON.stringify(board.entries())).not.toContain("subject-ada");
    expect(() =>
      desk.issue({
        subjectId: "subject-ada",
        electionId: "harbor-commons",
        blinded: blinded.blinded,
      }),
    ).toThrow(/already issued/);
    expect(() =>
      desk.issue({
        subjectId: "subject-no",
        electionId: "harbor-commons",
        blinded: blinded.blinded,
      }),
    ).toThrow(/not eligible/);
  });
});

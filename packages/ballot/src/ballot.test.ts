import { describe, expect, it } from "vitest";
import { generateRsaKeypair } from "./node.js";
import {
  BulletinBoard,
  blindCredential,
  createElection,
  createVotingKey,
  openTally,
  releaseShare,
  sealBallot,
  signBlinded,
  sumBoardColumns,
  unblindCredential,
  verifyPublishedTally,
} from "./index.js";

describe("sealed plurality ballots", () => {
  it("tallies two sealed choices, rejects a second vote, and lets an outsider recompute the count", () => {
    const keys = generateRsaKeypair();
    const election = createElection({
      id: "harbor-commons",
      options: ["Mangrove nursery", "Night clinic", "Public well"],
      purse: 100,
      threshold: 2,
      trustees: 3,
      rsaPublicKey: keys.publicKey,
    });
    const board = new BulletinBoard(election.public);
    const choices = [0, 2, 0];
    const subjectIds = ["subject-alice", "subject-basil", "subject-cora"];
    const votingKeys: string[] = [];

    for (const [index, choice] of choices.entries()) {
      const voter = createVotingKey();
      votingKeys.push(voter.publicKey);
      const blinded = blindCredential(election.public.id, voter.publicKey, keys.publicKey);
      expect(blinded.blinded).not.toContain(voter.publicKey);
      const signature = unblindCredential(
        signBlinded(blinded.blinded, keys.privateKey),
        blinded.blinding,
        keys.publicKey,
      );
      board.submit(
        sealBallot({
          election: election.public,
          votingKey: voter.publicKey,
          signature,
          optionIndex: choice!,
        }),
      );
      expect(() =>
        board.submit(
          sealBallot({
            election: election.public,
            votingKey: voter.publicKey,
            signature,
            optionIndex: choice!,
          }),
        ),
      ).toThrow(/already voted/);
    }

    const summed = sumBoardColumns(board.entries(), election.public.options.length);
    const partials = [0, 2].map((trustee) =>
      releaseShare({
        election: election.public,
        trustee: election.trustees[trustee]!,
        summed,
      }),
    );
    const tally = openTally({ election: election.public, board, partials });
    expect(tally.counts).toEqual([2, 0, 1]);
    expect(tally.allocation).toEqual([67, 0, 33]);
    expect(tally.allocation.reduce((sum, share) => sum + share, 0)).toBe(100);
    expect(
      verifyPublishedTally({
        election: election.public,
        entries: board.entries(),
        tally,
      }),
    ).toBe(true);

    const published = JSON.stringify(board.entries());
    for (const subjectId of subjectIds) expect(published).not.toContain(subjectId);
    const tampered = structuredClone(board.entries());
    tampered[0]!.ballot.ciphertexts[0]!.A = tampered[1]!.ballot.ciphertexts[0]!.A;
    expect(
      verifyPublishedTally({
        election: election.public,
        entries: tampered,
        tally,
      }),
    ).toBe(false);

    const badAllocation = structuredClone(tally);
    badAllocation.allocation = [100, 0, 0];
    expect(
      verifyPublishedTally({
        election: election.public,
        entries: board.entries(),
        tally: badAllocation,
      }),
    ).toBe(false);

    const badShare = structuredClone(tally);
    badShare.partials[0]!.options[0]!.D = badShare.partials[1]!.options[0]!.D;
    expect(
      verifyPublishedTally({
        election: election.public,
        entries: board.entries(),
        tally: badShare,
      }),
    ).toBe(false);
    expect(votingKeys.every((key) => published.includes(key))).toBe(true);
  });
});

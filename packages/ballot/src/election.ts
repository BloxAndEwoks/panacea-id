import { canonicalJson } from "@panacea-id/protocol";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  addCiphertexts,
  ciphertextJson,
  discreteLog,
  encrypt,
  keygen,
  lagrangeAtZero,
  proveBit,
  proveSum,
  shareSecret,
  verifyBit,
  verifySum,
  type BitProofJson,
  type CiphertextJson,
  type SumProofJson,
} from "./elgamal.js";
import {
  bigToHex,
  hashToScalar,
  hexToBig,
  modN,
  multiply,
  multiplyG,
  pointBytes,
  pointFromHex,
  pointHex,
  type Point,
} from "./group.js";
import { verifyCredential, type RsaPublicKey } from "./rsa.js";

export type ElectionPublic = {
  id: string;
  options: readonly string[];
  /** Integer purse divided across options by the opened vote counts. */
  purse: number;
  publicKey: string;
  threshold: number;
  commitments: readonly { index: number; commitment: string }[];
  rsaPublicKey: RsaPublicKey;
};

export type TrusteeShare = { index: number; share: string; commitment: string };

export type ElectionSecrets = {
  public: ElectionPublic;
  trustees: TrusteeShare[];
};

export function createElection(input: {
  id: string;
  options: readonly string[];
  purse: number;
  threshold: number;
  trustees: number;
  rsaPublicKey: RsaPublicKey;
}): ElectionSecrets {
  const { secret, publicKey } = keygen();
  const shares = shareSecret(secret, input.threshold, input.trustees);
  const trustees = shares.map((share) => ({
    index: share.index,
    share: bigToHex(share.share),
    commitment: pointHex(multiplyG(share.share)),
  }));
  return {
    public: {
      id: input.id,
      options: [...input.options],
      purse: assertPurse(input.purse),
      publicKey: pointHex(publicKey),
      threshold: input.threshold,
      commitments: trustees.map(({ index, commitment }) => ({ index, commitment })),
      rsaPublicKey: input.rsaPublicKey,
    },
    trustees,
  };
}

export type SealedBallot = {
  electionId: string;
  votingKey: string;
  signature: string;
  ciphertexts: CiphertextJson[];
  bitProofs: BitProofJson[];
  sumProof: SumProofJson;
};

export function createVotingKey(): { secret: string; publicKey: string } {
  const key = keygen();
  return { secret: bigToHex(key.secret), publicKey: pointHex(key.publicKey) };
}

export function sealBallot(input: {
  election: ElectionPublic;
  votingKey: string;
  signature: string;
  optionIndex: number;
}): SealedBallot {
  if (input.optionIndex < 0 || input.optionIndex >= input.election.options.length) {
    throw new Error("Option is not on this ballot");
  }
  canonicalVotingKey(input.votingKey);
  const publicKey = pointFromHex(input.election.publicKey);
  const ciphertexts = [];
  const bitProofs = [];
  let randomnessSum = 0n;
  for (let index = 0; index < input.election.options.length; index += 1) {
    const message = (index === input.optionIndex ? 1 : 0) as 0 | 1;
    const sealed = encrypt(BigInt(message), publicKey);
    randomnessSum = modN(randomnessSum + sealed.randomness);
    const json = ciphertextJson(sealed);
    ciphertexts.push(json);
    bitProofs.push(
      proveBit({
        electionId: input.election.id,
        optionIndex: index,
        message,
        randomness: sealed.randomness,
        ciphertext: sealed,
        publicKey,
      }),
    );
  }
  const summed = ciphertexts.reduce((left, right) => addCiphertexts(left, right));
  return {
    electionId: input.election.id,
    votingKey: canonicalVotingKey(input.votingKey),
    signature: input.signature,
    ciphertexts,
    bitProofs,
    sumProof: proveSum({
      electionId: input.election.id,
      randomness: randomnessSum,
      summed,
      publicKey,
    }),
  };
}

export function ballotIsValid(ballot: SealedBallot, election: ElectionPublic): boolean {
  if (ballot.electionId !== election.id) return false;
  if (ballot.ciphertexts.length !== election.options.length) return false;
  if (ballot.bitProofs.length !== election.options.length) return false;
  try {
    canonicalVotingKey(ballot.votingKey);
  } catch {
    return false;
  }
  if (!verifyCredential(election.id, ballot.votingKey, ballot.signature, election.rsaPublicKey)) return false;
  const publicKey = pointFromHex(election.publicKey);
  for (let index = 0; index < ballot.ciphertexts.length; index += 1) {
    const ciphertext = ballot.ciphertexts[index];
    const proof = ballot.bitProofs[index];
    if (!ciphertext || !proof) return false;
    if (!verifyBit({ electionId: election.id, optionIndex: index, ciphertext, publicKey, proof })) return false;
  }
  const summed = ballot.ciphertexts.reduce((left, right) => addCiphertexts(left, right));
  return verifySum({ electionId: election.id, summed, publicKey, proof: ballot.sumProof });
}

function canonicalVotingKey(votingKey: string): string {
  const canonical = pointHex(pointFromHex(votingKey));
  if (canonical !== votingKey) throw new Error("Voting key is not canonical");
  return canonical;
}

export type BoardEntry = {
  ballot: SealedBallot;
  previousHash: string;
  hash: string;
};

const GENESIS = "00".repeat(32);

export class BulletinBoard {
  private readonly rows: BoardEntry[] = [];
  private readonly seen = new Set<string>();
  private frozenHash: string | null = null;

  constructor(private readonly election: ElectionPublic) {}

  submit(ballot: SealedBallot): BoardEntry {
    if (this.frozenHash) throw new Error("The bulletin board is frozen");
    if (!ballotIsValid(ballot, this.election)) throw new Error("Ballot failed verification");
    if (this.seen.has(ballot.votingKey)) throw new Error("This credential has already voted");
    const previousHash = this.rows.at(-1)?.hash ?? GENESIS;
    const hash = bytesToHex(
      sha256(new TextEncoder().encode(`${previousHash}${canonicalJson(ballot)}`)),
    );
    const entry = { ballot, previousHash, hash };
    this.rows.push(entry);
    this.seen.add(ballot.votingKey);
    return entry;
  }

  freeze(): string {
    this.frozenHash = this.rows.at(-1)?.hash ?? GENESIS;
    return this.frozenHash;
  }

  entries(): readonly BoardEntry[] {
    return this.rows;
  }

  snapshotHash(): string {
    return this.frozenHash ?? this.rows.at(-1)?.hash ?? GENESIS;
  }
}

export type OptionShare = { D: string; e: string; z: string };
export type PartialDecrypt = { index: number; options: OptionShare[] };

export function releaseShare(input: {
  election: ElectionPublic;
  trustee: TrusteeShare;
  summed: CiphertextJson[];
}): PartialDecrypt {
  const share = hexToBig(input.trustee.share);
  if (pointHex(multiplyG(share)) !== input.trustee.commitment) {
    throw new Error("Trustee share does not match its commitment");
  }
  const options = input.summed.map((ciphertext, optionIndex) => {
    const A = pointFromHex(ciphertext.A);
    const D = multiply(A, share);
    const nonce = keygen().secret;
    const t1 = multiplyG(nonce);
    const t2 = multiply(A, nonce);
    const challenge = hashToScalar("panacea.partial.v1", [
      new TextEncoder().encode(input.election.id),
      new TextEncoder().encode(String(input.trustee.index)),
      new TextEncoder().encode(String(optionIndex)),
      pointBytes(pointFromHex(input.trustee.commitment)),
      pointBytes(A),
      pointBytes(D),
      pointBytes(t1),
      pointBytes(t2),
    ]);
    return {
      D: pointHex(D),
      e: bigToHex(challenge),
      z: bigToHex(modN(nonce + challenge * share)),
    };
  });
  return { index: input.trustee.index, options };
}

export type PublishedTally = {
  electionId: string;
  boardHash: string;
  counts: number[];
  /** Largest-remainder shares of `election.purse`. Sums to the purse when anyone voted. */
  allocation: number[];
  partials: PartialDecrypt[];
};

/** Split an integer purse by vote counts. The remainders go to the largest fractional shares. */
export function allocatePurse(counts: readonly number[], purse: number): number[] {
  const budget = assertPurse(purse);
  if (counts.some((count) => !Number.isInteger(count) || count < 0)) {
    throw new Error("Vote counts must be non-negative integers");
  }
  const total = counts.reduce((sum, count) => sum + count, 0);
  if (total === 0) return counts.map(() => 0);
  const shares = counts.map((count) => Math.floor((budget * count) / total));
  let remainder = budget - shares.reduce((sum, share) => sum + share, 0);
  const ranked = counts
    .map((count, index) => ({ index, remainder: (budget * count) % total }))
    .sort((left, right) => right.remainder - left.remainder || left.index - right.index);
  for (const item of ranked) {
    if (remainder === 0) break;
    shares[item.index] = (shares[item.index] ?? 0) + 1;
    remainder -= 1;
  }
  return shares;
}

function assertPurse(purse: number): number {
  if (!Number.isInteger(purse) || purse < 0) throw new Error("Purse must be a non-negative integer");
  return purse;
}

export function openTally(input: {
  election: ElectionPublic;
  board: BulletinBoard;
  partials: readonly PartialDecrypt[];
  maxBallots?: number;
}): PublishedTally {
  const boardHash = input.board.freeze();
  const tally = combine({
    election: input.election,
    entries: input.board.entries(),
    boardHash,
    partials: input.partials,
    maxBallots: input.maxBallots ?? 10_000,
  });
  return tally;
}

export function verifyPublishedTally(input: {
  election: ElectionPublic;
  entries: readonly BoardEntry[];
  tally: PublishedTally;
  maxBallots?: number;
}): boolean {
  try {
    const recomputed = combine({
      election: input.election,
      entries: input.entries,
      boardHash: input.tally.boardHash,
      partials: input.tally.partials,
      maxBallots: input.maxBallots ?? 10_000,
    });
    return (
      recomputed.boardHash === chainHash(input.entries) &&
      canonicalJson(recomputed.counts) === canonicalJson(input.tally.counts) &&
      canonicalJson(recomputed.allocation) === canonicalJson(input.tally.allocation)
    );
  } catch {
    return false;
  }
}

function chainHash(entries: readonly BoardEntry[]): string {
  let previous = GENESIS;
  for (const entry of entries) {
    if (entry.previousHash !== previous) throw new Error("Bulletin board hash chain broke");
    const hash = bytesToHex(
      sha256(new TextEncoder().encode(`${previous}${canonicalJson(entry.ballot)}`)),
    );
    if (hash !== entry.hash) throw new Error("Bulletin board entry was modified");
    previous = hash;
  }
  return previous;
}

function combine(input: {
  election: ElectionPublic;
  entries: readonly BoardEntry[];
  boardHash: string;
  partials: readonly PartialDecrypt[];
  maxBallots: number;
}): PublishedTally {
  if (chainHash(input.entries) !== input.boardHash) throw new Error("Tally is for a different board");
  for (const entry of input.entries) {
    if (!ballotIsValid(entry.ballot, input.election)) throw new Error("Board contains an invalid ballot");
  }
  const indexes = new Set<number>();
  for (const partial of input.partials) {
    if (indexes.has(partial.index)) throw new Error("Duplicate trustee share");
    indexes.add(partial.index);
  }
  if (input.partials.length < input.election.threshold) throw new Error("Not enough trustee shares");
  const used = [...input.partials].sort((left, right) => left.index - right.index);
  const parties = used.map((partial) => partial.index);
  const publicKey = pointFromHex(input.election.publicKey);
  let reconstructed = pointFromHex("00");
  for (const partial of used) {
    const commitment = input.election.commitments.find((item) => item.index === partial.index);
    if (!commitment) throw new Error("Unknown trustee");
    const lambda = lagrangeAtZero(partial.index, parties);
    reconstructed = reconstructed.add(multiply(pointFromHex(commitment.commitment), lambda));
  }
  if (!reconstructed.equals(publicKey)) throw new Error("Shares do not match the election key");

  const summed = sumBoardColumns(input.entries, input.election.options.length);
  const counts: number[] = [];
  for (let option = 0; option < summed.length; option += 1) {
    const column = summed[option];
    if (!column) throw new Error("Missing column");
    let secretTimesA = pointFromHex("00");
    for (const partial of used) {
      const share = partial.options[option];
      const commitment = input.election.commitments.find((item) => item.index === partial.index);
      if (!share || !commitment) throw new Error("Trustee skipped an option");
      if (!partialProofValid({
        electionId: input.election.id,
        trusteeIndex: partial.index,
        optionIndex: option,
        commitment: commitment.commitment,
        ciphertext: column,
        share,
      })) {
        throw new Error("Trustee share proof failed");
      }
      const lambda = lagrangeAtZero(partial.index, parties);
      secretTimesA = secretTimesA.add(multiply(pointFromHex(share.D), lambda));
    }
    const message = pointFromHex(column.B).subtract(secretTimesA);
    const count = discreteLog(message, input.maxBallots);
    if (count === null) throw new Error("Tally is outside the published bound");
    counts.push(count);
  }
    return {
      electionId: input.election.id,
      boardHash: input.boardHash,
      counts,
      allocation: allocatePurse(counts, input.election.purse),
      partials: used,
    };
}

export function sumBoardColumns(entries: readonly BoardEntry[], options: number): CiphertextJson[] {
  const columns: CiphertextJson[] = [];
  for (let option = 0; option < options; option += 1) {
    let column: CiphertextJson | null = null;
    for (const entry of entries) {
      const ciphertext = entry.ballot.ciphertexts[option];
      if (!ciphertext) throw new Error("Ballot is missing an option");
      column = column ? addCiphertexts(column, ciphertext) : ciphertext;
    }
    if (!column) {
      column = { A: "00", B: "00" };
    }
    columns.push(column);
  }
  return columns;
}

function partialProofValid(input: {
  electionId: string;
  trusteeIndex: number;
  optionIndex: number;
  commitment: string;
  ciphertext: CiphertextJson;
  share: OptionShare;
}): boolean {
  const A = pointFromHex(input.ciphertext.A);
  const D = pointFromHex(input.share.D);
  const commitment = pointFromHex(input.commitment);
  const challenge = hexToBig(input.share.e);
  const response = hexToBig(input.share.z);
  const t1 = multiplyG(response).subtract(multiply(commitment, challenge));
  const t2 = multiply(A, response).subtract(multiply(D, challenge));
  const expected = hashToScalar("panacea.partial.v1", [
    new TextEncoder().encode(input.electionId),
    new TextEncoder().encode(String(input.trusteeIndex)),
    new TextEncoder().encode(String(input.optionIndex)),
    pointBytes(commitment),
    pointBytes(A),
    pointBytes(D),
    pointBytes(t1),
    pointBytes(t2),
  ]);
  return expected === challenge;
}

export function electionPublicKey(election: ElectionPublic): Point {
  return pointFromHex(election.publicKey);
}

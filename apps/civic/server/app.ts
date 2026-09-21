import { Hono } from "hono";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { signDevelopmentProof, zkPassport } from "@panacea-id/better-auth";
import { generateRsaKeypair } from "@panacea-id/ballot/node";
import {
  BulletinBoard,
  blindCredential,
  createElection,
  createVotingKey,
  openTally,
  releaseShare,
  sealBallot,
  sumBoardColumns,
  unblindCredential,
  verifyPublishedTally,
  type BoardEntry,
  type ElectionPublic,
  type PartialDecrypt,
  type PublishedTally,
  type SealedBallot,
  type TrusteeShare,
} from "@panacea-id/ballot";
import { EligibilityDesk } from "@panacea-id/credentials";

export const ORIGIN = "http://127.0.0.1:5173";
export const ELECTION_ID = "harbor-commons";
export const DEVELOPMENT_SECRET = "harbor-commons-development-verifier";
const TRUSTEE_PASSPHRASES = ["release-harbor", "release-clinic", "release-assembly"] as const;

export const PROJECTS = [
  "Mangrove nursery",
  "Night clinic hours",
  "Public well repair",
  "Assembly hall",
] as const;

type Memory = Record<string, unknown[]>;

type VerificationRow = {
  userId: string;
  subjectId: string;
  claims: string;
  assurance: string;
  policyId: string;
  scope: string;
  purpose: string;
};

export type PublicState = {
  election: ElectionPublic;
  projects: readonly string[];
  board: readonly BoardEntry[];
  tally: PublishedTally | null;
  released: number[];
  trustees: { index: number; name: string; passphrase: string }[];
  verifier: "development";
  limitations: string[];
};

export function createCivic() {
  const memory: Memory = {
    user: [],
    session: [],
    account: [],
    verification: [],
  };
  const keys = generateRsaKeypair();
  const election = createElection({
    id: ELECTION_ID,
    options: PROJECTS,
    threshold: 2,
    trustees: 3,
    rsaPublicKey: keys.publicKey,
  });
  const board = new BulletinBoard(election.public);
  const desk = new EligibilityDesk(keys.privateKey, keys.publicKey, (subjectId) =>
    Boolean(subjectId),
  );
  const released = new Map<number, PartialDecrypt>();
  let tally: PublishedTally | null = null;

  const auth = betterAuth({
    baseURL: ORIGIN,
    secret: "panacea-harbor-commons-auth-secret-32",
    basePath: "/api/auth",
    database: memoryAdapter(memory),
    trustedOrigins: [ORIGIN, "http://localhost:5173"],
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

  const app = new Hono();

  app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));

  app.get("/api/state", (c) => c.json(publicState()));

  app.post("/api/demo/attest", async (c) => {
    const body = (await c.req.json()) as {
      challengeId?: string;
      binding?: string;
      age?: number;
      nationality?: string;
      personToken?: string;
    };
    if (!body.challengeId || !body.binding || !body.personToken) {
      return c.json({ message: "The development verifier needs a challenge and a person token." }, 400);
    }
    if (!Number.isInteger(body.age) || body.age! < 1 || body.age! > 120) {
      return c.json({ message: "Enter an age between 1 and 120." }, 400);
    }
    if (!/^[A-Z]{2}$/.test(body.nationality ?? "")) {
      return c.json({ message: "Enter a two-letter nationality code." }, 400);
    }
    const proof = signDevelopmentProof(DEVELOPMENT_SECRET, {
      challengeId: body.challengeId,
      binding: body.binding,
      uniqueIdentifier: body.personToken,
      queryResult: {
        age: { gte: { result: body.age! >= 18, expected: 18 } },
        nationality: {
          in: { result: body.nationality === "SV", expected: ["SV"] },
        },
      },
    });
    return c.json(proof);
  });

  app.post("/api/eligibility", async (c) => {
    const session = await auth.api.getSession({ headers: c.req.raw.headers });
    if (!session) return c.json({ message: "Prove eligibility before asking for a voting credential." }, 401);
    const subject = verificationFor(session.user.id);
    if (!subject) return c.json({ message: "No eligibility record is stored for this session." }, 403);
    const body = (await c.req.json()) as { blinded?: string };
    if (!body.blinded) return c.json({ message: "Missing blinded credential request." }, 400);
    try {
      const issued = desk.issue({
        subjectId: subject.subjectId,
        electionId: ELECTION_ID,
        blinded: body.blinded,
      });
      return c.json({ signature: issued.signature });
    } catch (error) {
      return c.json({ message: error instanceof Error ? error.message : "Issuance failed" }, 400);
    }
  });

  app.post("/api/ballots", async (c) => {
    const ballot = (await c.req.json()) as SealedBallot;
    try {
      const entry = board.submit(ballot);
      return c.json({ hash: entry.hash });
    } catch (error) {
      return c.json({ message: error instanceof Error ? error.message : "Ballot rejected" }, 400);
    }
  });

  app.post("/api/trustees/:index/release", async (c) => {
    const index = Number(c.req.param("index"));
    const trustee = election.trustees[index - 1];
    if (!trustee || index < 1 || index > 3) return c.json({ message: "Unknown trustee." }, 404);
    const passphrase = c.req.header("x-trustee-passphrase") ?? "";
    if (passphrase !== TRUSTEE_PASSPHRASES[index - 1]) {
      return c.json({ message: "That release phrase does not match this trustee." }, 403);
    }
    if (tally) return c.json(publicState());
    board.freeze();
    if (!released.has(index)) {
      released.set(
        index,
        releaseShare({
          election: election.public,
          trustee,
          summed: sumBoardColumns(board.entries(), PROJECTS.length),
        }),
      );
    }
    if (released.size >= election.public.threshold) {
      tally = openTally({
        election: election.public,
        board,
        partials: [...released.values()],
      });
    }
    return c.json(publicState());
  });

  function verificationFor(userId: string): VerificationRow | null {
    const rows = (memory.zkVerification ?? []) as VerificationRow[];
    return rows.find((row) => row.userId === userId) ?? null;
  }

  function publicState(): PublicState {
    return {
      election: election.public,
      projects: PROJECTS,
      board: board.entries(),
      tally,
      released: [...released.keys()],
      trustees: [
        { index: 1, name: "Harbor clerk", passphrase: TRUSTEE_PASSPHRASES[0] },
        { index: 2, name: "Clinic board", passphrase: TRUSTEE_PASSPHRASES[1] },
        { index: 3, name: "Assembly chair", passphrase: TRUSTEE_PASSPHRASES[2] },
      ],
      verifier: "development",
      limitations: [
        "A phone at home cannot stop someone standing over the voter.",
        "Malware can change a selection before it is sealed.",
        "This count is a civic consultation, not a binding election.",
      ],
    };
  }

  return { app, desk, board, memory, election, auth };
}

export {
  blindCredential,
  createVotingKey,
  sealBallot,
  unblindCredential,
  verifyPublishedTally,
};
export type { ElectionPublic, SealedBallot, TrusteeShare };

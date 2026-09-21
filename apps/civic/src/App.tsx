import { useEffect, useState, type FormEvent } from "react";
import {
  blindCredential,
  createVotingKey,
  sealBallot,
  unblindCredential,
  verifyPublishedTally,
  type PublishedTally,
} from "@panacea-id/ballot";
import { personToken, proveEligibility } from "./auth.js";
import type { PublicState } from "../server/app.js";

type Receipt = {
  assurance: string;
  policyId: string;
  scope: string;
  purpose: string;
  claims: Record<string, unknown>;
};

const PROJECT_NOTES = [
  "Restore the shoreline that keeps the harbor from eating the road.",
  "Keep the clinic open past dusk for dock workers and night buses.",
  "Fix the three wells that go dry before the rains.",
  "A room for the commons, with a published record of what was decided.",
];

export function App() {
  const [state, setState] = useState<PublicState | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [age, setAge] = useState("18");
  const [nationality, setNationality] = useState("SV");
  const [choice, setChoice] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [voted, setVoted] = useState(() => sessionStorage.getItem("panacea.voted") === "1");
  const [audit, setAudit] = useState<string | null>(null);

  async function refresh() {
    const response = await fetch("/api/state");
    setState((await response.json()) as PublicState);
    const proof = await fetch("/api/auth/zk-passport/receipt", { credentials: "include" });
    if (proof.ok) {
      setReceipt((await proof.json()) as Receipt);
    } else {
      setReceipt(null);
      sessionStorage.removeItem("panacea.voted");
      setVoted(false);
    }
  }

  useEffect(() => {
    void refresh().catch((cause: unknown) => {
      setError(cause instanceof Error ? cause.message : "The ledger did not open.");
    });
  }, []);

  async function onProve(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await proveEligibility({
        age: Number(age),
        nationality: nationality.trim().toUpperCase(),
        personToken: personToken(),
      });
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Eligibility was not accepted.");
    } finally {
      setBusy(false);
    }
  }

  async function onSeal() {
    if (!state) return;
    setBusy(true);
    setError(null);
    try {
      const voter = createVotingKey();
      const blinded = blindCredential(state.election.id, voter.publicKey, state.election.rsaPublicKey);
      const issued = await fetch("/api/eligibility", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ blinded: blinded.blinded }),
      });
      const issuedBody = (await issued.json()) as { signature?: string; message?: string };
      if (!issued.ok || !issuedBody.signature) {
        throw new Error(issuedBody.message ?? "The credential was not issued.");
      }
      const ballot = sealBallot({
        election: state.election,
        votingKey: voter.publicKey,
        signature: unblindCredential(issuedBody.signature, blinded.blinding, state.election.rsaPublicKey),
        optionIndex: choice,
      });
      const cast = await fetch("/api/ballots", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(ballot),
      });
      const castBody = (await cast.json()) as { message?: string };
      if (!cast.ok) throw new Error(castBody.message ?? "The ballot was rejected.");
      sessionStorage.setItem("panacea.voted", "1");
      setVoted(true);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The preference was not sealed.");
    } finally {
      setBusy(false);
    }
  }

  async function onRelease(index: number, passphrase: string) {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(`/api/trustees/${index}/release`, {
        method: "POST",
        headers: { "x-trustee-passphrase": passphrase },
      });
      const body = (await response.json()) as PublicState & { message?: string };
      if (!response.ok) throw new Error(body.message ?? "The share was not released.");
      setState(body);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The share was not released.");
    } finally {
      setBusy(false);
    }
  }

  function onAudit() {
    if (!state?.tally) return;
    const ok = verifyPublishedTally({
      election: state.election,
      entries: state.board,
      tally: state.tally,
    });
    setAudit(ok ? "The published count matches the board." : "The published count does not match the board.");
  }

  if (!state) {
    return (
      <main className="shell">
        <p className="eyebrow">Panacea</p>
        <h1>Opening the ledger…</h1>
      </main>
    );
  }

  return (
    <main className="shell">
      <header className="top">
        <p className="eyebrow">Panacea · Harbor commons</p>
        <p className="cycle">Cycle 01 · consultation, not a binding election</p>
      </header>

      <section className="thesis">
        <h1>One sealed preference. No name on the ballot.</h1>
        <p>
          Prove you may take part. Leave with a credential this booth cannot tie back to you. Two of
          three trustees open the count, and anyone can recompute it.
        </p>
      </section>

      <div className="layout">
        <section className="sheet" aria-labelledby="booth-title">
          <div className="sheet-head">
            <h2 id="booth-title">{receipt ? (voted ? "Bulletin" : "Your preference") : "Eligibility"}</h2>
            <p className="assurance">Development verifier · not a passport check</p>
          </div>

          {!receipt ? (
            <form className="prove" onSubmit={onProve}>
              <p>
                This booth asks only whether you are at least 18 and a citizen of SV. It does not ask
                for a document number, a photograph, or a DUI. The development verifier records the
                claim you type. It does not read a chip.
              </p>
              <label>
                Age
                <input
                  inputMode="numeric"
                  value={age}
                  onChange={(event) => setAge(event.target.value)}
                  required
                />
              </label>
              <label>
                Nationality
                <input
                  value={nationality}
                  maxLength={2}
                  onChange={(event) => setNationality(event.target.value.toUpperCase())}
                  required
                />
              </label>
              <button type="submit" disabled={busy}>
                {busy ? "Checking…" : "Check eligibility"}
              </button>
            </form>
          ) : null}

          {receipt && !voted ? (
            <div className="choose">
              <p className="stored">Stored for this booth</p>
              <pre>{JSON.stringify(receipt.claims, null, 2)}</pre>
              <ul className="projects">
                {state.projects.map((project, index) => (
                  <li key={project}>
                    <button
                      type="button"
                      className={choice === index ? "project selected" : "project"}
                      onClick={() => setChoice(index)}
                      aria-pressed={choice === index}
                    >
                      <span>{project}</span>
                      <small>{PROJECT_NOTES[index]}</small>
                    </button>
                  </li>
                ))}
              </ul>
              <button type="button" className="seal" disabled={busy || state.tally !== null} onClick={() => void onSeal()}>
                {busy ? "Sealing…" : "Seal this preference"}
              </button>
            </div>
          ) : null}

          {voted ? (
            <div className="board">
              <p>
                {state.board.length} sealed {state.board.length === 1 ? "preference" : "preferences"}. The
                booth can see a credential and a ciphertext. It cannot see who sealed them.
              </p>
              <ol className="nibs">
                {state.board.map((entry) => (
                  <li key={entry.hash}>{entry.hash.slice(0, 8)}</li>
                ))}
              </ol>
              {state.tally ? <Tally tally={state.tally} projects={state.projects} onAudit={onAudit} audit={audit} /> : null}
            </div>
          ) : null}

          {error ? <p className="error">{error}</p> : null}
          <div className="perforation" aria-hidden="true" />
        </section>

        <aside className="rail">
          <h2>What this booth keeps</h2>
          <ul>
            <li>Age at least 18, passed</li>
            <li>Nationality in SV, passed</li>
            <li>A pseudonym scoped to this consultation</li>
          </ul>
          <h2>What it does not keep</h2>
          <ul>
            <li>Passport images or chip data</li>
            <li>Document numbers</li>
            <li>A link from your name to your ballot</li>
          </ul>
          <h2>Trustees</h2>
          <p className="fine">
            The count stays sealed until two of these three release a share. In this pilot the phrases
            are printed here so you can watch the threshold. A real deployment would split them across
            people.
          </p>
          <ul className="trustees">
            {state.trustees.map((trustee) => (
              <li key={trustee.index}>
                <div>
                  <strong>{trustee.name}</strong>
                  <code>{trustee.passphrase}</code>
                </div>
                <button
                  type="button"
                  disabled={busy || state.released.includes(trustee.index) || state.board.length === 0}
                  onClick={() => void onRelease(trustee.index, trustee.passphrase)}
                >
                  {state.released.includes(trustee.index) ? "Released" : "Release share"}
                </button>
              </li>
            ))}
          </ul>
          <h2>Limits</h2>
          <ul>
            {state.limitations.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </aside>
      </div>
    </main>
  );
}

function Tally({
  tally,
  projects,
  onAudit,
  audit,
}: {
  tally: PublishedTally;
  projects: readonly string[];
  onAudit: () => void;
  audit: string | null;
}) {
  return (
    <div className="tally">
      <p className="seal-mark">Opened</p>
      <ol>
        {projects.map((project, index) => (
          <li key={project}>
            <span>{project}</span>
            <strong>{tally.counts[index] ?? 0}</strong>
          </li>
        ))}
      </ol>
      <button type="button" onClick={onAudit}>
        Check the count
      </button>
      {audit ? <p className="audit">{audit}</p> : null}
    </div>
  );
}

# Panacea

Privacy-preserving, government-attested identity and civic participation infrastructure.

This repository is a consultation booth, not an election system. A remote phone vote cannot honestly be called unspoofable. Panacea separates the right to take part from the sealed preference, stores only the claims a policy asks for, and publishes a count that an outsider can recompute.

## What is here

| Package | Role |
| --- | --- |
| `@panacea-id/protocol` | Policy DSL, origin-bound challenges, pseudonymous subjects, minimum claims |
| `@panacea-id/better-auth` | Better Auth plugin. Conceptual package name from the design is `@zkpassport/better-auth`; this repo does not own that scope |
| `@panacea-id/credentials` | Eligibility desk. It signs a blinded voting key and forgets it |
| `@panacea-id/ballot` | One-time voting key, sealed plurality ballot, hash-chained bulletin, 2-of-3 tally |
| `apps/civic` | Harbor commons, a fictional public-goods consultation |

The plugin matches the intended developer surface:

```ts
const auth = betterAuth({
  plugins: [
    zkPassport({
      verifier: "server-side",
      origin: "https://harbor.example",
      purpose: "Harbor commons consultation",
      policies: {
        adultCitizen: (query) => query.gte("age", 18).in("nationality", ["SV"]).done(),
      },
    }),
  ],
});

await authClient.zkPassport.verify({
  policy: "adultCitizen",
  scope: "harbor-commons",
});
```

A real deployment passes phone proofs to `@zkpassport/sdk` by setting `zkPassportDomain`. The Harbor commons pilot uses a development verifier and labels every record `assurance: "development"`. It does not read a passport chip, and it does not assume El Salvador's DUI exposes an ICAO trust chain.

Each participant seals one preference. When two trustees open the count, a purse of 100,000 harbor marks is split across the projects by those preferences. Largest remainders make the shares add up to the purse. The independent check recomputes both the vote counts and that split.

## Run

```bash
pnpm install
pnpm test
pnpm dev
```

Open http://127.0.0.1:5173. The API is on port 8787 and is proxied from the app.

## Limits

The booth can show that a preference was eligible and counted once. It cannot stop coercion, malware that changes a selection before encryption, a bad voter roll, or a denial of service. Attributes that are not on the identity document, such as an electoral district, need a separate credential from the authority. ZKPassport can prove what the document says. It cannot infer a district from a passport.

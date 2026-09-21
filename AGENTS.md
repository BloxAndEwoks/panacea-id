# Panacea agent contract

Work lands in this repository through the commands below. There is no separate router.

## Commands

- `pnpm test` runs the privacy and tally suite.
- `pnpm typecheck` is `tsc -b`.
- `pnpm dev` starts the Harbor commons booth at http://127.0.0.1:5173.

## Verification

A change to identity, credentials, or ballots is verified by `pnpm test`, including the Harbor commons story that proves eligibility, casts a sealed ballot, and checks the published board does not contain the person token.

A change to the booth UI is verified in a browser at http://127.0.0.1:5173: prove eligibility, seal a preference, release two trustee shares, and check the count.

## Privacy invariants

- Verification records store predicate outcomes and explicitly disclosed allowlisted claims. They do not store document numbers, images, biometrics, or the ZKPassport unique identifier.
- The eligibility desk stores that a pseudonymous subject was issued a credential. It does not store the voting key.
- The bulletin board stores the voting key, the blind signature, and ciphertexts. It does not store the subject.
- The unique identifier is scoped to an origin and a consultation. It is not a universal person id.

## Merge policy

The owner merges. Do not force-push `main`.

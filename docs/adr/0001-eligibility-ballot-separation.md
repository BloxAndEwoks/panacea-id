# Eligibility and the ballot are different records

The booth needs to know that a person may take part, and it needs to count a sealed preference. Those facts live in different stores.

The verification record keeps an origin-scoped pseudonym and the predicate outcomes the policy asked for. The eligibility desk records that this pseudonym received one blinded credential for one consultation. The issuer sees the blinded integer, not the voting key. The bulletin board accepts the unblinded key, the signature, and the ciphertext. It has no column for the pseudonym.

A passport proof cannot supply an electoral district. District, residency, and any other attribute that is not on the document have to be a separate signed credential from the authority. This pilot does not invent one.

The development verifier is not a government document check. Records it produces are marked `assurance: "development"`. A ZKPassport phone proof is accepted only when `zkPassportDomain` is set, and it is marked `assurance: "zkpassport"`.

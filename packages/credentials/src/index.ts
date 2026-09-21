import { signBlinded, type RsaPrivateKey, type RsaPublicKey } from "@panacea-id/ballot";

export type IssuanceLogEntry = {
  subjectId: string;
  electionId: string;
  issuedAt: string;
};

/**
 * The eligibility desk sees a pseudonymous subject and a blinded credential
 * request. It records that a subject was issued a token. It does not record
 * the voting key, the blinded integer, or the signature.
 */
export class EligibilityDesk {
  private readonly issued = new Map<string, IssuanceLogEntry>();

  constructor(
    private readonly privateKey: RsaPrivateKey,
    readonly publicKey: RsaPublicKey,
    private readonly eligible: (subjectId: string, electionId: string) => boolean,
  ) {}

  issue(input: {
    subjectId: string;
    electionId: string;
    blinded: string;
    now?: Date;
  }): { signature: string } {
    if (!this.eligible(input.subjectId, input.electionId)) {
      throw new Error("This subject is not eligible for the consultation");
    }
    const key = `${input.electionId}|${input.subjectId}`;
    if (this.issued.has(key)) {
      throw new Error("An anonymous credential was already issued for this consultation");
    }
    const signature = signBlinded(input.blinded, this.privateKey);
    this.issued.set(key, {
      subjectId: input.subjectId,
      electionId: input.electionId,
      issuedAt: (input.now ?? new Date()).toISOString(),
    });
    return { signature };
  }

  log(): IssuanceLogEntry[] {
    return [...this.issued.values()];
  }
}

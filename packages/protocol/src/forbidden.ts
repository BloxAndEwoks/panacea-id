/** Keys that must never be written to a verification record or a ballot. */
export const FORBIDDEN_CLAIM_KEYS = [
  "document_number",
  "documentNumber",
  "passport_number",
  "passportNumber",
  "mrz",
  "biometric",
  "biometrics",
  "face",
  "face_image",
  "faceImage",
  "portrait",
  "chip",
  "raw_image",
  "rawImage",
  "photo",
  "uniqueIdentifier",
  "unique_identifier",
] as const;

const forbidden = new Set<string>(FORBIDDEN_CLAIM_KEYS.map((key) => key.toLowerCase()));

export function isForbiddenClaimKey(key: string): boolean {
  return forbidden.has(key.toLowerCase());
}

export function forbiddenKeysIn(value: unknown): string[] {
  const found: string[] = [];
  const visit = (current: unknown) => {
    if (!current || typeof current !== "object") return;
    if (Array.isArray(current)) {
      for (const entry of current) visit(entry);
      return;
    }
    for (const [key, entry] of Object.entries(current as Record<string, unknown>)) {
      if (isForbiddenClaimKey(key)) found.push(key);
      visit(entry);
    }
  };
  visit(value);
  return found;
}

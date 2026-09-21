export { canonicalJson } from "./canonical.js";
export { FORBIDDEN_CLAIM_KEYS, forbiddenKeysIn, isForbiddenClaimKey } from "./forbidden.js";
export {
  assertChallengeFresh,
  challengeBinding,
  createChallenge,
  deriveSubjectId,
  sealVerificationRecord,
} from "./identity.js";
export type { Challenge, VerificationRecord } from "./identity.js";
export {
  QueryBuilder,
  assertPolicySatisfied,
  compilePolicies,
  minimumClaims,
} from "./policy.js";
export type {
  ComparableField,
  DisclosureField,
  MembershipField,
  PolicyDocument,
  Predicate,
  QueryResult,
  StoredClaims,
} from "./policy.js";

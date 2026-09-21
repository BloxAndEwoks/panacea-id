import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalJson } from "./canonical.js";
import { isForbiddenClaimKey } from "./forbidden.js";

export type ComparableField = "age" | "birthdate" | "expiry_date";
export type MembershipField = "nationality" | "issuing_country" | "document_type";
export type DisclosureField =
  | "nationality"
  | "birthdate"
  | "fullname"
  | "firstname"
  | "lastname"
  | "expiry_date"
  | "document_type"
  | "issuing_country"
  | "gender";

const DISCLOSURE_FIELDS = new Set<string>([
  "nationality",
  "birthdate",
  "fullname",
  "firstname",
  "lastname",
  "expiry_date",
  "document_type",
  "issuing_country",
  "gender",
]);

export type Predicate =
  | { op: "gte"; field: ComparableField; value: number | string }
  | { op: "in"; field: MembershipField; values: string[] }
  | { op: "disclose"; field: DisclosureField };

export type PolicyDocument = {
  id: string;
  version: string;
  predicates: Predicate[];
};

export type QueryResultField = {
  gte?: { result: boolean; expected: number | string };
  in?: { result: boolean; expected: string[] };
  disclose?: { result: unknown };
};

export type QueryResult = Record<string, QueryResultField>;

export class QueryBuilder {
  private readonly predicates: Predicate[] = [];

  constructor(private readonly id: string) {}

  gte(field: ComparableField, value: number | string): this {
    this.predicates.push({ op: "gte", field, value });
    return this;
  }

  in(field: MembershipField, values: readonly string[]): this {
    this.predicates.push({ op: "in", field, values: [...values].sort() });
    return this;
  }

  disclose(field: string): this {
    if (isForbiddenClaimKey(field) || !DISCLOSURE_FIELDS.has(field)) {
      throw new Error(
        `Refusing to disclose ${field}. Verification stores the minimum claims a policy asks for, never a document number or biometric.`,
      );
    }
    this.predicates.push({ op: "disclose", field: field as DisclosureField });
    return this;
  }

  done(): PolicyDocument {
    const predicates = this.predicates.map((predicate) => ({ ...predicate }));
    const version = bytesToHex(
      sha256(new TextEncoder().encode(canonicalJson({ id: this.id, predicates }))),
    );
    return { id: this.id, version, predicates };
  }
}

export function compilePolicies(
  definitions: Record<string, (query: QueryBuilder) => PolicyDocument>,
): Record<string, PolicyDocument> {
  const compiled: Record<string, PolicyDocument> = {};
  for (const [id, build] of Object.entries(definitions)) {
    const document = build(new QueryBuilder(id));
    if (document.id !== id) {
      throw new Error(`Policy builder for ${id} returned ${document.id}`);
    }
    compiled[id] = document;
  }
  return compiled;
}

export type StoredClaims = Record<string, unknown>;

export function assertPolicySatisfied(policy: PolicyDocument, result: QueryResult): void {
  for (const predicate of policy.predicates) {
    const field = result[predicate.field];
    if (!field) {
      throw new Error(`Proof is missing ${predicate.field}`);
    }
    if (predicate.op === "gte") {
      if (!field.gte?.result || field.gte.expected !== predicate.value) {
        throw new Error(`${predicate.field} does not satisfy >= ${String(predicate.value)}`);
      }
    } else if (predicate.op === "in") {
      const expected = [...(field.in?.expected ?? [])].sort();
      const wanted = [...predicate.values].sort();
      if (!field.in?.result || canonicalJson(expected) !== canonicalJson(wanted)) {
        throw new Error(`${predicate.field} is outside the allowed set`);
      }
    } else if (field.disclose?.result === undefined) {
      throw new Error(`${predicate.field} was not disclosed`);
    }
  }
}

/** Keep predicate outcomes and explicitly disclosed allowlisted fields. Drop everything else. */
export function minimumClaims(policy: PolicyDocument, result: QueryResult): StoredClaims {
  assertPolicySatisfied(policy, result);
  const claims: StoredClaims = {};
  for (const predicate of policy.predicates) {
    if (predicate.op === "gte") {
      claims[predicate.field] = { gte: predicate.value, passed: true };
    } else if (predicate.op === "in") {
      claims[predicate.field] = { in: [...predicate.values], passed: true };
    } else {
      const disclosed = result[predicate.field]?.disclose?.result;
      claims[predicate.field] = disclosed;
    }
  }
  return claims;
}

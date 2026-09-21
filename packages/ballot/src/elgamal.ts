import {
  ORDER,
  bigToHex,
  bytesToBigInt,
  generator,
  hashToScalar,
  hexToBig,
  identity,
  modN,
  multiply,
  multiplyG,
  pointBytes,
  pointFromHex,
  pointHex,
  randomBytes,
  randomScalar,
  type Point,
} from "./group.js";

export type Ciphertext = { A: Point; B: Point; randomness: bigint };
export type CiphertextJson = { A: string; B: string };
export type BitProofJson = { e0: string; e1: string; z0: string; z1: string };
export type SumProofJson = { e: string; z: string };

export function encrypt(message: bigint, publicKey: Point, randomness = randomScalar()): Ciphertext {
  if (message < 0n) throw new Error("Message must be non-negative");
  return {
    A: multiplyG(randomness),
    B: multiply(publicKey, randomness).add(multiplyG(message)),
    randomness,
  };
}

export function addCiphertexts(left: CiphertextJson, right: CiphertextJson): CiphertextJson {
  const a = pointFromHex(left.A).add(pointFromHex(right.A));
  const b = pointFromHex(left.B).add(pointFromHex(right.B));
  return { A: pointHex(a), B: pointHex(b) };
}

export function ciphertextJson(ciphertext: Ciphertext): CiphertextJson {
  return { A: pointHex(ciphertext.A), B: pointHex(ciphertext.B) };
}

function statementBytes(electionId: string, optionIndex: number, A: Point, B: Point, publicKey: Point): Uint8Array[] {
  return [
    new TextEncoder().encode(electionId),
    new TextEncoder().encode(String(optionIndex)),
    pointBytes(A),
    pointBytes(B),
    pointBytes(publicKey),
  ];
}

export function proveBit(input: {
  electionId: string;
  optionIndex: number;
  message: 0 | 1;
  randomness: bigint;
  ciphertext: Ciphertext;
  publicKey: Point;
}): BitProofJson {
  const { message, randomness, ciphertext, publicKey } = input;
  const other = (message === 0 ? 1 : 0) as 0 | 1;
  const eOther = randomScalar();
  const zOther = randomScalar();
  const simulated = simulateBit(other, ciphertext.A, ciphertext.B, publicKey, eOther, zOther);
  const nonce = randomScalar();
  const realT1 = multiplyG(nonce);
  const realT2 = multiply(publicKey, nonce);
  const t1 = [realT1, realT1] as [Point, Point];
  const t2 = [realT2, realT2] as [Point, Point];
  t1[message] = realT1;
  t2[message] = realT2;
  t1[other] = simulated.T1;
  t2[other] = simulated.T2;
  const challenge = hashToScalar("panacea.bit.v1", [
    ...statementBytes(input.electionId, input.optionIndex, ciphertext.A, ciphertext.B, publicKey),
    pointBytes(t1[0]),
    pointBytes(t2[0]),
    pointBytes(t1[1]),
    pointBytes(t2[1]),
  ]);
  const eReal = modN(challenge - eOther);
  const zReal = modN(nonce + eReal * randomness);
  const e = [eOther, eOther];
  const z = [zOther, zOther];
  e[message] = eReal;
  z[message] = zReal;
  e[other] = eOther;
  z[other] = zOther;
  return { e0: bigToHex(e[0]!), e1: bigToHex(e[1]!), z0: bigToHex(z[0]!), z1: bigToHex(z[1]!) };
}

function simulateBit(bit: 0 | 1, A: Point, B: Point, publicKey: Point, challenge: bigint, response: bigint) {
  const committed = B.add(multiplyG(BigInt(bit)).negate());
  return {
    T1: multiplyG(response).add(multiply(A, challenge).negate()),
    T2: multiply(publicKey, response).add(multiply(committed, challenge).negate()),
  };
}

export function verifyBit(input: {
  electionId: string;
  optionIndex: number;
  ciphertext: CiphertextJson;
  publicKey: Point;
  proof: BitProofJson;
}): boolean {
  const A = pointFromHex(input.ciphertext.A);
  const B = pointFromHex(input.ciphertext.B);
  const e0 = hexToBig(input.proof.e0);
  const e1 = hexToBig(input.proof.e1);
  const z0 = hexToBig(input.proof.z0);
  const z1 = hexToBig(input.proof.z1);
  const zero = simulateBit(0, A, B, input.publicKey, e0, z0);
  const one = simulateBit(1, A, B, input.publicKey, e1, z1);
  const challenge = hashToScalar("panacea.bit.v1", [
    ...statementBytes(input.electionId, input.optionIndex, A, B, input.publicKey),
    pointBytes(zero.T1),
    pointBytes(zero.T2),
    pointBytes(one.T1),
    pointBytes(one.T2),
  ]);
  return modN(e0 + e1) === challenge;
}

export function proveSum(input: {
  electionId: string;
  randomness: bigint;
  summed: CiphertextJson;
  publicKey: Point;
}): SumProofJson {
  const A = pointFromHex(input.summed.A);
  const B = pointFromHex(input.summed.B);
  const nonce = randomScalar();
  const t1 = multiplyG(nonce);
  const t2 = multiply(input.publicKey, nonce);
  const challenge = hashToScalar("panacea.sum.v1", [
    new TextEncoder().encode(input.electionId),
    pointBytes(A),
    pointBytes(B),
    pointBytes(input.publicKey),
    pointBytes(t1),
    pointBytes(t2),
  ]);
  return {
    e: bigToHex(challenge),
    z: bigToHex(modN(nonce + challenge * input.randomness)),
  };
}

export function verifySum(input: {
  electionId: string;
  summed: CiphertextJson;
  publicKey: Point;
  proof: SumProofJson;
}): boolean {
  const A = pointFromHex(input.summed.A);
  const B = pointFromHex(input.summed.B);
  const challenge = hexToBig(input.proof.e);
  const response = hexToBig(input.proof.z);
  const committed = B.add(generator().negate());
  const t1 = multiplyG(response).add(multiply(A, challenge).negate());
  const t2 = multiply(input.publicKey, response).add(multiply(committed, challenge).negate());
  const expected = hashToScalar("panacea.sum.v1", [
    new TextEncoder().encode(input.electionId),
    pointBytes(A),
    pointBytes(B),
    pointBytes(input.publicKey),
    pointBytes(t1),
    pointBytes(t2),
  ]);
  return expected === challenge;
}

export function keygen(): { secret: bigint; publicKey: Point } {
  const secret = randomScalar();
  return { secret, publicKey: multiplyG(secret) };
}

export function lagrangeAtZero(index: number, indexes: readonly number[]): bigint {
  let numerator = 1n;
  let denominator = 1n;
  const xi = BigInt(index);
  for (const other of indexes) {
    if (other === index) continue;
    const xj = BigInt(other);
    numerator = modN(numerator * xj);
    denominator = modN(denominator * modN(xj - xi));
  }
  return modN(numerator * invert(denominator, ORDER));
}

function invert(value: bigint, modulus: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = modulus;
  let newR = modN(value);
  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }
  if (r !== 1n) throw new Error("Scalar is not invertible");
  return modN(t);
}

export function shareSecret(secret: bigint, threshold: number, parties: number): { index: number; share: bigint }[] {
  if (threshold < 1 || threshold > parties) throw new Error("Invalid threshold");
  const coefficients = [modN(secret)];
  for (let degree = 1; degree < threshold; degree += 1) coefficients.push(randomScalar());
  const shares: { index: number; share: bigint }[] = [];
  for (let index = 1; index <= parties; index += 1) {
    let value = 0n;
    let power = 1n;
    const x = BigInt(index);
    for (const coefficient of coefficients) {
      value = modN(value + coefficient * power);
      power = modN(power * x);
    }
    shares.push({ index, share: value });
  }
  return shares;
}

export function discreteLog(point: Point, max: number): number | null {
  if (point.equals(identity())) return 0;
  const step = Math.ceil(Math.sqrt(max + 1));
  const table = new Map<string, number>();
  let baby = identity();
  for (let index = 0; index < step; index += 1) {
    table.set(pointHex(baby), index);
    baby = baby.add(generator());
  }
  const giant = multiplyG(BigInt(step)).negate();
  let probe = point;
  for (let jump = 0; jump <= step; jump += 1) {
    const hit = table.get(pointHex(probe));
    if (hit !== undefined) {
      const message = jump * step + hit;
      if (message <= max && multiplyG(BigInt(message)).equals(point)) return message;
    }
    probe = probe.add(giant);
  }
  return null;
}

export function randomMessage(bytes = 32): bigint {
  return bytesToBigInt(randomBytes(bytes));
}

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import { bytesToBigInt } from "./group.js";

export type RsaPublicKey = { n: string; e: string };
export type RsaPrivateKey = { n: string; d: string };

export type BlindedRequest = {
  blinded: string;
  blinding: string;
};

function hexToBig(hex: string): bigint {
  return BigInt(`0x${hex}`);
}

function bigToHex(value: bigint): string {
  return value.toString(16);
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new Error("Modulus must be positive");
  let result = 1n;
  let value = ((base % modulus) + modulus) % modulus;
  let exp = exponent;
  while (exp > 0n) {
    if (exp & 1n) result = (result * value) % modulus;
    value = (value * value) % modulus;
    exp >>= 1n;
  }
  return result;
}

function gcd(left: bigint, right: bigint): bigint {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

function modInverse(value: bigint, modulus: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = modulus;
  let newR = ((value % modulus) + modulus) % modulus;
  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }
  if (r !== 1n) throw new Error("Value is not invertible");
  if (t < 0n) t += modulus;
  return t;
}

function randomBelow(modulus: bigint): bigint {
  const width = Math.ceil(modulus.toString(16).length / 2);
  let value = bytesToBigInt(randomBytes(width)) % modulus;
  if (value < 2n) value = 2n;
  return value;
}

export function credentialMessage(electionId: string, votingKey: string, modulus: bigint): bigint {
  const digest = sha256(new TextEncoder().encode(`panacea.credential.v1|${electionId}|${votingKey}`));
  let message = bytesToBigInt(digest) % modulus;
  if (message < 2n) message = 2n;
  return message;
}

/** Chaum blind RSA signature request. The issuer sees `blinded`, never the voting key. */
export function blindCredential(electionId: string, votingKey: string, publicKey: RsaPublicKey): BlindedRequest & { message: string } {
  const modulus = hexToBig(publicKey.n);
  const exponent = hexToBig(publicKey.e);
  const message = credentialMessage(electionId, votingKey, modulus);
  let blinding = randomBelow(modulus);
  while (gcd(blinding, modulus) !== 1n) blinding = randomBelow(modulus);
  const blinded = (message * modPow(blinding, exponent, modulus)) % modulus;
  return { blinded: bigToHex(blinded), blinding: bigToHex(blinding), message: bigToHex(message) };
}

export function signBlinded(blinded: string, privateKey: RsaPrivateKey): string {
  const modulus = hexToBig(privateKey.n);
  const exponent = hexToBig(privateKey.d);
  return bigToHex(modPow(hexToBig(blinded), exponent, modulus));
}

export function unblindCredential(signedBlinded: string, blinding: string, publicKey: RsaPublicKey): string {
  const modulus = hexToBig(publicKey.n);
  const signature = (hexToBig(signedBlinded) * modInverse(hexToBig(blinding), modulus)) % modulus;
  return bigToHex(signature);
}

export function verifyCredential(electionId: string, votingKey: string, signature: string, publicKey: RsaPublicKey): boolean {
  const modulus = hexToBig(publicKey.n);
  const exponent = hexToBig(publicKey.e);
  const message = credentialMessage(electionId, votingKey, modulus);
  return modPow(hexToBig(signature), exponent, modulus) === message;
}

export function hexDigest(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

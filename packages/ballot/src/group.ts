import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";

const Point = secp256k1.Point;
export const ORDER = Point.CURVE().n;
const G = Point.BASE;

export type Point = ReturnType<typeof Point.fromHex>;

export function modN(value: bigint): bigint {
  const reduced = value % ORDER;
  return reduced >= 0n ? reduced : reduced + ORDER;
}

export function randomScalar(): bigint {
  const scalar = modN(bytesToBigInt(randomBytes(32)));
  return scalar === 0n ? 1n : scalar;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) + BigInt(byte);
  return value;
}

export function bigToHex(value: bigint): string {
  return value.toString(16);
}

export function hexToBig(hex: string): bigint {
  if (!/^[0-9a-f]+$/i.test(hex)) throw new Error("Expected hex");
  return BigInt(`0x${hex}`);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function u32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

export function hashToScalar(label: string, parts: Uint8Array[]): bigint {
  const chunks = [new TextEncoder().encode(label), u32(parts.length)];
  for (const part of parts) chunks.push(u32(part.length), part);
  const scalar = modN(bytesToBigInt(sha256(concat(chunks))));
  return scalar === 0n ? 1n : scalar;
}

export function generator(): Point {
  return G;
}

export function multiplyG(scalar: bigint): Point {
  const reduced = modN(scalar);
  if (reduced === 0n) return Point.ZERO;
  return G.multiply(reduced);
}

export function multiply(point: Point, scalar: bigint): Point {
  const reduced = modN(scalar);
  if (reduced === 0n) return Point.ZERO;
  return point.multiply(reduced);
}

export function identity(): Point {
  return Point.ZERO;
}

export function pointHex(point: Point): string {
  if (point.is0()) return "00";
  return point.toHex(true);
}

export function pointFromHex(hex: string): Point {
  if (hex === "00") return Point.ZERO;
  const point = Point.fromHex(hex);
  point.assertValidity();
  return point;
}

export function pointBytes(point: Point): Uint8Array {
  if (point.is0()) return new Uint8Array([0]);
  return point.toBytes(true);
}

export { bytesToHex, hexToBytes, randomBytes };

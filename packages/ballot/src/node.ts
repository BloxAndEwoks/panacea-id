import { generateKeyPairSync } from "node:crypto";
import type { RsaPrivateKey, RsaPublicKey } from "./rsa.js";

function jwkToHex(value: string): string {
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  const buffer = Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  return buffer.toString("hex").replace(/^0+/, "") || "0";
}

export function generateRsaKeypair(): { publicKey: RsaPublicKey; privateKey: RsaPrivateKey } {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 65537,
  });
  const jwk = privateKey.export({ format: "jwk" }) as { n: string; e: string; d: string };
  const n = jwkToHex(jwk.n);
  return {
    publicKey: { n, e: jwkToHex(jwk.e) },
    privateKey: { n, d: jwkToHex(jwk.d) },
  };
}

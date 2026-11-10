/**
 * RSA keypair management using jose + Web Crypto.
 *
 * Replaces:
 *   - crypto.generateKeyPairSync  →  generateKeyPair (jose, async)
 *   - rasha pem<->jwk conversion  →  exportSPKI / exportJWK / importSPKI (jose)
 */

import { exportJWK, exportPKCS8, exportSPKI, generateKeyPair, importPKCS8, importSPKI } from "@panva/jose";
import { decrypt, encrypt } from "../crypto.ts";
import type { LTIStorage } from "../storage/lti-storage.ts";

export interface JWKRecord {
  kid: string;
  kty: string;
  alg: string;
  use: string;
  n: string;
  e: string;
}

/**
 * Generate a 4096-bit RSA keypair, encrypt both halves, and store them.
 */
export async function generateAndStorePlatformKeyPair(
  kid: string,
  storage: LTIStorage,
  aesKey: CryptoKey,
): Promise<void> {

  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    modulusLength: 4096,
    extractable: true,
  });

  const publicPem = await exportSPKI(publicKey);
  const privatePem = await exportPKCS8(privateKey);

  const [encPub, encPriv] = await Promise.all([
    encrypt(publicPem, aesKey),
    encrypt(privatePem, aesKey),
  ]);

  await storage.saveKeyPair(kid, encPub, encPriv);
}

/**
 * Retrieve and decrypt the private key for a given kid.
 * Used when signing Deep Linking responses, access token requests, etc.
 */
export async function getPrivateKey(
  kid: string,
  storage: LTIStorage,
  aesKey: CryptoKey,
): Promise<CryptoKey> {
  const encPriv = await storage.getPrivateKey(kid);
  if (!encPriv) throw new Error(`Private key not found for kid: ${kid}`);
  const pem = await decrypt(encPriv, aesKey);
  return importPKCS8(pem, "RS256");
}

/**
 * Retrieve and decrypt the public key for a given kid.
 */
export async function getPublicKey(
  kid: string,
  storage: LTIStorage,
  aesKey: CryptoKey,
): Promise<CryptoKey> {
  const encPub = await storage.getPublicKey(kid);
  if (!encPub) throw new Error(`Public key not found for kid: ${kid}`);
  const pem = await decrypt(encPub, aesKey);
  return importSPKI(pem, "RS256");
}

/**
 * Build the JWKS response body for GET /keys.
 * Decrypts all stored public keys and converts them to JWK format.
 */
export async function buildJwks(
  storage: LTIStorage,
  aesKey: CryptoKey,
): Promise<{ keys: JWKRecord[] }> {
  const encKeys = await storage.getAllPublicKeys();

  const jwks = await Promise.all(
    encKeys.map(async ({ kid, encryptedKey }) => {
      const pem = await decrypt(encryptedKey, aesKey);
      const cryptoKey = await importSPKI(pem, "RS256");
      const jwk = await exportJWK(cryptoKey);
      return { ...jwk, kid, alg: "RS256", use: "sig" } as JWKRecord;
    }),
  );

  return { keys: jwks };
}

/**
 * Generate a random hex string for use as a kid or state parameter.
 * Replaces crypto.randomBytes(n).toString('hex').
 */
export function randomHex(bytes = 16): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

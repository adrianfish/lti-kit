/**
 * OAuth2 client credentials flow for LTI service API calls.
 */

import { SignJWT } from "@panva/jose";
import { getPrivateKey, randomHex } from "../auth/keys.ts";
import type { LTIStorage } from "../storage/storage.ts";
import type { LTIToken, AccessToken } from "../types.ts";

const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Get a cached or freshly-minted OAuth2 access token for the given scopes.
 * Uses the platform's access token endpoint and the tool's private key.
 */
export async function getAccessToken(
  token: LTIToken,
  scopes: string[],
  storage: LTIStorage,
  aesKey: CryptoKey,
): Promise<string> {

  const scopeStr = scopes.sort().join(" ");

  // Try cache first
  const cached = await storage.getAccessToken(token.iss, token.clientId, scopeStr);
  if (cached) return cached.token;

  // We need the platform record to find the token endpoint
  // The token endpoint is stored in the platform record but not in IdToken;
  // callers that need access tokens should pass the platform directly, or we
  // look it up via platformId (kid).  For simplicity we accept it as a parameter
  // via the token context — the platform's accesstokenEndpoint is passed separately.
  throw new Error(
    "getAccessToken requires platformAccessTokenEndpoint — " +
      "pass it explicitly or retrieve the Platform record via storage",
  );
}

/**
 * Full OAuth2 client credentials request.
 * Called once per platform per scope set; result is cached.
 */
export async function requestAccessToken(
  toolDomain: string,
  platformAccessTokenEndpoint: string,
  platformUrl: string,
  clientId: string,
  platformKid: string,
  scopes: string[],
  storage: LTIStorage,
  aesKey: CryptoKey,
): Promise<string | null> {

  const scopeStr = scopes.sort().join(" ");

  // Check cache
  const cached = await storage.getAccessToken(platformUrl, clientId, scopeStr);
  if (cached) return cached.token;

  const privateKey = await getPrivateKey(platformKid, storage, aesKey);
  const now = Math.floor(Date.now() / 1000);

  // Signed client assertion JWT
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "RS256", kid: platformKid })
    //.setIssuer(`https://${toolDomain}/lti`)
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(platformAccessTokenEndpoint)
    .setIssuedAt(now)
    .setExpirationTime(now + 60)
    .setJti(randomHex(16))
    .sign(privateKey);

  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertion,
    scope: scopeStr,
  });

  const res = await fetch(platformAccessTokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!res.ok) {
    console.error(`Access token request failed: ${res.status} ${await res.text()}`);
    return null;
  }

  const data = await res.json();
  const accessToken = data.access_token as string;

  // Use the token's expiry to set the cache ttl
  const expiresIn = (data.expires_in as number) ?? 3600;

  // Cache it
  const record: AccessToken = {
    token: accessToken,
    platformUrl,
    clientId,
    requestedScopes: scopeStr,
    expiresAt: Date.now() + expiresIn * 1000 - 30_000, // 30s safety margin
  };
  await storage.saveAccessToken(record, Math.min(expiresIn * 1000, ACCESS_TOKEN_TTL_MS));

  return accessToken;
}

/**
 * LTI token validation using jose.
 */

import { createRemoteJWKSet, importJWK, importSPKI, jwtVerify, SignJWT } from "@panva/jose";
import { DEEP_LINKING, RESOURCE_LINK } from "../messages.ts";

import type { JWTPayload, JWTVerifyGetKey } from "@panva/jose";
import type { ContextToken, IdToken, Platform } from "../types.ts";
import type { Storage } from "../storage/storage.ts";
import type { LtikPayload } from "../types.ts";

const NONCE_TTL_MS = 10_000; // 10 seconds
const TOKEN_MAX_AGE_SEC = 10; // LTI spec: token freshness

// ---------------------------------------------------------------------------
// LTIK helpers (HS256 signed with the tool's encryption key)
// ---------------------------------------------------------------------------

/** Encode the secret string as a Uint8Array for jose HMAC ops. */
function ltikSecret(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

export async function signLtik(
  payload: LtikPayload,
  secret: string,
): Promise<string> {

  return new SignJWT(payload as unknown as JWTPayload)
    .setProtectedHeader({ alg: "HS256" })
    .sign(ltikSecret(secret));
}

export async function verifyLtik(
  ltik: string,
  secret: string,
): Promise<LtikPayload | null> {

  if (!ltik) return null;

  try {
    const { payload } = await jwtVerify(ltik, ltikSecret(secret));
    return payload as unknown as LtikPayload;
  } catch (error) {
    console.error(error);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Platform token validation
// ---------------------------------------------------------------------------

/**
 * Fetch the JWKS for a platform and return a jose KeyLike suitable for jwtVerify.
 */
function resolvePlatformKey(
  platform: Platform,
  kid: string,
): JWTVerifyGetKey {

  if (platform.jwksUri) {
    return createRemoteJWKSet(new URL(platform.jwksUri));
  }

  throw new Error("No JSON Web Key Set uri supplied (jwksUri)");
}

export interface ValidationResult {
  idToken: IdToken;
  contextToken: ContextToken;
}

/**
 * Full LTI 1.3 token validation pipeline.
 *
 * 1. Decode JWT header to extract kid
 * 2. Resolve verification key from platform config
 * 3. Verify signature + standard JWT claims via jose
 * 4. OIDC claim validation (aud, alg, nonce, maxAge)
 * 5. LTI 1.3 claim validation (message_type, version, deployment_id, etc.)
 * 6. Check + consume nonce
 * 7. Split validated payload into IdToken + ContextToken
 */
export async function validateToken(
  idTokenJwt: string,
  platform: Platform,
  storage: Storage,
  debug: boolean = false,
): Promise<ValidationResult> {
  // Decode header without verifying — we need kid to pick the right key
  const [headerB64] = idTokenJwt.split(".");
  const header = JSON.parse(atob(headerB64.replace(/-/g, "+").replace(/_/g, "/")));
  const kid: string = header.kid;

  const jwkSet: JWTVerifyGetKey = resolvePlatformKey(platform, kid);

  const { payload } = await jwtVerify(idTokenJwt, jwkSet, {
    algorithms: ["RS256"],
    audience: platform.clientId,
    issuer: platform.url,
    maxTokenAge: `${TOKEN_MAX_AGE_SEC}s`,
  });

  // -------------------------------------------------------------------------
  // OIDC validation
  // -------------------------------------------------------------------------
  const nonce = payload.nonce as string | undefined;
  if (!nonce) throw new Error("Missing nonce claim");

  const nonceUsed = await storage.hasNonce(nonce);
  if (nonceUsed) throw new Error("Nonce already used");
  await storage.saveNonce(nonce, NONCE_TTL_MS);

  // -------------------------------------------------------------------------
  // LTI 1.3 claim validation
  // -------------------------------------------------------------------------
  const messageType = payload["https://purl.imsglobal.org/spec/lti/claim/message_type"];
  const version = payload["https://purl.imsglobal.org/spec/lti/claim/version"] as string;
  const deploymentId = payload["https://purl.imsglobal.org/spec/lti/claim/deployment_id"] as string;
  const resourceLink = payload["https://purl.imsglobal.org/spec/lti/claim/resource_link"] as
    | Record<string, unknown>
    | undefined;
  const targetLinkUri = payload["https://purl.imsglobal.org/spec/lti/claim/target_link_uri"] as string | undefined;

  if (!messageType) throw new Error("Missing LTI message_type claim");
  if (version !== "1.3.0") throw new Error(`Invalid LTI version: ${version}`);
  if (!deploymentId) throw new Error("Missing LTI deployment_id claim");
  if (!payload.sub) throw new Error("Missing sub claim");

  if (messageType === RESOURCE_LINK) {
    if (!targetLinkUri) throw new Error("Missing target_link_uri claim");
    if (!resourceLink?.id) throw new Error("Missing resource_link.id claim");
  }

  // -------------------------------------------------------------------------
  // Split into stored records
  // -------------------------------------------------------------------------
  const roles = (payload["https://purl.imsglobal.org/spec/lti/claim/roles"] ?? []) as string[];
  const context = (payload["https://purl.imsglobal.org/spec/lti/claim/context"] ?? {}) as Record<string, unknown>;
  const custom = (payload["https://purl.imsglobal.org/spec/lti/claim/custom"] ?? {}) as Record<string, unknown>;
  const endpoint = payload["https://purl.imsglobal.org/spec/lti/claim/endpoint"] as Record<string, unknown> | undefined;
  const namesRoles = payload["https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice"] as
    | Record<string, unknown>
    | undefined;
  const groups = payload["https://purl.imsglobal.org/spec/lti-gs/claim/groupsservice"] as | Record<string, Array<string> | string> | undefined;
  const grades = payload["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"] as | Record<string, Array<string> | string> | undefined;
  const deepLinkingSettings = payload["https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings"] as
    | Record<string, unknown>
    | undefined;
  const toolPlatform = (payload["https://purl.imsglobal.org/spec/lti/claim/tool_platform"] ?? {}) as Record<string, string>;
  const launchPresentation = (payload["https://purl.imsglobal.org/spec/lti/claim/launch_presentation"] ?? {}) as Record<
    string,
    unknown
  >;
  const lis = (payload["https://purl.imsglobal.org/spec/lti/claim/lis"] ?? {}) as Record<string, unknown>;

  const contextId = (context.id as string) ?? `${deploymentId}:${payload.sub}`;

  const idToken: IdToken = {
    iss: payload.iss!,
    user: payload.sub as string,
    userInfo: {
      given_name: payload.given_name as string | undefined,
      family_name: payload.family_name as string | undefined,
      name: payload.name as string | undefined,
      email: payload.email as string | undefined,
      locale: payload.locale as string | undefined,
    },
    platformInfo: {},
    clientId: platform.clientId,
    platformId: platform.kid,
    deploymentId,
  };

  const contextToken: ContextToken = {
    contextId,
    user: payload.sub as string,
    roles,
    path: "/",
    targetLinkUri: targetLinkUri ?? "/",
    context,
    resource: (resourceLink ?? {}) as Record<string, unknown>,
    custom,
    launchPresentation,
    messageType: messageType as ContextToken["messageType"],
    version,
    deepLinkingSettings,
    toolPlatform,
    lis,
    endpoint,
    namesRoles,
    groups,
    grades,
  };

  if (contextToken.messageType === DEEP_LINKING) {
    if (!contextToken.deepLinkingSettings) throw new Error("No deep_linking_settings supplied");
    if (!contextToken.deepLinkingSettings.deep_link_return_url) throw new Error("No deep_link_return_url supplied");
    if (!contextToken.deepLinkingSettings.accept_types) throw new Error("No accept_types supplied");
    if (!contextToken.deepLinkingSettings.accept_presentation_document_targets) {
      throw new Error("No accept_presentation_document_targets supplied");
    }
  }

  return { idToken, contextToken };
}

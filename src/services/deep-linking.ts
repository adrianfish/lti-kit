/**
 * Deep Linking Service (LTI 1.3 Content Item Selection)
 */

import { SignJWT } from "@panva/jose";
import { getPrivateKey } from "../auth/keys.ts";
import type { Storage } from "../storage/storage.ts";
import type { ContentItem, ContextToken, IdToken, LTIToken } from "../types.ts";

/**
 * Create an auto-submitting HTML form that posts the Deep Linking response
 * back to the platform.
 *
 * @param {platformCode: string; contextId: string; userId: string;} data The params.
 * @param {ContentItem[]} items Content items to return to the platform
 * @param {Storage} storage Storage (to retrieve the private key)
 * @param {CryptoKey} aesKey AES key for decrypting stored private key
 * @param {string} toolUrl The tool's own URL (used as iss in the response JWT)
 *
 * @return {string} The html markup for the deep linking form
 */
export async function createDeepLinkingForm(
  data: { platformCode: string; contextId: string; userId: string; },
  items: ContentItem[],
  storage: Storage,
  aesKey: CryptoKey,
  toolUrl: string,
): Promise<string> {

  if (!data?.contextId || !data?.userId) {
    return "data.contextId and data.userId must be supplied";
  }

  const userIdIndex = data.userId.lastIndexOf("/");
  const userId = data.userId.substring(userIdIndex + 1);

  const contextToken: ContextToken | null = await storage.getContextToken(`${data.contextId}${userId}`);

  if (!contextToken) {
    return `Failed to get context token for ${data.contextId} and ${userId}`;
  }

  const idToken: IdToken | null = await storage.getIdToken(`${data.platformCode}${userId}`);
  if (!idToken) {
    return `Failed to get id token for ${data.platformCode} and ${userId}`;
  }

  const ltiToken: LTIToken = { ...idToken, platformContext: contextToken };

  const message = await createDeepLinkingMessage(ltiToken, items, storage, aesKey, toolUrl);
  const returnUrl = contextToken.deepLinkingSettings?.deep_link_return_url || "";

  // Auto-submitting form
  return `<!DOCTYPE html>
<html>
<body>
  <form id="dlForm" method="POST" action="${escapeHtml(returnUrl as string)}">
    <input type="hidden" name="JWT" value="${escapeHtml(message)}" />
  </form>
  <script>document.getElementById('dlForm').submit();</script>
</body>
</html>`;
}

/**
 * Create a signed Deep Linking response JWT.
 * The caller can embed this in a form or return it directly.
 */
export async function createDeepLinkingMessage(
  token: LTIToken,
  items: ContentItem[],
  storage: Storage,
  aesKey: CryptoKey,
  toolUrl: string,
): Promise<string> {

  const settings = token.platformContext.deepLinkingSettings;

  let data = settings?.data;
  if (!data) {
    const url = new URL(token.platformContext.deepLinkingSettings?.deep_link_return_url as string || "");
    data = url.searchParams.get("data");
  }

  const kid = `${token.iss}\$\$${token.clientId}`;
  const privateKey = await getPrivateKey(kid, storage, aesKey);

  const now = Math.floor(Date.now() / 1000);

  return new SignJWT({
    "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingResponse",
    "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
    "https://purl.imsglobal.org/spec/lti/claim/deployment_id": token.deploymentId,
    "https://purl.imsglobal.org/spec/lti-dl/claim/content_items": items,
    "https://purl.imsglobal.org/spec/lti-dl/claim/data": data,
  })
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuer(token.clientId)
    .setAudience(token.iss)
    .setSubject(token.user)
    .setIssuedAt(now)
    .setExpirationTime(now + 600) // 10-minute validity
    .sign(privateKey);
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

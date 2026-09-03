/**
 * Assignment and Grade Service (AGS) — LTI 1.3
 */
import { requestAccessToken } from "./oauth.ts";
import { buildKeyId } from "../utils/platform-utils.ts";

import type { Storage } from "../storage/storage.ts";
import type { ContextToken, LineItem, LineItemOptions, LTIToken, Platform, Result, Score } from "../types.ts";

const AGS_SCOPE_LINEITEM = "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem";
const AGS_SCOPE_LINEITEM_RO = "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly";
const AGS_SCOPE_SCORE = "https://purl.imsglobal.org/spec/lti-ags/scope/score";
const AGS_SCOPE_RESULT_RO = "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly";

export async function ensureLineItemsCached(
  storage: Storage,
  toolDomain: string,
  aesKey: CryptoKey,
  platformUrl: string,
  clientId: string,
  contextId: string,
  userId: string,
  options?: LineItemOptions,
): Promise<void> {

  if (await storage.hasAnyLineItems(platformUrl, clientId, contextId, options)) {
    console.debug(`Line items already cached for clientId ${clientId}, contextId ${contextId}`);
    return;
  }

  const items: LineItem[] | null = await loadLineItems(storage, toolDomain, aesKey, platformUrl, clientId, contextId, userId, options);
  if (items) {
    items.forEach(item => storage.setLineItem(platformUrl, clientId, contextId, item));
  } else {
    console.warn("No items found");
  }
}

export async function getLineItems(
  storage: Storage,
  toolDomain: string,
  aesKey: CryptoKey,
  platformUrl: string,
  clientId: string,
  contextId: string,
  userId: string,
  options?: LineItemOptions,
): Promise<LineItem[]> {

  await ensureLineItemsCached(storage, toolDomain, aesKey, platformUrl, clientId, contextId, userId, options);
  return storage.getLineItems(platformUrl, clientId, contextId);
}

/** Get all line items for the current context, following pagination. */
async function loadLineItems(
  storage: Storage,
  toolDomain: string,
  aesKey: CryptoKey,
  platformUrl: string,
  clientId: string,
  contextId: string,
  userId: string,
  options?: LineItemOptions,
): Promise<LineItem[] | null> {

  if (!platformUrl || !clientId) {
    console.error("platformUrl and clientId must be supplied");
    return null;
  }

  const contextToken: ContextToken | null = await storage.getContextToken(`${contextId}${userId}`);
  if (!contextToken) return null;

  let url: URL;
  try {
    url = new URL(contextToken.grades?.lineitems as string || "");
  } catch (error) {
    console.error(error);
    return null;
  }

  const platform: Platform | null = await storage.getPlatform(platformUrl, clientId);
  if (!platform) return null;

  const requestedScopes = [ AGS_SCOPE_LINEITEM_RO, AGS_SCOPE_LINEITEM ];

  const accessToken = await requestAccessToken(
    toolDomain,
    platform.accesstokenEndpoint,
    platformUrl,
    clientId,
    buildKeyId(platform),
    requestedScopes,
    storage,
    aesKey,
  );

  if (!accessToken) {
    console.warn("Failed to get access token");
    return null;
  }

  if (options?.resourceId) url.searchParams.set("resource_id", options.resourceId);
  if (options?.tag) url.searchParams.set("tag", options.tag);

  return await fetchAllPages(url.toString(), accessToken, "application/vnd.ims.lis.v2.lineitemcontainer+json");
}

export async function createLineItem(
  storage: Storage,
  toolDomain: string,
  aesKey: CryptoKey,
  platformUrl: string,
  clientId: string,
  contextId: string,
  userId: string,
  lineItem: LineItem,
): Promise<LineItem | null> {

  if (!platformUrl || !clientId) {
    console.error("platformUrl and clientId must be supplied");
    return null;
  }

  const contextToken: ContextToken | null = await storage.getContextToken(`${contextId}${userId}`);
  if (!contextToken) return null;

  let url: URL;
  try {
    url = new URL(contextToken.grades?.lineitems as string || "");
  } catch (error) {
    console.error(error);
    return null;
  }

  const platform: Platform | null = await storage.getPlatform(platformUrl, clientId);
  if (!platform) return null;

  const accessToken = await requestAccessToken(
    toolDomain,
    platform.accesstokenEndpoint,
    platformUrl,
    clientId,
    buildKeyId(platform),
    [AGS_SCOPE_LINEITEM],
    storage,
    aesKey,
  );

  if (!accessToken) {
    console.warn("Failed to get access token");
    return null;
  }

  const res = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/vnd.ims.lis.v2.lineitem+json",
    },
    body: JSON.stringify(lineItem),
  });

  if (!res.ok) throw new Error(`Failed to create line item: ${res.status} ${await res.text()}`);
  return res.json();
}

export async function postScore(
  storage: Storage,
  toolDomain: string,
  aesKey: CryptoKey,
  platformUrl: string,
  clientId: string,
  lineItemUrl: string,
  score: Score,
): Promise<boolean> {

  if (!platformUrl || !clientId) {
    console.error("platformUrl and clientId must be supplied");
    return false;
  }

  const platform: Platform | null = await storage.getPlatform(platformUrl, clientId);
  if (!platform) return false;

  const accessToken = await requestAccessToken(
    toolDomain,
    platform.accesstokenEndpoint,
    platformUrl,
    clientId,
    buildKeyId(platform),
    [AGS_SCOPE_SCORE],
    storage,
    aesKey,
  );

  if (!accessToken) {
    console.warn("Failed to get access token");
    return false;
  }

  const scoreUrl = lineItemUrl.replace(/\/?$/, "/scores");
  const res = await fetch(scoreUrl, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/vnd.ims.lis.v1.score+json",
    },
    body: JSON.stringify({
      ...score,
      timestamp: score.timestamp ?? new Date().toISOString(),
    }),
  });

  return res.ok;
}

/**
 * Get the results for the specified line item.
 *
 * @param {Object} storage The data storage api
 * @param {string} toolDomain The client tool's domain
 * @param {Object} aesKey The tools key
 * @param {string} platformUrl The platform's url (iss)
 * @param {string} clientId The client id as supplied by the platform during launch
 * @param {string} lineItemId The id of the platform line item.
 *
 * @returns A promise containing an array of Result objects or null
 */
export async function getResults(
  storage: Storage,
  toolDomain: string, 
  aesKey: CryptoKey,
  platformUrl: string,
  clientId: string,
  lineItemId: string,
): Promise<Result[] | null> {

  // TODO: Add lazy caching. As results are requested for a line item, cache them at that point.

  if (!platformUrl || !clientId) {
    console.error("platformUrl and clientId must be supplied");
    return  [];
  }

  let results: Result[] | null= await storage.getResults(platformUrl, clientId, lineItemId);

  if (results && results.length > 0) {
    return results;
  }

  const platform: Platform | null = await storage.getPlatform(platformUrl, clientId);
  if (!platform) {
    console.warn(`Failed to get platform for platformUrl ${platformUrl} and clientId ${clientId}`);
    return null;
  }

  const accessToken = await requestAccessToken(
    toolDomain,
    platform.accesstokenEndpoint,
    platformUrl,
    clientId,
    buildKeyId(platform),
    [AGS_SCOPE_RESULT_RO],
    storage,
    aesKey,
  );

  if (!accessToken) {
    console.warn("Failed to get access token");
    return [];
  }

  const resultsUrl = lineItemId.replace(/\/?$/, "/results");
  results = (await fetchAllPages(resultsUrl, accessToken, "application/vnd.ims.lis.v2.resultcontainer+json")) as Result[];
  for (const r of results as Result[]) await storage.setResult(platformUrl, clientId, lineItemId, r);

  return results;
}

async function fetchAllPages(
  url: string,
  accessToken: string,
  accept: string,
): Promise<any[]> {
  const all = [];
  let nextUrl: string | null = url;

  while (nextUrl) {
    const res = await fetch(nextUrl, {
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": accept,
      },
    });

    if (!res.ok) throw new Error(`AGS request failed: ${res.status} ${await res.text()}`);

    const data = await res.json();
    all.push(...(Array.isArray(data) ? data : [ data ]));

    // Follow RFC 5988 Link: <url>; rel="next" header
    nextUrl = parseNextLink(res.headers.get("link"));
  }

  return all;
}

function parseNextLink(linkHeader: string | null): string | null {

  if (!linkHeader) return null;
  for (const part of linkHeader.split(",")) {
    const match = part.match(/<([^>]+)>.*rel="next"/);
    if (match) return match[1];
  }
  return null;
}

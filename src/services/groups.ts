/**
 * Course Groups — LTI 1.3
 */

import { HTTPHeaderLink, HTTPHeaderLinkEntry } from "@hugoalh/http-header-link";
import { requestAccessToken } from "./oauth.ts";
import { buildKeyId } from "../utils/platform-utils.ts";

import type { LTIStorage } from "../storage/lti-storage.ts";
import type { ContextToken, Group, Platform } from "../types.ts";

export async function ensureGroupsCached(
    storage: LTIStorage,
    toolDomain: string,
    aesKey: CryptoKey,
    platformUrl: string,
    clientId: string,
    contextId: string,
    userId: string,
): Promise<void> {

  if (await storage.hasAnyGroups(platformUrl, clientId, contextId)) {
    console.debug(`Groups already cached for clientId ${clientId}, contextId ${contextId}`);
    return;
  }

  await primeGroupsCache(storage, toolDomain, aesKey, platformUrl, clientId, contextId, userId);
}

export async function getGroups(
  storage: LTIStorage,
  toolDomain: string,
  aesKey: CryptoKey,
  platformUrl: string,
  clientId: string,
  contextId: string,
  userId: string,
): Promise<Array<Group>> {

  await ensureGroupsCached(storage, toolDomain, aesKey, platformUrl, clientId, contextId, userId);

  return await storage.getGroups(platformUrl, clientId, contextId);
}

/**
 * Loads groups from the LTI Course Groups Service. This can be called in two ways. The first way
 * - with the groupsUrl and accessToken set to null and the rest of the params set - is usually
 * the way the first page of results is requested. An CGS implementation may well supply a url
 * and access token to get the next page, alongside the group objects. That url can be used with
 * the token in further calls to loadGroups and in that case only groupsUrl and accessToken will
 * be supplied.
 *
 * @param {string} groupsUrl The url of the platform's groups service
 * @param {string} accessToken An access tokem for retrieving the groups from the groupsUrl
 * @param {string} platformUrl Used to identify a registered platform
 * @param {string} clientId Used to identify a registered platform
 * @param {string} contextId Used to retrieve the context token
 * @param {string} user Used to retrieve the context token
 *
 * @return {object} A js object with the groups
 */
async function loadGroups(
  storage: LTIStorage,
  toolDomain: string,
  aesKey: CryptoKey,
  groupsUrl?: string | string[] | null,
  accessToken?: string | null,
  platformUrl?: string | null,
  clientId?: string | null,
  contextId?: string | null,
  user?: string | null,
): Promise<any | null> {

  const contextToken: ContextToken | null = await storage.getContextToken(`${contextId}${user}`);
  const productFamilyCode = contextToken?.toolPlatform?.product_family_code;

  if (!accessToken && !groupsUrl && platformUrl && clientId) {
    const platform: Platform | null = await storage.getPlatform(platformUrl, clientId);
    if (!platform) return null;

    groupsUrl = contextToken?.groups?.context_groups_url || null;
    if (!groupsUrl) {
      console.error("No context_groups_url supplied. Let's check product codes");
      if (productFamilyCode === "canvas") {
        console.debug("We're launching into Canvas. Return an empty groups list for now ...");
        return { groups: [] };
      } else {
      }
    }

    accessToken = await requestAccessToken(
      toolDomain,
      platform.accesstokenEndpoint,
      platformUrl,
      clientId,
      buildKeyId(platform),
      ["https://purl.imsglobal.org/spec/lti-gs/scope/contextgroup.readonly"],
      storage,
      aesKey,
    );
  }

  if (!accessToken) {
    console.debug("Still no accessToken. Not great :(");
  }

  console.debug(`Retrieving groups from ${groupsUrl}`);

  return fetch(groupsUrl as string, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.ims.lti-gs.v1.contextgroupcontainer+json",
      },
    })
    .then(async r => {
      if (r.ok) {
        const headers: HTTPHeaderLink = HTTPHeaderLink.parse(r.headers);
        const next: HTTPHeaderLinkEntry[] = headers.getByRel("next");

        const groupsData = await r.json();

        if (next.length) {
          groupsData.next = next.length ? next[0][0] : undefined;
          groupsData.accessToken = accessToken;
        }

        return groupsData;
      } else {
        console.error(`Network error while getting groups from ${groupsUrl}: ${r.status}`);
        console.error(await r.json());
        return {};
      }
    });
}

async function primeGroupsCache(
    storage: LTIStorage,
    toolDomain: string,
    aesKey: CryptoKey,
    platformUrl: string,
    clientId: string,
    contextId: string,
    userId: string,
): Promise<void> {

  if (await storage.isGroupsCaching(platformUrl, clientId, contextId)) {
    // Another request is already filling the cache; wait until at least the first page is in.
    return;
  }

  storage.setGroupsCaching(platformUrl, clientId, contextId);

  console.debug(`Getting first page of members for clientId ${clientId} and contextId ${contextId} ...`);
  const first = await loadGroups(storage, toolDomain, aesKey, null, null, platformUrl, clientId, contextId, userId);
  if (!first) return;
  await persistGroups(storage, platformUrl, clientId, contextId, first.groups);

  if (!first.next) {
    storage.unsetGroupsCaching(platformUrl, clientId, contextId);
    return;
  }

  let pageUrl: string | undefined = first.next;
  let accessToken: string | undefined = first.accessToken;
  let page = 2;
  while (pageUrl) {
    const result = await loadGroups(storage, toolDomain, aesKey, pageUrl, accessToken, null, null, null, null);
    if (!result) break;
    await persistGroups(storage, platformUrl, clientId, contextId, result.groups);
    console.debug(`Drained groups page ${page} for clientId ${clientId} and contextId ${contextId}`);
    pageUrl = result.next;
    accessToken = result.accessToken;
    page++;
  }
  storage.unsetGroupsCaching(platformUrl, clientId, contextId);
}

async function persistGroups(
  storage: LTIStorage,
  platformUrl: string,
  clientId: string,
  contextId: string,
  groups: Array<Group> = [],
): Promise<void> {

  for (const g of groups) await storage.setGroup(platformUrl, clientId, contextId, g as Group);
}

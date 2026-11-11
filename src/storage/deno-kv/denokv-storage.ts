import type { GroupTotals, LTIStorage } from "../lti-storage.ts";
import type { AccessToken, ContextToken, Group, IdToken, LineItem, LineItemOptions, Member, MemberPage, OidcStateData, Platform, Result } from "../../types.ts";

const LIST_CHUNK = 200;

/**
 * DenoKVStorage — zero-dependency storage using Deno's built-in KV store.
 *
 * Key schema:
 *   ["platform", url, clientId]                → Platform
 *   ["platform_by_url", url, clientId]         → true  (index for list-by-url)
 *   ["key_public", kid]                        → encrypted public key string
 *   ["key_private", kid]                       → encrypted private key string
 *   ["idtoken", key]                           → IdToken   (24h TTL)
 *   ["contexttoken", key]                      → ContextToken (24h TTL)
 *   ["nonce", nonce]                           → true  (10s TTL)
 *   ["state", state]                           → OidcStateData (10m TTL)
 *   ["accesstoken", platformUrl, clientId, scopes] → AccessToken (1h TTL)
 *
 * Requires: --unstable-kv flag (or "unstable": ["kv"] in deno.json)
 */
export class DenoKVStorage implements LTIStorage {
  #kv: Deno.Kv;
  #membersAndGroupsTTL: number = 15 * 60 * 1_000;

  private constructor(kv: Deno.Kv) {
    this.#kv = kv;
  }

  static async open(kv?: Deno.Kv, path?: string): Promise<DenoKVStorage> {

    if (kv) return new DenoKVStorage(kv);
    return new DenoKVStorage(await Deno.openKv(path));
  }

  #publicKeyKey(
    kid: string,
  ): Deno.KvKey {
    return ["lti", "key_public", kid];
  }

  #privateKeyKey(
    kid: string,
  ): Deno.KvKey {
    return ["lti", "key_private", kid];
  }

  #accessTokenKey(
    platformUrl: string,
    clientId: string,
    requestedScopes: string
  ): Deno.KvKey {
    return [ "lti", "accesstoken", platformUrl, clientId, requestedScopes ];
  }

  #membersPrefix(platformUrl: string, clientId: string, contextId: string): Deno.KvKey {
    return [ "lti", "members", platformUrl, clientId, contextId ];
  }

  #groupsPrefix(platformUrl: string, clientId: string, contextId: string): Deno.KvKey {
    return [ "lti", "groups", platformUrl, clientId, contextId ];
  }

  #roleTotalsKey(platformUrl: string, clientId: string, contextId: string): Deno.KvKey {
    return [ "lti", "role-totals", platformUrl, clientId, contextId ];
  }

  #groupTotalsKey(platformUrl: string, clientId: string, contextId: string): Deno.KvKey {
    return [ "lti", "group-totals", platformUrl, clientId, contextId ];
  }

  #membersCachingKey(platformUrl: string, clientId: string, contextId: string): Deno.KvKey {
    return [ "lti", "members-caching", platformUrl, clientId, contextId ];
  }

  #groupsCachingKey(platformUrl: string, clientId: string, contextId: string): Deno.KvKey {
    return [ "lti", "groups-caching", platformUrl, clientId, contextId ];
  }

  #lineItemsPrefix(platformUrl: string, clientId: string, contextId: string, options?: LineItemOptions): Array<string | number> {

    const prefix = [ "lti", "line-items", platformUrl, clientId, contextId ];
    options?.resourceId && prefix.push(options.resourceId);
    return prefix;
  }

  #resultsPrefix(platformUrl: string, clientId: string, lineItemId: string): Deno.KvKey {
    return [ "lti", "results", platformUrl, clientId, lineItemId ];
  }

  #platformKey(url: string, clientId: string): Deno.KvKey {
    return [ "lti", "platform", url, clientId];
  }

  // -------------------------------------------------------------------------
  // Platforms
  // -------------------------------------------------------------------------

  async savePlatform(platform: Platform): Promise<void> {
    await this.#kv.set(this.#platformKey(platform.url, platform.clientId), platform);
  }

  async getPlatform(url: string, clientId: string): Promise<Platform | null> {
    return (await this.#kv.get<Platform>(this.#platformKey(url, clientId))).value;
  }

  async setPlatformActive(url: string, clientId: string, active: boolean): Promise<void> {

    const platform = await this.getPlatform(url, clientId);
    if (!platform) throw new Error(`Platform not found: ${url} / ${clientId}`);
    await this.#kv.set(this.#platformKey(url, clientId), { ...platform, active });
  }

  // -------------------------------------------------------------------------
  // Keypairs
  // -------------------------------------------------------------------------

  async saveKeyPair(
    kid: string,
    encryptedPublicKey: string,
    encryptedPrivateKey: string,
  ): Promise<void> {

    await this.#kv.set(this.#publicKeyKey(kid), encryptedPublicKey);
    await this.#kv.set(this.#privateKeyKey(kid), encryptedPrivateKey);
  }

  async getPublicKey(kid: string): Promise<string | null> {
    return (await this.#kv.get<string>(this.#publicKeyKey(kid))).value;
  }

  async getPrivateKey(kid: string): Promise<string | null> {
    return (await this.#kv.get<string>(this.#privateKeyKey(kid))).value;
  }

  async getAllPublicKeys(): Promise<Array<{ kid: string; encryptedKey: string }>> {

    const results: Array<{ kid: string; encryptedKey: string }> = [];
    for await (const entry of this.#kv.list({ prefix: ["lti", "key_public"] })) {
      if (entry.value) {
        const kid: string = entry.key[2] as string;
        results.push({ kid, encryptedKey: entry.value as string });
      }
    }
    return results;
  }

  // -------------------------------------------------------------------------
  // ID tokens
  // -------------------------------------------------------------------------

  async saveIdToken(key: string, token: IdToken, ttlMs: number): Promise<void> {
    await this.#kv.set(["lti", "idtoken", key], token, { expireIn: ttlMs });
  }

  async getIdToken(key: string): Promise<IdToken | null> {
    return (await this.#kv.get<IdToken>(["lti", "idtoken", key])).value;
  }

  // -------------------------------------------------------------------------
  // Context tokens
  // -------------------------------------------------------------------------

  async saveContextToken(
    key: string,
    token: ContextToken,
    ttlMs: number,
  ): Promise<void> {
    await this.#kv.set(["lti", "contexttoken", key], token, { expireIn: ttlMs });
  }

  async getContextToken(key: string): Promise<ContextToken | null> {
    return (await this.#kv.get<ContextToken>(["lti", "contexttoken", key])).value;
  }

  // -------------------------------------------------------------------------
  // Nonces
  // -------------------------------------------------------------------------

  async saveNonce(nonce: string, ttlMs: number): Promise<void> {
    await this.#kv.set(["lti", "nonce", nonce], true, { expireIn: ttlMs });
  }

  async hasNonce(nonce: string): Promise<boolean> {
    return (await this.#kv.get(["lti", "nonce", nonce])).value !== null;
  }

  // -------------------------------------------------------------------------
  // OIDC state
  // -------------------------------------------------------------------------

  async saveState(state: string, data: OidcStateData, ttlMs: number): Promise<void> {
    await this.#kv.set(["lti", "state", state], data, { expireIn: ttlMs });
  }

  async getState(state: string): Promise<OidcStateData | null> {
    return (await this.#kv.get<OidcStateData>(["lti", "state", state])).value;
  }

  async deleteState(state: string): Promise<void> {
    await this.#kv.delete(["lti", "state", state]);
  }

  // -------------------------------------------------------------------------
  // Access token cache
  // -------------------------------------------------------------------------

  async saveAccessToken(record: AccessToken, ttlMs: number): Promise<void> {

    await this.#kv.set(
      this.#accessTokenKey(record.platformUrl, record.clientId, record.requestedScopes),
      record,
      { expireIn: ttlMs },
    );
  }

  async getAccessToken(
    platformUrl: string,
    clientId: string,
    requestedScopes: string,
  ): Promise<AccessToken | null> {

    const entry = await this.#kv.get<AccessToken>(this.#accessTokenKey(platformUrl, clientId, requestedScopes));
    if (!entry.value) return null;
    if (entry.value.expiresAt < Date.now()) return null;
    return entry.value;
  }

  async isMembersCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {
    return !!(await this.#kv.get(this.#membersCachingKey(platformUrl, clientId, contextId))).value;
  }

  async setMembersCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {
    return (await this.#kv.set(this.#membersCachingKey(platformUrl, clientId, contextId), true)).ok;
  }

  async unsetMembersCaching(platformUrl: string, clientId: string, contextId: string): Promise<void> {
    return await this.#kv.delete(this.#membersCachingKey(platformUrl, clientId, contextId));
  }

  async setMember(platformUrl: string, clientId: string, contextId: string, user: any): Promise<boolean> {

    let id = user.user_id;
    const index = id.lastIndexOf("/");
    if (index !== -1) id = id.substring(index + 1);

    delete user.lti11_legacy_user_id;
    delete user.lis_person_sourcedid;

    return (await this.#kv.set([ ...this.#membersPrefix(platformUrl, clientId, contextId), id ], user, { expireIn: this.#membersAndGroupsTTL })).ok;
  }

  async hasAnyMembers(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {

    // Try and get one user
    const iter = this.#kv.list({ prefix: this.#membersPrefix(platformUrl, clientId, contextId) }, { limit: 1 });
    for await (const _ of iter) return true;
    return false;
  }

  async getPageOfMembers(
    platformUrl: string,
    clientId: string,
    contextId: string,
    start: number,
    length: number,
    filter?: (m: Member) => boolean,
    filteredCount?: number,
  ): Promise<MemberPage> {

    const prefix = this.#membersPrefix(platformUrl, clientId, contextId);

    // When the caller already knows the filtered count (no filter, or a
    // role/group filter whose count we cached) we only need to read the
    // start..start+length window and can stop the scan as soon as it is
    // full. We still need the unfiltered total for DataTables, so that also
    // has to be known up front — otherwise fall back to a full scan.
    const cachedTotal = (await this.getCachedGroupTotals(platformUrl, clientId, contextId))?.total;
    const windowed = filteredCount !== undefined && cachedTotal !== undefined && length > 0;

    const members: Array<Member> = [];
    let recordsTotal = 0;
    let matched = 0;
    let cursor: string | undefined;

    while (true) {
      const iter = this.#kv.list<Member>({ prefix }, { cursor, limit: LIST_CHUNK });
      let seenInChunk = 0;
      let filled = false;
      for await (const entry of iter) {
        seenInChunk++;
        recordsTotal++;
        const member: Member = entry.value;
        if (filter && !filter(member)) continue;
        if (matched >= start && members.length < length) members.push(member);
        matched++;
        if (windowed && members.length === length) {
          filled = true;
          break;
        }
      }
      if (filled) break;
      cursor = iter.cursor || undefined;
      if (!cursor || seenInChunk === 0) break;
    }

    return {
      members,
      recordsTotal: windowed ? cachedTotal : recordsTotal,
      recordsFiltered: filteredCount !== undefined ? filteredCount : matched,
    };
  }

  async getAllMembers(platformUrl: string, clientId: string, contextId: string): Promise<Array<Member>> {

    const all: Array<Member> = [];
    let cursor: string | undefined;
    while (true) {
      const iter = this.#kv.list<Member>({ prefix: this.#membersPrefix(platformUrl, clientId, contextId) }, { cursor, limit: LIST_CHUNK });
      let seen = 0;
      for await (const entry of iter) {
        seen++;
        all.push(entry.value);
      }
      cursor = iter.cursor || undefined;
      if (!cursor || seen === 0) break;
    }
    return all;
  }

  async getCachedRoleTotals(platformUrl: string, clientId: string, contextId: string): Promise<Record<string, number> | null> {
    return (await this.#kv.get<Record<string, number>>(this.#roleTotalsKey(platformUrl, clientId, contextId))).value;
  }

  async getCachedGroupTotals(platformUrl: string, clientId: string, contextId: string): Promise<GroupTotals | null> {
    return (await this.#kv.get<GroupTotals>(this.#groupTotalsKey(platformUrl, clientId, contextId))).value;
  }

  async cacheTotals(platformUrl: string, clientId: string, contextId: string): Promise<Record<string, number>> {

    const totals = await this.getCachedRoleTotals(platformUrl, clientId, contextId);
    const groupTotalsCached = await this.getCachedGroupTotals(platformUrl, clientId, contextId);

    if (totals && groupTotalsCached) {
      console.debug(`Using cached totals for platformUrl ${platformUrl}, clientId ${clientId} and contextId ${contextId}.`);
      return totals;
    }

    console.debug(`Totals for platformUrl ${platformUrl}, clientId ${clientId} and contextId ${contextId} not cached. Building ...`);

    // A single pass over the members yields the per-role counts, the
    // per-group counts and the overall member total, so DataTables can page
    // without rescanning on every draw.
    const roleTotals: Record<string, number> = {};
    const groupTotals: GroupTotals = { total: 0, byGroup: {} };

    const all = await this.getAllMembers(platformUrl, clientId, contextId);
    for (const m of all) {
      groupTotals.total++;

      m.roles?.forEach(r => {
        roleTotals[r] = (roleTotals[r] ?? 0) + 1;
      });

      // Dedupe group ids so a member is counted once per group even if the
      // platform reports duplicate enrolments (matches the filter predicate).
      const groupIds = new Set<string>((m.group_enrollments ?? []).map(e => e.group_id));
      for (const groupId of groupIds) {
        groupTotals.byGroup[groupId] = (groupTotals.byGroup[groupId] ?? 0) + 1;
      }
    }

    await this.#kv.set(this.#roleTotalsKey(platformUrl, clientId, contextId), roleTotals, { expireIn: this.#membersAndGroupsTTL } );
    await this.#kv.set(this.#groupTotalsKey(platformUrl, clientId, contextId), groupTotals, { expireIn: this.#membersAndGroupsTTL });

    return roleTotals;
  }

  async hasAnyGroups(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {

    // Try and get one user
    const iter = this.#kv.list<Group>({ prefix: this.#groupsPrefix(platformUrl, clientId, contextId) }, { limit: 1 });
    for await (const _ of iter) return true;
    return false;
  }

  async isGroupsCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {
    return !!(await this.#kv.get(this.#groupsCachingKey(platformUrl, clientId, contextId))).value;
  }

  async setGroupsCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {
    return (await this.#kv.set(this.#groupsCachingKey(platformUrl, clientId, contextId), true)).ok;
  }

  async unsetGroupsCaching(platformUrl: string, clientId: string, contextId: string): Promise<void> {
    return await this.#kv.delete(this.#groupsCachingKey(platformUrl, clientId, contextId));
  }

  async setGroup(platformUrl: string, clientId: string, contextId: string, group: Group): Promise<boolean> {

    const expireIn: number = 15 * 60 * 1000;
    return (await this.#kv.set([ ...this.#groupsPrefix(platformUrl, clientId, contextId), group.id ], group, { expireIn })).ok;
  }

  async getGroups(platformUrl: string, clientId: string, contextId: string): Promise<Array<Group>> {

    const groups: Array<Group> = [];
    let cursor: string | undefined;

    const prefix = this.#groupsPrefix(platformUrl, clientId, contextId);
    while (true) {
      const iter = this.#kv.list<Group>({ prefix }, { cursor, limit: LIST_CHUNK });
      for await (const entry of iter) {
        entry.value && groups.push(entry.value);
      }
      cursor = iter.cursor || undefined;
      if (!cursor) break;
    }

    return groups;
  }

  async hasAnyLineItems(platformUrl: string, clientId: string, contextId: string, options?: LineItemOptions): Promise<boolean> {

    // Try and get one user
    const iter = this.#kv.list({ prefix: this.#lineItemsPrefix(platformUrl, clientId, contextId, options) }, { limit: 1 });
    for await (const _ of iter) return true;
    return false;
  }

  async setLineItem(platformUrl: string, clientId: string, contextId: string, item: LineItem): Promise<boolean> {

    let id = item.id;
    if (!id) return false;

    const index = id.lastIndexOf("/");
    if (index !== -1) id = id.substring(index + 1);

    const expireIn: number = 15 * 60 * 1000;
    const key = this.#lineItemsPrefix(platformUrl, clientId, contextId);
    item?.resourceId && key.push(item.resourceId);
    key.push(id);
    return (await this.#kv.set(key, item, { expireIn })).ok;
  }

  async getLineItems(platformUrl: string, clientId: string, contextId: string, options?: LineItemOptions): Promise<Array<LineItem>> {

    const items: Array<LineItem> = [];
    let cursor: string | undefined;
    const prefix = this.#lineItemsPrefix(platformUrl, clientId, contextId, options);

    while (true) {
      const iter = this.#kv.list<LineItem>({ prefix }, { cursor, limit: LIST_CHUNK });
      for await (const entry of iter) {
        items.push(entry.value);
      }
      cursor = iter.cursor || undefined;
      if (!cursor) break;
    }

    return items;
  }

  async getResults(
    platformUrl: string,
    clientId: string,
    lineItemId: string,
  ): Promise<Array<Result> | null> {

    const results: Array<Result> = [];
    let cursor: string | undefined;
    const prefix = this.#resultsPrefix(platformUrl, clientId, lineItemId);

    while (true) {
      const iter = this.#kv.list<Result>({ prefix }, { cursor, limit: LIST_CHUNK });
      for await (const entry of iter) {
        results.push(entry.value);
      }
      cursor = iter.cursor || undefined;
      if (!cursor) break;
    }

    return results;
  }

  async setResult(
    platformUrl: string,
    clientId: string,
    lineItemId: string,
    result: Result,
  ): Promise<boolean> {

    let id = result.id;
    const index = id.lastIndexOf("/");
    if (index !== -1) id = id.substring(index + 1);

    return (await this.#kv.set([ ...this.#resultsPrefix(platformUrl, clientId, lineItemId), id ], result, { expireIn: this.#membersAndGroupsTTL })).ok;
  }

  async saveInvitation(code: string): Promise<boolean> {
    return (await this.#kv.set([ "lti", "invitations", code ], code)).ok;
  }

  async getInvitation(code: string): Promise<string | null> {
    return (await this.#kv.get<string>([ "lti", "invitations", code ])).value;
  }

  async clearInvitation(code: string): Promise<void> {
    await this.#kv.delete([ "lti", "invitations", code ]);
  }

  close(): void {
    this.#kv.close();
  }
}

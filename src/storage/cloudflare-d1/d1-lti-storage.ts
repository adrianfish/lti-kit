import type { D1Database } from "@cloudflare/workers-types";

import type { GroupTotals, LTIStorage } from "../lti-storage.ts";
import type { AccessToken, ContextToken, Group, IdToken, LineItem, LineItemOptions, Member, MemberPage, OidcStateData, Platform, Result } from "../../types.ts";

/**
 * D1's real bind signature takes `unknown[]`, which would let an `undefined`
 * through — and D1 rejects undefined at runtime. Narrowed to what this class
 * actually binds, so a possibly-undefined field has to be coalesced to null.
 */
type D1Value = string | number | null;

interface PlatformRow {
  url: string;
  client_id: string;
  name: string;
  auth_endpoint: string;
  accesstoken_endpoint: string;
  method: string;
  key: string | null;
  jwks_uri: string;
  kid: string | null;
  active: number;
}

interface TotalsRow {
  role_totals: string | null;
  group_totals: string | null;
}

/**
 * D1LTIStorage — LTIStorage backed by a Cloudflare D1 database.
 *
 * Schema: src/storage/cloudflare-d1/schema/0001_lti_init.sql. Point the
 * consuming Worker's `migrations_dir` at that directory, or copy the migration
 * into the app's own migrations.
 *
 * D1 has no TTL. Everything the KV implementation gave an `expireIn` is stored
 * with an `expires_at` (Unix epoch ms) instead, and every read adds
 * `expires_at > ?`. Expired rows are ignored rather than deleted, because
 * LTIStorage exposes no purge method — add a scheduled sweep if growth matters.
 */
export class D1LTIStorage implements LTIStorage {

  #db: D1Database;
  #membersAndGroupsTTL: number = 15 * 60 * 1_000;

  constructor(db: D1Database) {
    this.#db = db;
  }

  #expiresAt(ttlMs: number): number {
    return Date.now() + ttlMs;
  }

  /** True when the probe query returns a row. */
  async #exists(sql: string, ...params: D1Value[]): Promise<boolean> {
    return (await this.#db.prepare(sql).bind(...params).first()) !== null;
  }

  // -------------------------------------------------------------------------
  // Platforms
  // -------------------------------------------------------------------------

  async savePlatform(platform: Platform): Promise<void> {

    await this.#db.prepare(`
      INSERT INTO lti_platforms
        (url, client_id, name, auth_endpoint, accesstoken_endpoint, method, key, jwks_uri, kid, active)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (url, client_id) DO UPDATE SET
        name = excluded.name,
        auth_endpoint = excluded.auth_endpoint,
        accesstoken_endpoint = excluded.accesstoken_endpoint,
        method = excluded.method,
        key = excluded.key,
        jwks_uri = excluded.jwks_uri,
        kid = excluded.kid,
        active = excluded.active
    `)
      .bind(
        platform.url,
        platform.clientId,
        platform.name,
        platform.authEndpoint,
        platform.accesstokenEndpoint,
        platform.method,
        // key and kid are declared required on Platform but nothing ever sets
        // them, and D1 rejects an undefined bind.
        platform.key ?? null,
        platform.jwksUri,
        platform.kid ?? null,
        platform.active ? 1 : 0,
      )
      .run();
  }

  async getPlatform(url: string, clientId: string): Promise<Platform | null> {

    const row = await this.#db.prepare(
      `SELECT * FROM lti_platforms WHERE url = ? AND client_id = ?`,
    )
      .bind(url, clientId)
      .first<PlatformRow>();

    if (!row) return null;

    return {
      url: row.url,
      clientId: row.client_id,
      name: row.name,
      authEndpoint: row.auth_endpoint,
      accesstokenEndpoint: row.accesstoken_endpoint,
      method: row.method,
      key: row.key as string,
      jwksUri: row.jwks_uri,
      kid: row.kid as string,
      active: !!row.active,
    };
  }

  async setPlatformActive(url: string, clientId: string, active: boolean): Promise<void> {

    const { meta } = await this.#db.prepare(
      `UPDATE lti_platforms SET active = ? WHERE url = ? AND client_id = ?`,
    )
      .bind(active ? 1 : 0, url, clientId)
      .run();

    if (!meta.changes) throw new Error(`Platform not found: ${url} / ${clientId}`);
  }

  // -------------------------------------------------------------------------
  // Keypairs
  // -------------------------------------------------------------------------

  async saveKeyPair(
    kid: string,
    encryptedPublicKey: string,
    encryptedPrivateKey: string,
  ): Promise<void> {

    await this.#db.prepare(`
      INSERT INTO lti_keypairs (kid, public_key, private_key)
      VALUES (?, ?, ?)
      ON CONFLICT (kid) DO UPDATE SET
        public_key = excluded.public_key,
        private_key = excluded.private_key
    `)
      .bind(kid, encryptedPublicKey, encryptedPrivateKey)
      .run();
  }

  async getPublicKey(kid: string): Promise<string | null> {

    return this.#db.prepare(`SELECT public_key FROM lti_keypairs WHERE kid = ?`)
      .bind(kid)
      .first<string>("public_key");
  }

  async getPrivateKey(kid: string): Promise<string | null> {

    return this.#db.prepare(`SELECT private_key FROM lti_keypairs WHERE kid = ?`)
      .bind(kid)
      .first<string>("private_key");
  }

  async getAllPublicKeys(): Promise<Array<{ kid: string; encryptedKey: string }>> {

    const { results } = await this.#db.prepare(
      `SELECT kid, public_key FROM lti_keypairs ORDER BY kid`,
    )
      .all<{ kid: string; public_key: string }>();

    return results.map(({ kid, public_key }) => ({ kid, encryptedKey: public_key }));
  }

  // -------------------------------------------------------------------------
  // ID tokens
  // -------------------------------------------------------------------------

  async saveIdToken(key: string, token: IdToken, ttlMs: number): Promise<void> {

    await this.#db.prepare(`
      INSERT INTO lti_id_tokens (token_key, data, expires_at)
      VALUES (?, ?, ?)
      ON CONFLICT (token_key) DO UPDATE SET
        data = excluded.data,
        expires_at = excluded.expires_at
    `)
      .bind(key, JSON.stringify(token), this.#expiresAt(ttlMs))
      .run();
  }

  async getIdToken(key: string): Promise<IdToken | null> {

    const data = await this.#db.prepare(
      `SELECT data FROM lti_id_tokens WHERE token_key = ? AND expires_at > ?`,
    )
      .bind(key, Date.now())
      .first<string>("data");

    return data ? JSON.parse(data) as IdToken : null;
  }

  // -------------------------------------------------------------------------
  // Context tokens
  // -------------------------------------------------------------------------

  async saveContextToken(
    key: string,
    token: ContextToken,
    ttlMs: number,
  ): Promise<void> {

    await this.#db.prepare(`
      INSERT INTO lti_context_tokens (token_key, data, expires_at)
      VALUES (?, ?, ?)
      ON CONFLICT (token_key) DO UPDATE SET
        data = excluded.data,
        expires_at = excluded.expires_at
    `)
      .bind(key, JSON.stringify(token), this.#expiresAt(ttlMs))
      .run();
  }

  async getContextToken(key: string): Promise<ContextToken | null> {

    const data = await this.#db.prepare(
      `SELECT data FROM lti_context_tokens WHERE token_key = ? AND expires_at > ?`,
    )
      .bind(key, Date.now())
      .first<string>("data");

    return data ? JSON.parse(data) as ContextToken : null;
  }

  // -------------------------------------------------------------------------
  // Nonces
  // -------------------------------------------------------------------------

  async saveNonce(nonce: string, ttlMs: number): Promise<void> {

    await this.#db.prepare(`
      INSERT INTO lti_nonces (nonce, expires_at)
      VALUES (?, ?)
      ON CONFLICT (nonce) DO UPDATE SET expires_at = excluded.expires_at
    `)
      .bind(nonce, this.#expiresAt(ttlMs))
      .run();
  }

  async hasNonce(nonce: string): Promise<boolean> {

    return this.#exists(
      `SELECT 1 FROM lti_nonces WHERE nonce = ? AND expires_at > ?`,
      nonce,
      Date.now(),
    );
  }

  // -------------------------------------------------------------------------
  // OIDC state
  // -------------------------------------------------------------------------

  async saveState(state: string, data: OidcStateData, ttlMs: number): Promise<void> {

    await this.#db.prepare(`
      INSERT INTO lti_oidc_states (state, data, expires_at)
      VALUES (?, ?, ?)
      ON CONFLICT (state) DO UPDATE SET
        data = excluded.data,
        expires_at = excluded.expires_at
    `)
      .bind(state, JSON.stringify(data), this.#expiresAt(ttlMs))
      .run();
  }

  async getState(state: string): Promise<OidcStateData | null> {

    const data = await this.#db.prepare(
      `SELECT data FROM lti_oidc_states WHERE state = ? AND expires_at > ?`,
    )
      .bind(state, Date.now())
      .first<string>("data");

    return data ? JSON.parse(data) as OidcStateData : null;
  }

  async deleteState(state: string): Promise<void> {

    await this.#db.prepare(`DELETE FROM lti_oidc_states WHERE state = ?`)
      .bind(state)
      .run();
  }

  // -------------------------------------------------------------------------
  // Access token cache
  // -------------------------------------------------------------------------

  async saveAccessToken(record: AccessToken, ttlMs: number): Promise<void> {

    // The KV implementation enforced two deadlines at once — its own expireIn
    // and the record's expiresAt, which carries oauth.ts's 30s safety margin.
    // Both collapse into one column here, so take the earlier of the two.
    const expiresAt = Math.min(Date.now() + ttlMs, record.expiresAt);

    await this.#db.prepare(`
      INSERT INTO lti_access_tokens (platform_url, client_id, requested_scopes, token, expires_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (platform_url, client_id, requested_scopes) DO UPDATE SET
        token = excluded.token,
        expires_at = excluded.expires_at
    `)
      .bind(record.platformUrl, record.clientId, record.requestedScopes, record.token, expiresAt)
      .run();
  }

  async getAccessToken(
    platformUrl: string,
    clientId: string,
    requestedScopes: string,
  ): Promise<AccessToken | null> {

    const row = await this.#db.prepare(`
      SELECT token, expires_at FROM lti_access_tokens
      WHERE platform_url = ? AND client_id = ? AND requested_scopes = ? AND expires_at > ?
    `)
      .bind(platformUrl, clientId, requestedScopes, Date.now())
      .first<{ token: string; expires_at: number }>();

    if (!row) return null;
    return {
      token: row.token,
      platformUrl,
      clientId,
      requestedScopes,
      expiresAt: row.expires_at,
    };
  }

  // -------------------------------------------------------------------------
  // Roster and groups caching flags
  // -------------------------------------------------------------------------

  async #isCaching(kind: string, platformUrl: string, clientId: string, contextId: string): Promise<boolean> {

    return this.#exists(
      `SELECT 1 FROM lti_cache_flags WHERE kind = ? AND platform_url = ? AND client_id = ? AND context_id = ?`,
      kind,
      platformUrl,
      clientId,
      contextId,
    );
  }

  /**
   * Returns false when the flag was already set. The KV implementation always
   * returned true, because Kv.set is unconditional and its callers check
   * is*Caching first; no caller reads this value.
   */
  async #setCaching(kind: string, platformUrl: string, clientId: string, contextId: string): Promise<boolean> {

    const { meta } = await this.#db.prepare(`
      INSERT INTO lti_cache_flags (kind, platform_url, client_id, context_id)
      VALUES (?, ?, ?, ?)
      ON CONFLICT DO NOTHING
    `)
      .bind(kind, platformUrl, clientId, contextId)
      .run();

    return meta.changes > 0;
  }

  async #unsetCaching(kind: string, platformUrl: string, clientId: string, contextId: string): Promise<void> {

    await this.#db.prepare(
      `DELETE FROM lti_cache_flags WHERE kind = ? AND platform_url = ? AND client_id = ? AND context_id = ?`,
    )
      .bind(kind, platformUrl, clientId, contextId)
      .run();
  }

  async isMembersCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {
    return this.#isCaching("members", platformUrl, clientId, contextId);
  }

  async setMembersCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {
    return this.#setCaching("members", platformUrl, clientId, contextId);
  }

  async unsetMembersCaching(platformUrl: string, clientId: string, contextId: string): Promise<void> {
    return this.#unsetCaching("members", platformUrl, clientId, contextId);
  }

  async isGroupsCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {
    return this.#isCaching("groups", platformUrl, clientId, contextId);
  }

  async setGroupsCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {
    return this.#setCaching("groups", platformUrl, clientId, contextId);
  }

  async unsetGroupsCaching(platformUrl: string, clientId: string, contextId: string): Promise<void> {
    return this.#unsetCaching("groups", platformUrl, clientId, contextId);
  }

  // -------------------------------------------------------------------------
  // Members
  // -------------------------------------------------------------------------

  async setMember(platformUrl: string, clientId: string, contextId: string, user: any): Promise<boolean> {

    let id = user.user_id;
    const index = id.lastIndexOf("/");
    if (index !== -1) id = id.substring(index + 1);

    delete user.lti11_legacy_user_id;
    delete user.lis_person_sourcedid;

    await this.#db.prepare(`
      INSERT INTO lti_members (platform_url, client_id, context_id, member_id, data, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT (platform_url, client_id, context_id, member_id) DO UPDATE SET
        data = excluded.data,
        expires_at = excluded.expires_at
    `)
      .bind(platformUrl, clientId, contextId, id, JSON.stringify(user), this.#expiresAt(this.#membersAndGroupsTTL))
      .run();

    return true;
  }

  async hasAnyMembers(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {

    return this.#exists(
      `SELECT 1 FROM lti_members
       WHERE platform_url = ? AND client_id = ? AND context_id = ? AND expires_at > ?
       LIMIT 1`,
      platformUrl,
      clientId,
      contextId,
      Date.now(),
    );
  }

  /** Members in member_id order, matching the ordering of the KV prefix scan. */
  async #selectMembers(
    platformUrl: string,
    clientId: string,
    contextId: string,
    now: number,
    start?: number,
    length?: number,
  ): Promise<Array<Member>> {

    const windowed = start !== undefined && length !== undefined;
    const sql = `SELECT data FROM lti_members
       WHERE platform_url = ? AND client_id = ? AND context_id = ? AND expires_at > ?
       ORDER BY member_id${windowed ? " LIMIT ? OFFSET ?" : ""}`;

    const params: D1Value[] = [platformUrl, clientId, contextId, now];
    if (windowed) params.push(length as number, start as number);

    const { results } = await this.#db.prepare(sql).bind(...params).all<{ data: string }>();
    return results.map(({ data }) => JSON.parse(data) as Member);
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

    const now = Date.now();
    const row = await this.#db.prepare(`
      SELECT COUNT(*) AS total FROM lti_members
        WHERE platform_url = ? AND client_id = ? AND context_id = ? AND expires_at > ?
    `)
      .bind(platformUrl, clientId, contextId, now)
      .first<{ total: number }>();

    const recordsTotal = row?.total ?? 0;

    // Without a filter, start/length address the same rows SQL addresses, so
    // the page is a straight LIMIT/OFFSET and the roster is never read in full.
    // A filter skips non-matching rows, so start counts only matches and the
    // window has to be taken in JS.
    if (!filter && length > 0) {
      const members = await this.#selectMembers(platformUrl, clientId, contextId, now, start, length);
      return { members, recordsTotal, recordsFiltered: filteredCount ?? recordsTotal };
    }

    const all = await this.#selectMembers(platformUrl, clientId, contextId, now);
    const matched = filter ? all.filter(filter) : all;

    return {
      members: length > 0 ? matched.slice(start, start + length) : [],
      recordsTotal,
      recordsFiltered: filteredCount ?? matched.length,
    };
  }

  async getAllMembers(platformUrl: string, clientId: string, contextId: string): Promise<Array<Member>> {

    return this.#selectMembers(platformUrl, clientId, contextId, Date.now());
  }

  // -------------------------------------------------------------------------
  // Cached role and group totals
  // -------------------------------------------------------------------------

  #totalsRow(platformUrl: string, clientId: string, contextId: string): Promise<TotalsRow | null> {

    return this.#db.prepare(`
      SELECT role_totals, group_totals FROM lti_context_totals
        WHERE platform_url = ? AND client_id = ? AND context_id = ? AND expires_at > ?
    `)
      .bind(platformUrl, clientId, contextId, Date.now())
      .first<TotalsRow>();
  }

  async getCachedRoleTotals(platformUrl: string, clientId: string, contextId: string): Promise<Record<string, number> | null> {

    const roleTotals = (await this.#totalsRow(platformUrl, clientId, contextId))?.role_totals;
    return roleTotals ? JSON.parse(roleTotals) as Record<string, number> : null;
  }

  async getCachedGroupTotals(platformUrl: string, clientId: string, contextId: string): Promise<GroupTotals | null> {

    const groupTotals = (await this.#totalsRow(platformUrl, clientId, contextId))?.group_totals;
    return groupTotals ? JSON.parse(groupTotals) as GroupTotals : null;
  }

  async cacheTotals(platformUrl: string, clientId: string, contextId: string): Promise<Record<string, number>> {

    const cached = await this.#totalsRow(platformUrl, clientId, contextId);
    if (cached?.role_totals && cached?.group_totals) {
      console.debug(`Using cached totals for platformUrl ${platformUrl}, clientId ${clientId} and contextId ${contextId}.`);
      return JSON.parse(cached.role_totals) as Record<string, number>;
    }

    console.debug(`Totals for platformUrl ${platformUrl}, clientId ${clientId} and contextId ${contextId} not cached. Building ...`);

    // A single pass over the members yields the per-role counts, the per-group
    // counts and the overall member total, so DataTables can page without
    // rescanning on every draw.
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

    await this.#db.prepare(`
      INSERT INTO lti_context_totals (platform_url, client_id, context_id, role_totals, group_totals, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT (platform_url, client_id, context_id) DO UPDATE SET
        role_totals = excluded.role_totals,
        group_totals = excluded.group_totals,
        expires_at = excluded.expires_at
    `)
      .bind(platformUrl, clientId, contextId, JSON.stringify(roleTotals), JSON.stringify(groupTotals), this.#expiresAt(this.#membersAndGroupsTTL))
      .run();

    return roleTotals;
  }

  // -------------------------------------------------------------------------
  // Groups
  // -------------------------------------------------------------------------

  async hasAnyGroups(platformUrl: string, clientId: string, contextId: string): Promise<boolean> {

    return this.#exists(`
      SELECT 1 FROM lti_groups
        WHERE platform_url = ? AND client_id = ? AND context_id = ? AND expires_at > ?
       LIMIT 1
      `,
      platformUrl,
      clientId,
      contextId,
      Date.now(),
    );
  }

  async setGroup(platformUrl: string, clientId: string, contextId: string, group: Group): Promise<boolean> {

    await this.#db.prepare(`
      INSERT INTO lti_groups (platform_url, client_id, context_id, group_id, data, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT (platform_url, client_id, context_id, group_id) DO UPDATE SET
        data = excluded.data,
        expires_at = excluded.expires_at
    `)
      .bind(platformUrl, clientId, contextId, group.id, JSON.stringify(group), this.#expiresAt(this.#membersAndGroupsTTL))
      .run();

    return true;
  }

  async getGroups(platformUrl: string, clientId: string, contextId: string): Promise<Array<Group>> {

    const { results } = await this.#db.prepare(`
      SELECT data FROM lti_groups
      WHERE platform_url = ? AND client_id = ? AND context_id = ? AND expires_at > ?
      ORDER BY group_id
    `)
      .bind(platformUrl, clientId, contextId, Date.now())
      .all<{ data: string }>();

    return results.map(({ data }) => JSON.parse(data) as Group);
  }

  // -------------------------------------------------------------------------
  // Line items
  // -------------------------------------------------------------------------

  /**
   * The WHERE clause and binds shared by the line item reads. The KV
   * implementation could only narrow by resourceId, because that was part of
   * its key prefix; tag is a column here, so options.tag is honoured too.
   */
  #lineItemWhere(
    platformUrl: string,
    clientId: string,
    contextId: string,
    options?: LineItemOptions,
  ): { clause: string; params: D1Value[] } {

    const clause = ["platform_url = ?", "client_id = ?", "context_id = ?", "expires_at > ?"];
    const params: D1Value[] = [platformUrl, clientId, contextId, Date.now()];

    if (options?.resourceId !== undefined) {
      clause.push("resource_id = ?");
      params.push(options.resourceId);
    }
    if (options?.tag !== undefined) {
      clause.push("tag = ?");
      params.push(options.tag);
    }

    return { clause: clause.join(" AND "), params };
  }

  async hasAnyLineItems(platformUrl: string, clientId: string, contextId: string, options?: LineItemOptions): Promise<boolean> {

    const { clause, params } = this.#lineItemWhere(platformUrl, clientId, contextId, options);
    return this.#exists(`SELECT 1 FROM lti_line_items WHERE ${clause} LIMIT 1`, ...params);
  }

  async setLineItem(platformUrl: string, clientId: string, contextId: string, item: LineItem): Promise<boolean> {

    if (!item.id) return false;

    const index = item.id.lastIndexOf("/");
    const id = index === -1 ? item.id : item.id.substring(index + 1);

    await this.#db.prepare(`
      INSERT INTO lti_line_items
        (platform_url, client_id, context_id, line_item_id, resource_id, tag, data, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (platform_url, client_id, context_id, line_item_id) DO UPDATE SET
        resource_id = excluded.resource_id,
        tag = excluded.tag,
        data = excluded.data,
        expires_at = excluded.expires_at
    `)
      .bind(
        platformUrl,
        clientId,
        contextId,
        id,
        item.resourceId ?? null,
        item.tag ?? null,
        JSON.stringify(item),
        this.#expiresAt(this.#membersAndGroupsTTL),
      )
      .run();

    return true;
  }

  async getLineItems(platformUrl: string, clientId: string, contextId: string, options?: LineItemOptions): Promise<Array<LineItem>> {

    const { clause, params } = this.#lineItemWhere(platformUrl, clientId, contextId, options);
    const { results } = await this.#db.prepare(
      `SELECT data FROM lti_line_items WHERE ${clause} ORDER BY line_item_id`
    )
      .bind(...params)
      .all<{ data: string }>();

    return results.map(({ data }) => JSON.parse(data) as LineItem);
  }

  // -------------------------------------------------------------------------
  // Results
  // -------------------------------------------------------------------------

  async getResults(
    platformUrl: string,
    clientId: string,
    lineItemId: string,
  ): Promise<Array<Result> | null> {

    const { results } = await this.#db.prepare(`
      SELECT data FROM lti_results
      WHERE platform_url = ? AND client_id = ? AND line_item_id = ? AND expires_at > ?
      ORDER BY result_id
    `)
      .bind(platformUrl, clientId, lineItemId, Date.now())
      .all<{ data: string }>();

    return results.map(({ data }) => JSON.parse(data) as Result);
  }

  async setResult(
    platformUrl: string,
    clientId: string,
    lineItemId: string,
    result: Result,
  ): Promise<boolean> {

    const index = result.id.lastIndexOf("/");
    const id = index === -1 ? result.id : result.id.substring(index + 1);

    await this.#db.prepare(`
      INSERT INTO lti_results (platform_url, client_id, line_item_id, result_id, data, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT (platform_url, client_id, line_item_id, result_id) DO UPDATE SET
        data = excluded.data,
        expires_at = excluded.expires_at
    `)
      .bind(platformUrl, clientId, lineItemId, id, JSON.stringify(result), this.#expiresAt(this.#membersAndGroupsTTL))
      .run();

    return true;
  }

  // -------------------------------------------------------------------------
  // Invitations
  // -------------------------------------------------------------------------

  async saveInvitation(code: string): Promise<boolean> {

    // DO NOTHING rather than an upsert, so meta.changes reports whether the code
    // was new — handleInvitations answers 500 when it was not.
    const { meta } = await this.#db.prepare(
      `INSERT INTO lti_invitations (code) VALUES (?) ON CONFLICT (code) DO NOTHING`,
    )
      .bind(code)
      .run();

    return meta.changes > 0;
  }

  async getInvitation(code: string): Promise<string | null> {

    return this.#db.prepare(`SELECT code FROM lti_invitations WHERE code = ?`)
      .bind(code)
      .first<string>("code");
  }

  async clearInvitation(code: string): Promise<void> {

    await this.#db.prepare(`DELETE FROM lti_invitations WHERE code = ?`).bind(code).run();
  }
}

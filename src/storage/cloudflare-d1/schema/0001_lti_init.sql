-- LTI 1.3 Advantage schema for Cloudflare D1.
--
-- Covers the LTIStorage interface in src/storage/lti-storage.ts, following the
-- key schema documented in src/storage/deno-kv/denokv-storage.ts.
--
-- Conventions:
--   * D1 has no TTL. Every table backing a `ttlMs` method carries an
--     `expires_at` column holding a Unix epoch in MILLISECONDS — the unit
--     AccessToken.expiresAt already uses. Reads must add `expires_at > ?` bound
--     to Date.now(); expired rows are otherwise ignored rather than removed,
--     since LTIStorage exposes no purge method.
--   * Variable-shaped payloads (tokens, members, groups, line items, results,
--     totals) are stored as JSON text. Fixed shapes that are queried or partly
--     updated (platforms, access tokens) get real columns, so
--     setPlatformActive is a single UPDATE rather than a read-modify-write.
--   * Composite PRIMARY KEYs follow the (platform_url, client_id, context_id,
--     …) nesting of the KV key prefixes, so their leading columns serve the
--     same purpose as a KV prefix scan.

-- savePlatform / getPlatform / setPlatformActive.
-- `key` and `kid` are nullable because nothing populates them: registration
-- builds a Platform without either, and the kid is derived on demand by
-- buildKeyId(platform). NOT NULL here would fail every registration insert.
CREATE TABLE lti_platforms (
  url                  TEXT    NOT NULL,
  client_id            TEXT    NOT NULL,
  name                 TEXT    NOT NULL,
  auth_endpoint        TEXT    NOT NULL,
  accesstoken_endpoint TEXT    NOT NULL,
  method               TEXT    NOT NULL,
  key                  TEXT,
  jwks_uri             TEXT    NOT NULL,
  kid                  TEXT,
  active               INTEGER NOT NULL,
  PRIMARY KEY (url, client_id)
);

-- saveKeyPair / getPublicKey / getPrivateKey / getAllPublicKeys.
-- One row per kid instead of the KV's two prefixes, so the halves cannot drift
-- apart and getAllPublicKeys is a plain SELECT.
CREATE TABLE lti_keypairs (
  kid         TEXT PRIMARY KEY,
  public_key  TEXT NOT NULL,
  private_key TEXT NOT NULL
);

-- saveIdToken / getIdToken. `data` is a serialised IdToken.
CREATE TABLE lti_id_tokens (
  token_key  TEXT    PRIMARY KEY,
  data       TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);

-- saveContextToken / getContextToken. `data` is a serialised ContextToken.
CREATE TABLE lti_context_tokens (
  token_key  TEXT    PRIMARY KEY,
  data       TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);

-- saveNonce / hasNonce.
CREATE TABLE lti_nonces (
  nonce      TEXT    PRIMARY KEY,
  expires_at INTEGER NOT NULL
);

-- saveState / getState / deleteState. `data` is a serialised OidcStateData.
CREATE TABLE lti_oidc_states (
  state      TEXT    PRIMARY KEY,
  data       TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);

-- saveAccessToken / getAccessToken. The AccessToken record's own expiresAt and
-- the ttlMs argument express the same deadline, so both land in expires_at;
-- token is kept as a column because it is the only field callers read back.
CREATE TABLE lti_access_tokens (
  platform_url     TEXT    NOT NULL,
  client_id        TEXT    NOT NULL,
  requested_scopes TEXT    NOT NULL,
  token            TEXT    NOT NULL,
  expires_at       INTEGER NOT NULL,
  PRIMARY KEY (platform_url, client_id, requested_scopes)
);

-- isMembersCaching / setMembersCaching / unsetMembersCaching and the groups
-- equivalents, told apart by `kind` ('members' | 'groups').
-- Deliberately no expires_at: the KV impl sets these flags without a TTL and
-- clears them from a finally block. A worker killed mid-drain leaves the flag
-- set and that context's cache never primes again — same behaviour as KV.
CREATE TABLE lti_cache_flags (
  kind         TEXT NOT NULL,
  platform_url TEXT NOT NULL,
  client_id    TEXT NOT NULL,
  context_id   TEXT NOT NULL,
  PRIMARY KEY (kind, platform_url, client_id, context_id)
);

-- setMember / hasAnyMembers / getPageOfMembers / getAllMembers.
-- member_id is the user_id with any leading path stripped. The PRIMARY KEY
-- ordering gives getPageOfMembers the stable ordering the KV prefix scan had,
-- so LIMIT/OFFSET pages over it. `data` is the whole Member: role and group
-- filtering stays in JS because those are arrays inside the JSON.
CREATE TABLE lti_members (
  platform_url TEXT    NOT NULL,
  client_id    TEXT    NOT NULL,
  context_id   TEXT    NOT NULL,
  member_id    TEXT    NOT NULL,
  data         TEXT    NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (platform_url, client_id, context_id, member_id)
);

-- hasAnyGroups / setGroup / getGroups. `data` is a serialised Group.
-- Named course_groups because GROUPS is a SQLite keyword (window frame bounds).
CREATE TABLE lti_groups (
  platform_url TEXT    NOT NULL,
  client_id    TEXT    NOT NULL,
  context_id   TEXT    NOT NULL,
  group_id     TEXT    NOT NULL,
  data         TEXT    NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (platform_url, client_id, context_id, group_id)
);

-- getCachedRoleTotals / getCachedGroupTotals / cacheTotals.
-- cacheTotals computes both in one pass over the roster and stores them with
-- the same TTL, so they share a row. Each column is nullable so either getter
-- can still report "not cached" independently. role_totals is a
-- Record<string, number>, group_totals a GroupTotals.
CREATE TABLE lti_context_totals (
  platform_url TEXT    NOT NULL,
  client_id    TEXT    NOT NULL,
  context_id   TEXT    NOT NULL,
  role_totals  TEXT,
  group_totals TEXT,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (platform_url, client_id, context_id)
);

-- hasAnyLineItems / setLineItem / getLineItems. line_item_id is the LineItem id
-- with any leading path stripped; setLineItem rejects an item without one.
-- resource_id and tag are lifted out of the JSON because LineItemOptions
-- filters on them.
CREATE TABLE lti_line_items (
  platform_url TEXT    NOT NULL,
  client_id    TEXT    NOT NULL,
  context_id   TEXT    NOT NULL,
  line_item_id TEXT    NOT NULL,
  resource_id  TEXT,
  tag          TEXT,
  data         TEXT    NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (platform_url, client_id, context_id, line_item_id)
);

-- getLineItems(options.resourceId) cannot use the PRIMARY KEY, which orders by
-- line_item_id. This mirrors the KV prefix […, contextId, resourceId].
CREATE INDEX idx_line_items_context_resource
  ON lti_line_items (platform_url, client_id, context_id, resource_id);

-- getResults / setResult. line_item_id is stored exactly as the caller passes
-- it — setResult only strips the path from result.id, not from the line item.
CREATE TABLE lti_results (
  platform_url TEXT    NOT NULL,
  client_id    TEXT    NOT NULL,
  line_item_id TEXT    NOT NULL,
  result_id    TEXT    NOT NULL,
  data         TEXT    NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (platform_url, client_id, line_item_id, result_id)
);

-- saveInvitation / getInvitation / clearInvitation. The code is the whole
-- record. saveInvitation's boolean is an INSERT … ON CONFLICT DO NOTHING whose
-- meta.changes reports whether the code was new.
CREATE TABLE lti_invitations (
  code TEXT PRIMARY KEY
);

import type {AccessToken,  ContextToken, Group, IdToken, LineItem, LineItemOptions, Member, MemberPage, OidcStateData, Platform, Result } from "../types.ts";

/** Cached per-group membership counts, plus the overall member total. */
export interface GroupTotals {
  /** Total number of member records in the context. */
  total: number;
  /** Member count keyed by group id. */
  byGroup: Record<string, number>;
}

export interface Storage {

  savePlatform(platform: Platform): Promise<void>;

  getPlatform(url: string, clientId: string): Promise<Platform | null>;

  setPlatformActive(url: string, clientId: string, active: boolean): Promise<void>;

  saveKeyPair(
    kid: string,
    encryptedPublicKey: string,
    encryptedPrivateKey: string,
  ): Promise<void>;

  getPublicKey(kid: string): Promise<string | null>;

  getPrivateKey(kid: string): Promise<string | null>;

  getAllPublicKeys(): Promise<Array<{ kid: string; encryptedKey: string }>>;

  saveIdToken(key: string, token: IdToken, ttlMs: number): Promise<void>;

  getIdToken(key: string): Promise<IdToken | null>;

  saveContextToken(
    key: string,
    token: ContextToken,
    ttlMs: number,
  ): Promise<void>;

  getContextToken(key: string): Promise<ContextToken | null>;

  // -------------------------------------------------------------------------
  // Nonces
  // -------------------------------------------------------------------------

  saveNonce(nonce: string, ttlMs: number): Promise<void>;

  hasNonce(nonce: string): Promise<boolean>;

  saveState(state: string, data: OidcStateData, ttlMs: number): Promise<void>;

  getState(state: string): Promise<OidcStateData | null>;

  deleteState(state: string): Promise<void>;

  saveAccessToken(record: AccessToken, ttlMs: number): Promise<void>;

  getAccessToken(
    platformUrl: string,
    clientId: string,
    requestedScopes: string,
  ): Promise<AccessToken | null>;

  isMembersCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean>;

  setMembersCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean>;

  unsetMembersCaching(platformUrl: string, clientId: string, contextId: string): Promise<void>;

  setMember(platformUrl: string, clientId: string, contextId: string, user: any): Promise<boolean>;

  hasAnyMembers(platformUrl: string, clientId: string, contextId: string): Promise<boolean>;

  getPageOfMembers(
    platformUrl: string,
    clientId: string,
    contextId: string,
    start: number,
    length: number,
    filter?: (m: Member) => boolean,
    filteredCount?: number,
  ): Promise<MemberPage>;

  getAllMembers(platformUrl: string, clientId: string, contextId: string): Promise<Array<object>>;

  getCachedRoleTotals(platformUrl: string, clientId: string, contextId: string): Promise<Record<string, number> | null>;

  getCachedGroupTotals(platformUrl: string, clientId: string, contextId: string): Promise<GroupTotals | null>;

  cacheTotals(platformUrl: string, clientId: string, contextId: string): Promise<Record<string, number>>;

  hasAnyGroups(platformUrl: string, clientId: string, contextId: string): Promise<boolean>;

  isGroupsCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean>;

  setGroupsCaching(platformUrl: string, clientId: string, contextId: string): Promise<boolean>;

  unsetGroupsCaching(platformUrl: string, clientId: string, contextId: string): Promise<void>;

  setGroup(platformUrl: string, clientId: string, contextId: string, group: object): Promise<boolean>;

  getGroups(platformUrl: string, clientId: string, contextId: string): Promise<Array<Group>>;

  hasAnyLineItems(platformUrl: string, clientId: string, contextId: string, options?: LineItemOptions): Promise<boolean>;

  setLineItem(platformUrl: string, clientId: string, contextId: string, item: LineItem): Promise<boolean>;

  getLineItems(platformUrl: string, clientId: string, contextId: string, options?: LineItemOptions): Promise<Array<LineItem>>;

  getResults(platformUrl: string, clientId: string, lineItemId: string): Promise<Array<Result> | null>;

  setResult(platformUrl: string, clientId: string, lineItemId: string, result: Result): Promise<boolean>;

  saveInvitation(code: string): Promise<boolean>;

  getInvitation(code: string): Promise<string | null>;

  clearInvitation(code: string): Promise<void>;
}

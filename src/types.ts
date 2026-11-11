import { DEEP_LINKING, RESOURCE_LINK } from "./messages.ts";

import type { Context } from "hono";

// ---------------------------------------------------------------------------
// Platform configuration
// ---------------------------------------------------------------------------

export interface Platform {
  /** Issuer URL (matches iss claim in LTI tokens) */
  url: string;
  clientId: string;
  name: string;
  /** OIDC authorization endpoint */
  authEndpoint: string;
  /** OAuth2 token endpoint */
  accesstokenEndpoint: string;
  method: string;
  key: string;
  jwksUri: string;
  kid: string;
  active: boolean;
}

// ---------------------------------------------------------------------------
// Stored token records
// ---------------------------------------------------------------------------

export interface UserInfo {
  given_name?: string;
  family_name?: string;
  name?: string;
  email?: string;
  locale?: string;
}

export interface IdToken {
  iss: string;
  user: string;
  userInfo: UserInfo;
  platformInfo: Record<string, unknown>;
  clientId: string;
  platformId: string;
  deploymentId: string;
}

export interface ContextToken {
  contextId: string;
  user: string;
  roles: string[];
  path: string;
  targetLinkUri: string;
  context: Record<string, unknown>;
  resource: Record<string, unknown>;
  custom: Record<string, unknown>;
  launchPresentation: Record<string, unknown>;
  messageType: string;
  version: string;
  deepLinkingSettings?: Record<string, unknown>;
  lis: Record<string, unknown>;
  endpoint?: Record<string, unknown>;
  namesRoles?: Record<string, unknown>;
  groups?: Record<string, Array<string> | string>;
  grades?: Record<string, Array<string> | string>;
  /** tool_platform claim — `product_family_code` identifies the LMS. */
  toolPlatform?: Record<string, string>;
}

/** Combined token as seen by LTI handlers */
export interface LTIToken extends IdToken {
  platformContext: ContextToken;
}

// ---------------------------------------------------------------------------
// LTIK — our signed session JWT payload
// ---------------------------------------------------------------------------

export interface LtikPayload {
  platformUrl: string;
  clientId: string;
  deploymentId: string;
  /** base64(iss+clientId+deploymentId) — used as cookie name */
  platformCode: string;
  contextId: string;
  userId: string;
  role?: string;
  /** Random salt — makes each launch unique */
  s: string;
}

// ---------------------------------------------------------------------------
// OIDC state record (10-minute TTL)
// ---------------------------------------------------------------------------

export interface OidcStateData {
  iss: string;
  clientId?: string;
  loginHint: string;
  ltiMessageHint?: string;
  targetLinkUri?: string;
}

// ---------------------------------------------------------------------------
// OAuth2 access token cache record
// ---------------------------------------------------------------------------

export interface AccessToken {
  token: string;
  platformUrl: string;
  clientId: string;
  /** Space-separated scope string */
  requestedScopes: string;
  expiresAt: number;
}

// ---------------------------------------------------------------------------
// Handler types for the public API
// ---------------------------------------------------------------------------

export interface LTIContext {
  token: LTIToken;
  ltik: string;
}

/** Main LTI launch handler — return a Response */
export type LTIHandler = (
  c: Context,
  lti: LTIContext,
) => Response | Promise<Response>;

/** Error/lifecycle handler — return a Response */
export type ErrorHandler = (c: Context) => Response | Promise<Response>;

export interface CookieOptions {
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
  domain?: string;
}

// ---------------------------------------------------------------------------
// Tool options
// ---------------------------------------------------------------------------
export interface ToolOptions {
  /** If true, print lots of debug stuff */
  debug?: boolean;
  /** Custom route for the main LTI launch. Defaults to "/lti". */
  ltiRoute?: string;
  /** Cookie options applied to all set-cookie responses */
  cookies?: CookieOptions;
  /**
   * Extra custom parameters to request at dynamic registration, keyed by the
   * custom-claim name the platform will return. Values may be literals or LTI
   * substitution variables (e.g. "$Person.name.full"). Merged over the built-in
   * Tier 1 enrichment parameters (profile picture, pronouns, …).
   */
  customParameters?: Record<string, string>;
  services?: Array<string>;
}

export interface ContentItem {
  type: string;
  [key: string]: unknown;
}

export interface LineItem {
  id?: string;
  scoreMaximum: number;
  label: string;
  resourceId?: string;
  tag?: string;
  resourceLinkId?: string;
  [key: string]: unknown;
}

export interface LineItemOptions {
  resourceId?: string;
  tag?: string;
}

export interface Member {
  group_enrollments: Array<Record<string, string>>;
  user_id: string;
  roles: Array<string>;
  name: string;
  given_name: string;
  family_name: string;
  email: string;
  status: string;
  mobile?: string;
  phoneticName?: string;
  pronouns?: string;
  nickname?: string;
  sakai_groups?: Array<Record<string, string>>;
  sakai_role?: string;
}

/** A page of members plus the total and filtered totals. */
export interface MemberPage {
  members: Array<Member>;
  /** Total member records, ignoring any filter. */
  recordsTotal: number;
  /** Member records matching the active filter. */
  recordsFiltered: number;
}

export interface Group {
  id: string;
  name: string;
  tag: string;
}

export interface Result {
  id: string;
  userId: string;
  resultScore?: number;
  resultMaximum?: number;
  comment?: string;
}

export interface Score {
  userId: string;
  scoreGiven?: number;
  scoreMaximum?: number;
  comment?: string;
  timestamp?: string;
  activityProgress: "Initialized" | "Started" | "InProgress" | "Submitted" | "Completed";
  gradingProgress: "FullyGraded" | "Pending" | "PendingManual" | "Failed" | "NotReady";
}

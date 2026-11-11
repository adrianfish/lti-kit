/**
 * OIDC Login Initiation — POST /login
 *
 * Called by the platform to start the LTI 1.3 OIDC flow.
 * Stores state, sets a short-lived cookie, and redirects to the
 * platform's auth endpoint.
 *
 * Spec: IMS Security Framework §4.1.1
 */

import type { Context } from "hono";
import { setCookie } from "hono/cookie";
import type { LTIStorage } from "../storage/lti-storage.ts";
import type { Platform } from "../types.ts";
import { randomHex } from "../auth/keys.ts";

const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const STATE_COOKIE_TTL_MS = 60 * 1000; // 1 minute (just long enough for the round-trip)

interface LoginParams {
  iss: string;
  login_hint: string;
  target_link_uri?: string;
  lti_message_hint?: string;
  client_id: string;
  lti_deployment_id?: string;
}

export async function handleLogin(
  c: Context,
  storage: LTIStorage,
  cookieOptions: { secure: boolean; sameSite: "Lax" | "Strict" | "None" },
): Promise<Response> {
  // Accept both GET and POST (spec allows either)
  let params: LoginParams;
  if (c.req.method === "POST") {
    const body = await c.req.parseBody();
    params = body as unknown as LoginParams;
  } else {
    const q = c.req.query();
    params = q as unknown as LoginParams;
  }

  const { iss, login_hint, target_link_uri, lti_message_hint, client_id } = params;

  if (!iss || !login_hint || !client_id) {
    return c.text("Missing iss, login_hint or client_id", 400);
  }

  // Look up platform
  const platform: Platform | null = await storage.getPlatform(iss, client_id);
  if (!platform) {
    return c.text(`Unregistered platform for url ${iss} and client_id ${client_id}`, 400);
  }
  if (!platform.active) {
    return c.text(`Platform inactive for url ${iss} and client_id ${client_id}`, 401);
  }

  // Generate state (26 hex chars)
  const state = randomHex(13);

  // Store state in DB so we can validate it on the callback
  await storage.saveState(
    state,
    {
      iss,
      clientId: client_id ?? platform.clientId,
      loginHint: login_hint,
      ltiMessageHint: lti_message_hint,
      targetLinkUri: target_link_uri,
    },
    STATE_TTL_MS,
  );

  // Short-lived state cookie — binds the browser to this specific flow instance
  setCookie(c, `state${state}`, iss, {
    httpOnly: true,
    secure: cookieOptions.secure,
    sameSite: cookieOptions.sameSite,
    maxAge: STATE_COOKIE_TTL_MS / 1000,
    path: "/",
  });

  // Build auth redirect URL
  const nonce = randomHex(16);
  const redirectUrl = new URL(platform.authEndpoint);
  redirectUrl.searchParams.set("response_type", "id_token");
  redirectUrl.searchParams.set("response_mode", "form_post");
  redirectUrl.searchParams.set("scope", "openid");
  redirectUrl.searchParams.set("client_id", platform.clientId);
  redirectUrl.searchParams.set("redirect_uri", target_link_uri ?? new URL(c.req.url).origin + "/");
  redirectUrl.searchParams.set("login_hint", login_hint);
  redirectUrl.searchParams.set("state", state);
  redirectUrl.searchParams.set("nonce", nonce);
  redirectUrl.searchParams.set("prompt", "none");
  if (lti_message_hint) {
    redirectUrl.searchParams.set("lti_message_hint", lti_message_hint);
  }

  return c.redirect(redirectUrl.toString(), 302);
}

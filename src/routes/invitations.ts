import { hash } from "../crypto.ts";

import type { Context } from "hono";
import type { LTIStorage } from "../storage/lti-storage.ts";
import type { Platform } from "../types.ts";

/**
 * Creates an invitation and returns it as json, keyed on "url"
 *
 * @param {Object} c A Hono Context
 * @param {string} registrationUrl The tool's registration url
 * @param {string} secret The tool's secret.
 * @param {Object} storage The Storage for saving the invitation to.
 *
 * @returns {Object} The Promise of a Response with the json result
 */
export async function handleInvitations(
  c: Context,
  registrationUrl: string,
  secret: string,
  storage: LTIStorage,
): Promise<Response> {

  const body = await c.req.parseBody()
  const token: string | File = body["token"];
  if (!token) {
    console.warn("token must be supplied");
    c.status(400);
    return c.json({});
  }

  const hashedSecret = await hash(secret);
  if (token !== hashedSecret) {
    console.warn("Hashes not equal");
    c.status(403);
    return c.json({});
  }

  const code = crypto.randomUUID();
  if (await storage.saveInvitation(code)) {
    return c.json({ url: `${registrationUrl}?code=${code}` });
  }

  c.status(500);
  return c.json({});
}

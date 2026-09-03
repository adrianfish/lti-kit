import { ENRICHMENT_FIELDS } from "../services/enrichment-fields.ts";
import { DEEPLINKING, GRADING, ROSTER  } from "../constants.ts";
import { DEEP_LINKING, RESOURCE_LINK  } from "../messages.ts";
import { registerPlatform } from "../utils/platform-utils.ts";

import type { Context } from "@hono";
import type { Platform, ToolOptions } from "../types.ts";
import type { Storage } from "../storage/storage.ts";
import type { EnrichmentField } from "../services/enrichment-fields.ts";

export async function handleRegisterPlatform(
  c: Context,
  storage: Storage,
  toolDomain: string,
  aesKey: CryptoKey,
  clientName: string,
  description: string,
  logoUri: string,
  options: ToolOptions,
): Promise<Response> {

  const code: string | undefined = c.req.query("code");
  if (!code) {
    c.status(400);
    return c.text("You must supply an invitation code");
  }

  const storedCode: string |  null = await storage.getInvitation(code);
  if (code !== storedCode) {
    c.status(400);
    return c.text("Invalid invitation code");
  }

  const openIdUrl: string | undefined = c.req.query("openid_configuration");

  if (!openIdUrl) {
    c.status(400);
    return c.text("You must supply an openid_configuration parameter");
  }

  const openIdConfig = await fetch(openIdUrl)
    .then(r => {
      if (r.ok) {
        return r.json();
      }
      throw new Error(`Network error while retrieving OpenId configuration from ${openIdUrl}`);
    })
    .catch(e => console.error(e));

  if (options.debug) {
    console.debug("");
    console.debug(" ==== OPENID_CONFIG ====");
    console.debug(openIdConfig);
    console.debug("");
  }

  // Tier 1 enrichment: request profile picture / pronouns / … as custom
  // substitution variables, picking family-specific variables and dropping any
  // the platform doesn't advertise.
  const platformConfig = (openIdConfig?.["https://purl.imsglobal.org/spec/lti-platform-configuration"] ?? {}) as Record<
    string,
    unknown
  >;
  const familyCode = platformConfig["product_family_code"] as string | undefined;
  const supportedVariables = (platformConfig["variables"] ?? []) as string[];

  if (options.debug) {
    console.debug("SUPPORTED VARIABLES:");
    console.debug(supportedVariables);
  }

  const customParameters = filterSupportedVariables(
    buildCustomParameters(familyCode, {
      "context_history": "$Context.id.history",
      ...(options.customParameters ?? {}),
    }),
    supportedVariables,
    options.debug,
  );

  if (options.debug) {
    console.debug("FILTERED CUSTOM PARAMETERS:");
    console.debug(customParameters);
  }

  const scopesRequested = [
    "https://purl.imsglobal.org/spec/lti-reg/scope/registration",
    "https://purl.imsglobal.org/spec/lti-reg/scope/registration.readonly",
  ];

  if (options.services?.includes?.(DEEPLINKING)) {
    scopesRequested.push("https://purl.imsglobal.org/spec/lti-ags/scope/lineitem");
    scopesRequested.push("https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly");
  }

  if (options.services?.includes?.(ROSTER)) {
    scopesRequested.push("https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly");
  }

  if (options.services?.includes?.(GRADING)) {
    scopesRequested.push("https://purl.imsglobal.org/spec/lti-ags/scope/score");
    scopesRequested.push("https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly");
  }

  const messages: Array<any> = [
    {
      "type": RESOURCE_LINK,
      "target_link_uri": `https://${toolDomain}/lti`,
      "placements": [ "course_navigation", "https://canvas.instructure.com/lti/course_navigation" ],
      "https://canvas.instructure.com/lti/course_navigation/default_enabled": true,
      "https://canvas.instructure.com/lti/display_type": "full_width_in_context",
    },
  ];

  if (options.services?.includes?.(DEEPLINKING)) {
    messages.push(
      {
        "type": DEEP_LINKING,
        "target_link_uri": `https://${toolDomain}/lti`,
        "label": "Add a language",
        "placements": [ "https://canvas.instructure.com/lti/assignment_selection" ],
      }
    );
  }

  const data = {
    "application_type": "web",
    "response_types": ["id_token"],
    "grant_types": ["implicit", "client_credentials"],
    "initiate_login_uri": `https://${toolDomain}/lti/login`,
    "redirect_uris": [`https://${toolDomain}/lti`],
    "client_name": clientName,
    "logo_uri": logoUri,
    "jwks_uri": `https://${toolDomain}/lti/keys`,
    "token_endpoint_auth_method": "private_key_jwt",
    "scope": scopesRequested.join(" "),
    "https://purl.imsglobal.org/spec/lti-tool-configuration": {
      "domain": toolDomain,
      "description": description,
      "target_link_uri": `https://${toolDomain}/lti`,
      "custom_parameters": customParameters,
      messages,
      "claims": ["sub", "name", "given_name", "family_name"],
    },
  };

  if (options.debug) {
    console.debug("DATA TO BE SENT");
    console.debug(data);
  }

  const registrationEndpoint = openIdConfig["registration_endpoint"];
  const registrationToken = c.req.query("registration_token");
  if (options.debug) console.debug(`Posting tool registration to ${registrationEndpoint}`);
  const platform = await fetch(registrationEndpoint, {
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${registrationToken}`,
    },
    method: "POST",
    body: JSON.stringify(data),
  })
    .then((r) => {
      if (r.ok || r.status === 400) {
        return r.json();
      }
      throw new Error(`Network error while registering at endpoint ${registrationEndpoint}. Status: ${r.status}`);
    })
    .then((d) => {

      if (options.debug) {
        console.debug("");
        console.debug(" ==== CLIENT_REGISTRATION_RESPONSE ====");
        console.debug(d);
        console.debug("");
      }

      storage.clearInvitation(code);

      return {
        url: openIdConfig.issuer as string,
        clientId: d.client_id as string,
        name: d.name as string,
        authEndpoint: openIdConfig.authorization_endpoint as string,
        accesstokenEndpoint: openIdConfig.token_endpoint as string,
        method: openIdConfig.token_endpoint_auth_methods_supported[0] as string,
        jwksUri: openIdConfig.jwks_uri as string,
        active: true,
      };
    })
    .catch((e) => console.error(e.message));

  if (options.debug) {
    console.debug("");
    console.debug(" ==== PLATFORM ====");
    console.debug(platform);
    console.debug("");
  }

  await registerPlatform(storage, aesKey, platform as Platform, options);

  return c.html("<script>(window.opener || window.parent).postMessage({subject:'org.imsglobal.lti.close'}, '*')</script>");
}

/**
 * Build the `custom_parameters` map to send at registration, choosing the
 * family-specific substitution variable where one is declared.
 *
 * @param familyCode The platform's `product_family_code`, if known.
 * @param extra Literal/extra custom parameters merged over the enrichment ones.
 */
function buildCustomParameters(
  familyCode?: string,
  extra: Record<string, string> = {},
): Record<string, string> {

  const params: Record<string, string> = {};
  for (const field of ENRICHMENT_FIELDS) {
    const variable = (familyCode && field.byFamily?.[familyCode]) ?? field.variable;
    if (variable) params[field.param] = variable;
  }
  return { ...params, ...extra };
}

/**
 * Drop substitution-variable parameters the platform doesn't advertise.
 *
 * Dynamic registration platform configuration may list the substitution
 * variables it supports (without the leading `$`). Requesting an unsupported
 * variable can cause some platforms to echo the raw `$Foo.bar` string back or
 * reject it, so when the list is present we filter to advertised variables only.
 * Literal parameters (anything not starting with `$`) are always kept.
 */
function filterSupportedVariables(
  params: Record<string, string>,
  supportedVariables: string[] = [],
  debug = false,
): Record<string, string> {

  if (!supportedVariables.length) return params;

  const supported = new Set(supportedVariables);
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(params)) {
    if (value.startsWith("$") && !supported.has(value.slice(1))) {
      if (debug) console.debug(`Dropping unsupported custom parameter ${key}=${value}`);
      continue;
    }
    result[key] = value;
  }
  return result;
}

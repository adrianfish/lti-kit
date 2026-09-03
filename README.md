# lti-kit

A [LTI 1.3](https://www.imsglobal.org/spec/lti/v1p3/) tool library for [Deno](https://deno.com/),
using [Hono](https://hono.dev/) for the built in LTI routing.

Implements the full LTI 1.3 + OIDC launch flow, Assignment & Grade Services (AGS), Deep Linking, and
Names & Roles Provisioning. Uses Deno KV for storage.

For full documentation of the api, run "deno task doc" to generate a set of html documents under the
docs directory.

## Installation

Install from JSR:

deno add jsr:@adrianfish/lti-kit

## Quick start

The basic idea is that you, the user of this library, would write a web application in Javascript or
Typescript and you would add the lti-kit handler to your routing architecture. lti-kit handles all
of the LTI 1.3 stuff, storing keys and other LTI data under the "lti" prefix in a Deno KV store. You
would then be free to add hooks to lti-kit so your code can react to LTI 1.3 launches and
*do stuff*. You create the lti-kit instance and chain api calls, handlers first then setup.

```ts
import { LTIKit } from "jsr:@adrianfish/lti-kit";
import { Hono } from "jsr:@hono/hono";

import type { Context } from "jsr:@hono/hono";

const lti = new LTIKit();

await lti
  .onLaunch((c: Context, ltiContext: LTIContext) => {
    return c.html(`<h1>Hello, ${ltiContext.token.userInfo.name}!</h1>`);
  })
  .setup("my-lti-tool-domain.com", "SECRET", "My LTI Tool", "A tool that does stuff", "https://logos.com/my-tool-logo.png");

// If you're using Hono for your app logic, you can mount under a sub-path alongside other routes
const app = new Hono();
app.route("/lti", lti.handler());

// Your application's routing.
app.get("/some-app-route", someAppRouteHandler);
app.get("/some-other-app-route", someOtherAppRouteHandler);

Deno.serve(app.fetch);
```

The secret is used to sign session tokens (LTIKs) and encrypt stored RSA keys. It must remain
consistent across restarts — changing it invalidates all active sessions and stored keys.

## Built-in routes

Once initialized, `lti.handler()` exposes these routes:

| Method | Path | Purpose |
|--------|------|---------|
| `GET, POST` | `/login` | OIDC login initiation (third-party login) |
| `GET, POST` | `/register` | Dynamic platform registration |
| `GET` | `/keys` | JWKS endpoint (your tool's public keys) |
| `GET, POST` | `/lti` *(or `appRoute`)* | LTI launch and subsequent requests |
| `POST` | `/lti/management/invitations` | REST endpoint to generate LTI invitation codes |

When registering your tool with a platform, point the **Initiate Login URL** at `/login`, the
**Redirect/Launch URL** at `/lti` (or your `appRoute`), and the **Public Key / JWKS URL** at
`/keys`.

Must be called after `setup()`.

---

### Invitations

lti-kit provides a basic system for securing which platforms can register. An invitation is a code
which is generated at the invitations REST endpoint, returning a custom registration url that can be
supplied to the platform administrator for dynamic registration of the lti-kit tool.

### Session token transport

Subsequent requests (after the initial launch redirect), to lti-kit apis for example,  **must**
carry the LTIK session token as a query parameter.

`?ltik=<ltik>` query parameter

---

## Platform registration

Direct the platform to `GET /register?openid_configuration=<url>`. The handler fetches the platform's
OpenID configuration, completes OAuth2 dynamic client registration, and stores the platform
automatically.

---

## LTI 1.3 specifications

| Specification | Link |
|---------------|------|
| LTI 1.3 Core | https://www.imsglobal.org/spec/lti/v1p3/ |
| LTI Security Framework (OIDC) | https://www.imsglobal.org/spec/security/v1p0/ |
| Assignment and Grade Services 2.0 | https://www.imsglobal.org/spec/lti-ags/v2p0/ |
| Deep Linking 1.2 | https://www.imsglobal.org/spec/lti-dl/v1p0/ |
| Names and Role Provisioning Services 2.0 | https://www.imsglobal.org/spec/lti-nrps/v2p0/ |
| LTI 1.3 Implementation Guide | https://www.imsglobal.org/spec/lti/v1p3/impl/ |

## Description

This is a TypeScript library which adds LTI 1.3 Advantage capabilities to a client web application

## Architecture

### LTI 1.3 Call Routing

lti-kit.ts creates a Hono app to handle the LTI 1.3 routes and that app is then intended to be
mounted by a client web application, on a path of the web application's choosing

### Database

lti-kit exports a type, LTIStorage, which declares all the api methods needed to storing and
retrieving LTI 1.3 data. There are two included implementations, one for Deno KV and one for
Cloudflare workers D1.

If you need information on Deno KV, see https://docs.deno.com/deploy/kv/
If you need information on Cloudflare D1, see https://developers.cloudflare.com/d1/


## Commands

```bash
# Run tests
npm run test

# Type-check
npm run check
```

## Conventions

- Group routes with `Hono` sub-app instances (`app.route('/users', usersRoute)`) instead of one giant file.
- Add any storage access method declarations to `lti-storage.ts`.
- Use explicit types for request/response shapes; use any only if it significantly reduces code complexity

## Testing

- Use the `test` script from `package.json`. `npm run test`
- Test files live alongside source as `*_test.ts`.

## Notes for Agents

- The version of LTI is 1.3 with the LTI Advantage extensions. There is no support for older versions of the LTI specifications.

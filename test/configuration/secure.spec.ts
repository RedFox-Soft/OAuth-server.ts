import { describe, it } from 'bun:test';

// JUSTIFIED SKIP — obsolete contract.
//
// This suite verified koa-era `x-forwarded-proto` proxy trust: with `app.proxy = true`
// (or `provider.proxy = true`) the discovery document was expected to flip its endpoint
// URLs to `https:` based on the per-request `x-forwarded-proto` header.
//
// The Elysia rewrite has no such mechanism. Every discovery endpoint is derived from the
// static `ISSUER` env var via `new URL(route, ISSUER)` (see lib/configs/discoverySupport.ts),
// so the endpoint protocol is fixed at boot and never negotiated from proxy headers. There is
// no `provider.proxy` / `app.proxy` flag and no `x-forwarded-proto` handling anywhere in lib/.
// The behaviour under test cannot exist, so there is nothing to migrate.
describe.skip('x-forwarded-proto trust (obsolete: issuer-derived endpoints, no proxy trust)', () => {
	it('is trusted when proxy=true is set on the koa app', () => {});
});

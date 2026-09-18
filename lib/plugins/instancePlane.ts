import { Elysia } from 'elysia';

import { bucketAtHost, isCanonicalHost } from 'lib/admin/auth/bucketAddress.js';
import { hostOfRequest } from 'lib/consts/request_host.js';

/*
 * The first path segments that belong to the instance rather than to any population.
 *
 * The administrative console and the agent endpoint are properties of the deployment: the console
 * authenticates against the instance's own issuer as a relying party, and the agent's audience is the
 * instance. Both already appear in `reserved_names.ts` for the same reason one segment further out — no
 * bucket may take either name — and this is the other half of that rule, for the other address form.
 */
export const INSTANCE_PLANE_PREFIXES: readonly string[] = ['/admin', '/mcp'];

function isInstancePlanePath(pathname: string): boolean {
	return INSTANCE_PLANE_PREFIXES.some(
		(prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
	);
}

/*
 * Those surfaces, refused at a tenant's address.
 *
 * Serving either at `acme.auth.example.com` would give one instance-wide surface a second origin, and
 * would let a tenant's hostname reach an operator surface. A 404 rather than a 403, because the honest
 * answer is that nothing is served there; a 403 would confirm the surface exists at an address it does
 * not.
 *
 * **`onRequest`, not `onBeforeHandle`, and that is the whole difficulty.** Schema validation runs
 * before `beforeHandle` and throws rather than returning — the trap `lib/mcp/index.ts` already records
 * about its own header schema — so a guard at that stage never runs for a route whose query or body
 * fails to validate. `/admin/callback` demonstrated it exactly: every other admin route was refused at
 * a bucket host and that one answered 422, because its query schema rejected the empty request first.
 * A refusal that holds for every route except the ones carrying a schema is not a refusal, and the
 * completeness case in test/host_buckets/surface_parity.spec.ts is what found it.
 *
 * `onRequest` runs before routing, so it matches on the path itself rather than on the route that
 * would have matched. That is why the prefixes above are declared rather than derived, and why the
 * test enumerates the *mounted route table* beneath them instead of trusting this list.
 */
export const instancePlaneOnly = new Elysia({
	name: 'instance-plane-only'
}).onRequest(async ({ request, set }) => {
	if (!isInstancePlanePath(new URL(request.url).pathname)) return;

	const host = hostOfRequest(request);
	if (host === null || isCanonicalHost(host)) return;

	/*
	 * Only a host that actually addresses a bucket is refused. A deployment answers at more names than
	 * its canonical one — `localhost`, the platform's own, whatever a health check uses — and an
	 * operator reaching the console at one of those is doing something ordinary.
	 */
	if (!(await bucketAtHost(host))) return;

	set.status = 404;
	return { error: 'not_found' };
});

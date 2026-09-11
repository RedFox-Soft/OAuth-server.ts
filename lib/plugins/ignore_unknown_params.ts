import { Elysia } from 'elysia';
import type { TObject } from '@sinclair/typebox';

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}

/**
 * The parameter names a schema declares — the one definition of "recognized" for the request it
 * guards, so the answer cannot drift from what the route actually validates.
 */
export function declaredParams(...schemas: TObject[]): Set<string> {
	const names = new Set<string>();
	for (const schema of schemas) {
		for (const name of Object.keys(schema.properties)) {
			names.add(name);
		}
	}
	return names;
}

/**
 * Deletes every key the schema does not declare. A parameter the server does not recognize is
 * dropped rather than carried, which is what "ignore" has to mean for a request that is later
 * persisted: PAR stores its parameters as a request object and the interaction record stores them
 * again, so anything carried is anything a client can make this server keep.
 */
export function ignoreUnknownIn(declared: Set<string>, target: unknown): void {
	if (!isRecord(target)) return;
	for (const name of Object.keys(target)) {
		if (!declared.has(name)) {
			delete target[name];
		}
	}
}

/**
 * Elysia plugin: ignore request parameters the route does not define, instead of refusing the
 * request.
 *
 * Every endpoint that takes authorization-request parameters is required to do this — RFC 6749
 * §3.1 and §3.2, RFC 8628 §3.1 and CIBA §7.1 all carry the same MUST, and RFC 9126 §2.1 inherits it
 * for PAR by processing a pushed request as an authorization request. It is what makes the protocol
 * extensible: a client may send what a newer profile defines, and an older server must still answer.
 *
 * Runs at the `transform` stage, before validation, and is scoped to the routes of the instance that
 * mounts it — the same shape as coerceArrayParams and parseJsonParams, which it runs alongside.
 *
 * Elysia's own `normalize: true` does something adjacent, and is not what this wants. Two measured
 * differences, not preferences. It cleans *headers* against the route's header schema, and this
 * server reads headers no schema enumerates — `x-client-cert` in addon/mtls.ts above all — so under
 * the flag a certificate-bound token presented WITH its certificate answers 401. And it repairs the
 * input to fit the schema rather than only dropping what the schema does not name, so a malformed
 * `claims` stops being refused and is silently emptied instead. This deletes undeclared keys from
 * body and query, touches nothing else, and lets validation answer for everything that remains.
 *
 * A parameter that must be *refused* rather than ignored — `request_uri` at the pushed endpoint
 * (RFC 9126 §2.1), `registration` at the authorization endpoint (OIDC Core §7.2.1) — is a declared
 * member typed `t.Undefined`, not an absent one. Absence here means "ignore", and nothing else.
 */
export function ignoreUnknownParams(...schemas: TObject[]) {
	const declared = declaredParams(...schemas);

	return new Elysia().onTransform({ as: 'scoped' }, ({ body, query }) => {
		ignoreUnknownIn(declared, body);
		ignoreUnknownIn(declared, query);
	});
}

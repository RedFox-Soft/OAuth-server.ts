import { isPlainObject } from './_/object.js';

/* One requested claim as a reader uses it — `values` is still checked for being an array where read. */
export type ClaimRequest = {
	essential?: unknown;
	value?: unknown;
	values?: unknown;
};

/*
 * A claims member read as a claim request. Any non-object value — `null` ("requested, no
 * constraints") or something the server ignores (OIDC Core §5.5) — reads as having no constraints,
 * which is what property access on it already yielded. A leaf module so the interaction policy can use
 * it without importing the request context.
 */
export function claimRequest(value: unknown): ClaimRequest {
	return isPlainObject(value) ? value : {};
}

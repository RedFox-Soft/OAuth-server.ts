import { isDeepStrictEqual } from 'node:util';
import { pick, isPlainObject, merge } from './_/object.js';
import { configuration } from 'lib/configs/application.js';
import { pairwiseIdentifier } from '../addon/index.js';
import { type Client } from 'lib/models/client.js';

type ClaimsData = Record<string, unknown> & {
	_claim_names?: Record<string, string>;
	_claim_sources?: Record<string, unknown>;
};

/*
 * Claims whose requested value is governed by a rule of their own rather than by omission: a subject
 * that does not match fails the authentication (the login prompt's claims_id_token_sub_value), a
 * voluntary acr that cannot be met is answered with the session's current one (OIDC Core §5.5.1.1),
 * and amr reports the methods the sign-in used whatever was asked for
 * (wiki/concepts/amr-reporting.md) — the grant sets it on the token after this mask in any case.
 */
const OWN_VALUE_RULES = new Set(['sub', 'acr', 'amr']);

/*
 * OIDC Core §5.5.1: "When the Claim value does not match the requested value, the Claim is not
 * included in the response", by an equality comparison, with `values` processed the same way. The
 * comparison is of JSON values, so a structured claim matches on content and `"false"` is not
 * `false`. A claim held by another provider (aggregated or distributed) has no value here to compare
 * and is left to the reference.
 */
function valueDiffers(
	name: string,
	request: unknown,
	available: ClaimsData
): boolean {
	if (
		!isPlainObject(request) ||
		OWN_VALUE_RULES.has(name) ||
		!Object.hasOwn(available, name)
	) {
		return false;
	}
	const actual = available[name];
	if ('value' in request && !isDeepStrictEqual(request.value, actual)) {
		return true;
	}
	return (
		Array.isArray(request.values) &&
		!request.values.some((value) => isDeepStrictEqual(value, actual))
	);
}

export class Claims {
	client: Client;
	available: ClaimsData = {};
	filter: Record<string, unknown> = {};

	constructor(client: Client, available: ClaimsData) {
		this.available = available;
		this.client = client;
	}

	scope(value = '') {
		if (Object.keys(this.filter).length) {
			throw new Error('scope cannot be assigned after mask has been set');
		}
		const { claims: claimConfig } = configuration;
		value.split(' ').forEach((scope) => {
			// A scope's entry is the map of claims it grants. Anything else — an unknown scope, or a
			// name that is a standalone claim rather than a scope — grants none.
			const granted = claimConfig[scope];
			if (isPlainObject(granted)) this.mask(granted);
		});
		return this;
	}

	mask(value: Record<string, unknown> = {}) {
		merge(this.filter, value);
	}

	rejected(value: readonly string[] = []) {
		value.forEach((claim) => {
			delete this.filter[claim];
		});
	}

	async result(): Promise<ClaimsData> {
		const { available } = this;
		const { claimsSupported } = configuration;
		const include = Object.entries(this.filter)
			.filter(
				([key, value]) =>
					(value === null || isPlainObject(value)) &&
					claimsSupported.has(key) &&
					!valueDiffers(key, value, available)
			)
			.map(([key]) => key);

		const claims: ClaimsData = pick(available, ...include);

		if (available._claim_names && available._claim_sources) {
			const names = pick(available._claim_names, ...include);
			claims._claim_names = names;
			claims._claim_sources = pick(
				available._claim_sources,
				...Object.values(names)
			);

			if (!Object.keys(names).length) {
				delete claims._claim_names;
				delete claims._claim_sources;
			}
		}

		if (this.client.subjectType === 'pairwise' && claims.sub) {
			// Refused rather than passed through: a subject left as it is would reach a pairwise client.
			if (typeof claims.sub !== 'string') {
				throw new TypeError('an account subject must be a string');
			}
			claims.sub = await pairwiseIdentifier(claims.sub, this.client);
		}

		return claims;
	}
}

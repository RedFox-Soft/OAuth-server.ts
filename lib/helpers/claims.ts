import instance from './weak_cache.ts';
import { pick, isPlainObject, merge } from './_/object.js';
import { provider } from 'lib/provider.js';
import { type Client } from 'lib/models/client.js';

type ClaimsData = Record<string, unknown> & {
	_claim_names?: Record<string, string>;
	_claim_sources?: Record<string, unknown>;
};

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
		const { claims: claimConfig } = instance(provider).configuration;
		value.split(' ').forEach((scope) => {
			this.mask(claimConfig[scope]);
		});
		return this;
	}

	mask(value: Record<string, unknown> = {}) {
		merge(this.filter, value);
	}

	rejected(value = []) {
		value.forEach((claim) => {
			delete this.filter[claim];
		});
	}

	async result() {
		const { available } = this;
		const { claimsSupported, pairwiseIdentifier } =
			instance(provider).configuration;
		const include = Object.entries(this.filter)
			.filter(
				([key, value]) =>
					(value === null || isPlainObject(value)) && claimsSupported.has(key)
			)
			.map(([key, value]) => key);

		const claims = pick(available, ...include);

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
			claims.sub = await pairwiseIdentifier(claims.sub, this.client);
		}

		return claims;
	}
}

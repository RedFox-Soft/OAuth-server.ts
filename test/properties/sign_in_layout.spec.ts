/*
 * The sign-in page's provider layout (specs/105), checked against generated provider lists rather than a few
 * examples. The rule has three thresholds and a carve-out for brands, and the cases worth worrying about are the
 * boundaries between them — a list of exactly seven, five brands and two directories, a fold of one — which
 * nobody writes down as examples until one ships.
 *
 * Pure, like the rest of this directory: the rule runs in a browser too (the console's preview), so it takes
 * the project as an argument and needs no harness.
 */

import { describe, it, expect } from 'bun:test';
import fc from 'fast-check';

import type { FederationProvider } from 'lib/federation/types.js';
import {
	signInOptionsOf,
	type SignInSettings
} from 'lib/interactions/signInOptions.js';

const BRAND_ISSUERS = [
	'https://accounts.google.com',
	'https://login.microsoftonline.com/contoso.example/v2.0',
	'https://login.microsoftonline.com/fabrikam.example/v2.0',
	'https://appleid.apple.com',
	'https://github.com'
];

function connection(issuer: string, index: number): FederationProvider {
	return {
		id: `p${String(index)}`,
		displayName: `Provider ${String(index)}`,
		enabled: true,
		issuer,
		clientId: 'x',
		clientSecret: 'y',
		scopes: ['openid'],
		emailTrusted: false,
		provisioning: 'jit',
		allowedEmailDomains: [],
		emailClaim: 'email'
	};
}

/* Each slot is a brand or a directory, at random; the administrator's order is the shuffled id list. */
const project = fc
	.array(
		fc.oneof(
			fc.constantFrom(...BRAND_ISSUERS),
			fc.constant('https://directory.test')
		),
		{ minLength: 1, maxLength: 12 }
	)
	.chain((issuers) => {
		const federation = issuers.map(connection);
		return fc
			.shuffledSubarray(
				federation.map((p) => p.id),
				{ minLength: federation.length, maxLength: federation.length }
			)
			.map((signInOrder) => ({
				passwordLogin: true,
				registrationOpen: true,
				totpRequired: false,
				federation,
				signInOrder
			}));
	});

function layout(bucket: SignInSettings & { signInOrder: string[] }) {
	const { providers } = signInOptionsOf('b', bucket, true);
	return {
		order: providers.map((p) => p.id),
		visible: providers.filter((p) => !p.folded),
		folded: providers.filter((p) => p.folded),
		branded: providers.filter((p) => p.brand !== undefined)
	};
}

const isSubsequence = (part: string[], whole: string[]) => {
	let i = 0;
	for (const id of whole) if (id === part[i]) i++;
	return i === part.length;
};

describe('for every provider list a project can offer', () => {
	it('keeps every recognised provider out of the fold', () => {
		fc.assert(
			fc.property(project, (bucket) => {
				const { folded } = layout(bucket);
				expect(folded.every((p) => p.brand === undefined)).toBe(true);
			})
		);
	});

	it('folds nothing while there are six providers or fewer', () => {
		fc.assert(
			fc.property(project, (bucket) => {
				const { order, folded } = layout(bucket);
				if (order.length <= 6) expect(folded).toEqual([]);
			})
		);
	});

	it('folds two providers or more, or none', () => {
		fc.assert(
			fc.property(project, (bucket) => {
				const { folded } = layout(bucket);
				expect(folded.length === 0 || folded.length >= 2).toBe(true);
			})
		);
	});

	it('leaves five visible, or every brand when there are more, whenever it folds', () => {
		fc.assert(
			fc.property(project, (bucket) => {
				const { visible, folded, branded } = layout(bucket);
				if (folded.length > 0)
					expect(visible.length).toBe(Math.max(5, branded.length));
			})
		);
	});

	it('keeps the administrator’s order inside each group', () => {
		fc.assert(
			fc.property(project, (bucket) => {
				const { order, visible, folded } = layout(bucket);
				expect(order).toEqual(bucket.signInOrder);
				expect(
					isSubsequence(
						visible.map((p) => p.id),
						order
					)
				).toBe(true);
				expect(
					isSubsequence(
						folded.map((p) => p.id),
						order
					)
				).toBe(true);
			})
		);
	});

	it('names a connection under its brand exactly when another shares that brand', () => {
		fc.assert(
			fc.property(project, (bucket) => {
				const { providers } = signInOptionsOf('b', bucket, true);
				for (const p of providers) {
					const shared =
						p.brand !== undefined &&
						providers.some((o) => o !== p && o.brand === p.brand);
					expect(p.subtitle).toBe(shared ? p.displayName : undefined);
				}
			})
		);
	});
});

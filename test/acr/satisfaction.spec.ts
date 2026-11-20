import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	meets,
	reachedAcr,
	reportedAcr,
	satisfiesAny
} from 'lib/helpers/acr_satisfaction.ts';
import {
	PHISHING_RESISTANT_FALLBACK,
	withPhishingResistant
} from 'lib/consts/acr.ts';

const PWD = 'urn:example:acr:pwd';
const MFA = 'urn:example:acr:mfa';
const PHR = 'urn:example:acr:phr';
const FED = 'urn:example:acr:federated';

function asking(...values: string[]) {
	return { id_token: { acr: { values } } };
}

beforeAll(async () => {
	await bootstrap(import.meta.url);
});

/**
 * @proves A provider sign-in meets only the provider context and an unknown context meets nothing, so neither ever
 * passes a requirement of a code or of a passkey; a phishing-resistant sign-in meets every context a code meets.
 */
describe('which sign-in meets which requirement', () => {
	it('never lets a provider sign-in meet a requirement of a code or of a passkey', () => {
		expect(meets(FED, 'multi_factor')).toBe(false);
		expect(meets(FED, 'phishing_resistant')).toBe(false);
		expect(meets(FED, 'password')).toBe(false);
		expect(meets(FED, 'federated')).toBe(true);
	});

	it('never lets an unknown or absent context meet anything', () => {
		for (const required of [
			'password',
			'multi_factor',
			'phishing_resistant',
			'federated'
		] as const) {
			expect(meets('urn:example:acr:renamed', required)).toBe(false);
			expect(meets(undefined, required)).toBe(false);
		}
	});

	it('lets a phishing-resistant sign-in meet the password and multi-factor contexts', () => {
		expect(meets(PHR, 'password')).toBe(true);
		expect(meets(PHR, 'multi_factor')).toBe(true);
		expect(meets(PHR, 'phishing_resistant')).toBe(true);
	});

	it('never lets a code meet a requirement of a passkey', () => {
		expect(meets(MFA, 'phishing_resistant')).toBe(false);
		expect(satisfiesAny([PHR], MFA)).toBe(false);
	});

	it('judges a record from before the split on the value it reported', () => {
		expect(reachedAcr({ acr: MFA })).toBe(MFA);
		expect(reachedAcr({ acr: MFA, signInAcr: PHR })).toBe(PHR);
	});
});

/**
 * @proves `phr` reaches a token only when the request named it, and a request that named values is told the strongest
 * of them the sign-in met (contracts/protocol.md).
 */
describe('what a token says about the sign-in', () => {
	it.each([
		['nothing asked, passkey', PHR, undefined, MFA],
		['nothing asked, code', MFA, undefined, MFA],
		['nothing asked, provider', FED, undefined, FED],
		['phr asked, passkey', PHR, asking(PHR), PHR],
		['phr asked, code', MFA, asking(PHR), MFA],
		['phr and mfa asked, code', MFA, asking(PHR, MFA), MFA],
		['pwd asked, passkey', PHR, asking(PWD), PWD],
		['pwd asked, code', MFA, asking(PWD), PWD],
		['mfa asked, passkey', PHR, asking(MFA), MFA],
		['phr asked, provider', FED, asking(PHR), FED],
		['an unknown value asked, passkey', PHR, asking('urn:other'), MFA]
	])('%s', (_case, reached, claims, told) => {
		expect(reportedAcr(reached, claims)).toBe(told);
	});

	it('takes a single essential value as named', () => {
		expect(
			reportedAcr(PHR, { id_token: { acr: { essential: true, value: PHR } } })
		).toBe(PHR);
	});
});

/**
 * @proves An operator's stored names are kept when the phishing-resistant context is added, and `phr` is never given
 * to it when the operator already uses that name.
 */
describe('naming the phishing-resistant context in stored names', () => {
	it('adds phr and keeps every other name', () => {
		expect(
			withPhishingResistant({
				password: '1',
				multi_factor: '2',
				federated: '3'
			})
		).toEqual({
			next: {
				password: '1',
				multi_factor: '2',
				federated: '3',
				phishing_resistant: 'phr'
			},
			chosen: 'phr'
		});
	});

	it('falls back when the operator already named another context phr', () => {
		expect(
			withPhishingResistant({
				password: '1',
				multi_factor: '2',
				federated: 'phr'
			})?.chosen
		).toBe(PHISHING_RESISTANT_FALLBACK);
	});

	it('changes nothing once the context is named', () => {
		expect(
			withPhishingResistant({
				password: '1',
				multi_factor: '2',
				phishing_resistant: 'p',
				federated: '3'
			})
		).toBeUndefined();
	});
});

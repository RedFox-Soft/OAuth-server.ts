/*
 * Where an instance can offer passkeys (specs/139 research R4), checked over generated instance addresses rather than
 * a few examples: every host form an operator can put in ISSUER — an IPv4 or IPv6 address, `localhost`, a name under
 * it, any other name — under both schemes, with and without a port.
 *
 * Pure, like the rest of this directory: the predicates take the address as an argument and need no harness.
 */

import { describe, expect, it } from 'bun:test';
import fc from 'fast-check';

import {
	passkeysNeedHttps,
	passkeysPossible
} from 'lib/passkeys/relying_party.js';

type Form = 'ipv4' | 'ipv6' | 'localhost' | 'under-localhost' | 'name';

const host: fc.Arbitrary<{ form: Form; host: string }> = fc.oneof(
	fc.ipV4().map((address) => ({ form: 'ipv4' as const, host: address })),
	// Only the forms a URL can hold: an ISSUER the URL parser refuses never reaches these predicates.
	fc
		.ipV6()
		.filter((address) => URL.canParse(`http://[${address}]`))
		.map((address) => ({ form: 'ipv6' as const, host: `[${address}]` })),
	fc.constant({ form: 'localhost' as const, host: 'localhost' }),
	fc.domain().map((name) => ({
		form: 'under-localhost' as const,
		host: `${name}.localhost`
	})),
	fc
		.domain()
		.filter((name) => name !== 'localhost' && !name.endsWith('.localhost'))
		.map((name) => ({ form: 'name' as const, host: name }))
);

const issuer = fc
	.record({
		at: host,
		scheme: fc.constantFrom('http', 'https'),
		port: fc.option(fc.integer({ min: 1, max: 65535 }), { nil: undefined })
	})
	.map(({ at, scheme, port }) => ({
		form: at.form,
		scheme,
		issuer: `${scheme}://${at.host}${port === undefined ? '' : `:${String(port)}`}`
	}));

/**
 * @proves For every instance address, passkeys may be turned on exactly when its host is a name, and the console asks
 * for HTTPS exactly when a browser would not offer passkeys there.
 */
describe('instance addresses and passkeys', () => {
	it('allows passkeys exactly when the host is a name, never an IP address', () => {
		fc.assert(
			fc.property(issuer, ({ form, issuer: address }) => {
				expect(passkeysPossible(address)).toBe(
					form !== 'ipv4' && form !== 'ipv6'
				);
			})
		);
	});

	it('asks for HTTPS exactly over plain http at a host other than localhost or a name under it', () => {
		fc.assert(
			fc.property(issuer, ({ form, scheme, issuer: address }) => {
				expect(passkeysNeedHttps(address)).toBe(
					scheme === 'http' &&
						form !== 'localhost' &&
						form !== 'under-localhost'
				);
			})
		);
	});
});

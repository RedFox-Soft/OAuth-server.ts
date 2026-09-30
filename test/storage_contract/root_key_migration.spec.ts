import { describe, it, expect } from 'bun:test';

import { rootSignersOf } from 'lib/consts/migrations.js';

const key = (kid: string, alg: string, use?: 'sig' | 'enc') => ({
	kid,
	alg,
	...(use ? { use } : {})
});

/**
 * @proves Upgrading keeps the key that signed before: the migration's rule picks, per algorithm, the
 * key the server was signing with — the first in the store's order, or the lowest kid where the store
 * has no order — and makes no other key, and no encryption key, a signer.
 */
describe('the root key migration’s choice of signer', () => {
	it('picks, per algorithm, the first signing key in the order the store returned', () => {
		const signers = rootSignersOf(
			[
				key('z-rsa', 'RS256', 'sig'),
				key('a-rsa', 'RS256', 'sig'),
				key('ec', 'ES256')
			],
			{ ordered: true }
		);

		expect([...signers].sort()).toEqual(['ec', 'z-rsa']);
	});

	it('picks the lowest kid in byte order where the store gives no order', () => {
		const signers = rootSignersOf(
			[key('z-rsa', 'RS256'), key('B-rsa', 'RS256'), key('a-rsa', 'RS256')],
			{ ordered: false }
		);

		expect([...signers]).toEqual(['B-rsa']);
	});

	it('makes no encryption key a signer', () => {
		const signers = rootSignersOf(
			[key('enc', 'RSA-OAEP-256', 'enc'), key('rsa', 'RS256')],
			{ ordered: true }
		);

		expect([...signers]).toEqual(['rsa']);
	});

	it('picks no second signer in an algorithm that already has one', () => {
		const signers = rootSignersOf([key('late', 'RS256')], {
			ordered: true,
			alreadySigning: ['RS256']
		});

		expect([...signers]).toEqual([]);
	});
});

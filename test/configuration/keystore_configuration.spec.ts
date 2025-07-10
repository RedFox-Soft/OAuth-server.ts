import { randomBytes } from 'node:crypto';
import { describe, it, afterEach } from 'bun:test';
import { generateKeyPair, exportJWK } from 'jose';
import { createSandbox } from 'sinon';
import { expect } from 'chai';

import provider from '../../lib/index.ts';

const sinon = createSandbox();

describe('configuration.jwks', () => {
	afterEach(sinon.restore);

	it('must be a valid JWKS object', async () => {
		expect(() => {
			provider.init('http://localhost', {
				jwks: []
			});
		}).to.throw('keystore must be a JSON Web Key Set formatted object');
	});

	it('must only contain RSA, EC, or OKP keys', () => {
		expect(() => {
			provider.init('http://localhost', {
				jwks: {
					keys: [{ kty: 'oct', k: randomBytes(32).toString('base64url') }]
				}
			});
		}).to.throw('only RSA, EC, or OKP keys should be part of jwks');
	});

	it('must only contain private keys', async () => {
		const { publicKey } = await generateKeyPair('EdDSA');
		const jwk = await exportJWK(publicKey);
		jwk.alg = 'EdDSA';
		const jwks = { keys: [jwk] };

		expect(() => {
			provider.init('http://localhost', { jwks });
		}).to.throw(
			'jwks.keys[0] has validation failed /d Expected required property'
		);
	});

	it('rejects if "kid" is the same for multiple keys', async () => {
		const [rsa, ec] = await Promise.all([
			generateKeyPair('RS256', { extractable: true }),
			generateKeyPair('ES256', { extractable: true })
		]);
		const config = {
			jwks: {
				keys: [
					{
						...(await exportJWK(rsa.privateKey)),
						kid: 'nov-2019',
						alg: 'RS256'
					},
					{ ...(await exportJWK(ec.privateKey)), kid: 'nov-2019', alg: 'ES256' }
				]
			}
		};

		expect(() => {
			provider.init('http://localhost', config);
		}).to.throw('jwks.keys[1].kid must be unique, found duplicate: nov-2019');
	});
});

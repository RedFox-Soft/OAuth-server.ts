import { generateKeyPair, generateSecret, exportJWK } from 'jose';
import { describe, it, expect } from 'bun:test';

import * as JWT from '../../lib/helpers/jwt.ts';
import * as base64url from '../../lib/helpers/base64url.ts';
import epochTime from '../../lib/helpers/epoch_time.ts';
import KeyStore from '../../lib/helpers/keystore.ts';

/**
 * @proves A token is signed and verified with a real algorithm and a real key, and alg=none, a
 * wrong audience, a wrong issuer or an out-of-window claim is refused.
 */
describe('JSON Web Token (JWT) RFC7519 implementation', () => {
	describe('.decode()', () => {
		it('a value that is not a token is refused rather than partially decoded', () => {
			// @ts-expect-error what is refused here is a value that is not a string
			expect(() => JWT.decode({})).toThrow(TypeError);
		});

		it('a compact serialization without exactly three segments is refused', () => {
			expect(() => JWT.decode('foo.bar.baz.')).toThrow(TypeError);
		});
	});

	/*
	 * Built by hand: nothing here will sign with alg=none, so a token signed through `sign` never
	 * reached `verify` and the refusal it proved was the signer's. An unsecured JWT (RFC 7519 §6) is a
	 * header and payload with an empty signature.
	 */
	it('refuses an unsecured token even where a key is configured', async () => {
		const keyobject = await generateSecret('HS256', { extractable: true });
		const jwk = await exportJWK(keyobject);
		const unsecured = [{ alg: 'none' }, { data: true }]
			.map((part) => base64url.encode(JSON.stringify(part)))
			.join('.');

		await expect(
			JWT.verify(`${unsecured}.`, new KeyStore([jwk]))
		).rejects.toThrow();
	});

	it('signs and validates with oct', async () => {
		const keyobject = await generateSecret('HS256', { extractable: true });
		const jwk = await exportJWK(keyobject);
		return JWT.sign({ data: true }, keyobject, 'HS256')
			.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
			.then((decoded) => {
				expect(decoded.header).not.toHaveProperty('kid');
				expect(decoded.header).toHaveProperty('alg', 'HS256');
				expect(decoded.payload).toMatchObject({ data: true });
			});
	});

	it('a claim value outside ASCII survives signing and verification unchanged', async () => {
		const keyobject = await generateSecret('HS256', { extractable: true });
		return JWT.sign({ 'ś∂źć√': 'ś∂źć√' }, keyobject, 'HS256')
			.then((jwt) => JWT.decode(jwt))
			.then((decoded) => {
				expect(decoded.payload).toMatchObject({ 'ś∂źć√': 'ś∂źć√' });
			});
	});

	it('signs and validates with RSA', async () => {
		const { privateKey, publicKey } = await generateKeyPair('RS256');
		const jwk = await exportJWK(publicKey);
		return JWT.sign({ data: true }, privateKey, 'RS256')
			.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
			.then((decoded) => {
				expect(decoded.header).toHaveProperty('alg', 'RS256');
				expect(decoded.payload).toMatchObject({ data: true });
			});
	});

	it('signs and validates with EC', async () => {
		const { privateKey, publicKey } = await generateKeyPair('ES256');
		const jwk = await exportJWK(publicKey);
		return JWT.sign({ data: true }, privateKey, 'ES256')
			.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
			.then((decoded) => {
				expect(decoded.header).toHaveProperty('alg', 'ES256');
				expect(decoded.payload).toMatchObject({ data: true });
			});
	});

	it('signs and validates with EdDSA', async () => {
		const { privateKey, publicKey } = await generateKeyPair('EdDSA');
		const jwk = await exportJWK(publicKey);
		return JWT.sign({ data: true }, privateKey, 'EdDSA')
			.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
			.then((decoded) => {
				expect(decoded.header).toHaveProperty('alg', 'EdDSA');
				expect(decoded.payload).toMatchObject({ data: true });
			});
	});

	it('signs and validates with Ed25519', async () => {
		const { privateKey, publicKey } = await generateKeyPair('Ed25519');
		const jwk = await exportJWK(publicKey);
		return JWT.sign({ data: true }, privateKey, 'Ed25519')
			.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
			.then((decoded) => {
				expect(decoded.header).toHaveProperty('alg', 'Ed25519');
				expect(decoded.payload).toMatchObject({ data: true });
			});
	});

	describe('sign options', () => {
		it('a signed token carries iat without the caller asking', async () =>
			JWT.sign(
				{ data: true },
				await generateSecret('HS256', { extractable: true }),
				'HS256'
			)
				.then((jwt) => JWT.decode(jwt))
				.then((decoded) => {
					expect(decoded.payload).toHaveProperty('iat');
				}));

		it('a requested lifetime becomes an exp claim', async () =>
			JWT.sign(
				{ data: true },
				await generateSecret('HS256', { extractable: true }),
				'HS256',
				{ expiresIn: 60 }
			)
				.then((jwt) => JWT.decode(jwt))
				.then(({ payload: { iat, exp } }) => {
					if (iat === undefined) throw new Error('expected an iat claim');
					expect(exp).toBe(iat + 60);
				}));

		it('a signed token carries the audience it was issued for', async () =>
			JWT.sign(
				{ data: true },
				await generateSecret('HS256', { extractable: true }),
				'HS256',
				{ audience: 'clientId' }
			)
				.then((jwt) => JWT.decode(jwt))
				.then((decoded) => {
					expect(decoded.payload).toHaveProperty('aud', 'clientId');
				}));

		it('a signed token names this server as issuer', async () =>
			JWT.sign(
				{ data: true },
				await generateSecret('HS256', { extractable: true }),
				'HS256',
				{ issuer: 'http://example.com/issuer' }
			)
				.then((jwt) => JWT.decode(jwt))
				.then((decoded) => {
					expect(decoded.payload).toHaveProperty(
						'iss',
						'http://example.com/issuer'
					);
				}));

		it('a signed token carries the subject it was issued for', async () =>
			JWT.sign(
				{ data: true },
				await generateSecret('HS256', { extractable: true }),
				'HS256',
				{ subject: 'http://example.com/subject' }
			)
				.then((jwt) => JWT.decode(jwt))
				.then((decoded) => {
					expect(decoded.payload).toHaveProperty(
						'sub',
						'http://example.com/subject'
					);
				}));
	});

	describe('verify', () => {
		it('a requested not-before becomes an nbf claim', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign(
				{ data: true, nbf: epochTime() + 3600 },
				keyobject,
				'HS256'
			)
				.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
				.then(
					(valid) => {
						expect(valid).not.toBeTruthy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err).toBeInstanceOf(Error);
						expect(err).toHaveProperty('message', 'jwt not active yet');
					}
				);
		});

		it('nbf accepted within set clock tolerance', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign(
				{ data: true, nbf: epochTime() + 5 },
				keyobject,
				'HS256'
			).then((jwt) =>
				JWT.verify(jwt, new KeyStore([jwk]), {
					clockTolerance: 10
				})
			);
		});

		it('a token presented before its nbf is refused', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign({ data: true, nbf: 'not a nbf' }, keyobject, 'HS256')
				.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
				.then(
					(valid) => {
						expect(valid).not.toBeTruthy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err).toBeInstanceOf(Error);
						expect(err).toHaveProperty(
							'message',
							'invalid jwt payload: /nbf Expected integer'
						);
					}
				);
		});

		it('a caller-supplied iat is carried through', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign(
				{ data: true, iat: epochTime() + 3600 },
				keyobject,
				'HS256'
			)
				.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
				.then(
					(valid) => {
						expect(valid).not.toBeTruthy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err).toBeInstanceOf(Error);
						expect(err).toHaveProperty('message', 'jwt issued in the future');
					}
				);
		});

		it('iat accepted within set clock tolerance', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign(
				{ data: true, iat: epochTime() + 5 },
				keyobject,
				'HS256'
			).then((jwt) =>
				JWT.verify(jwt, new KeyStore([jwk]), {
					clockTolerance: 10
				})
			);
		});

		it('a token issued in the future is refused', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign({ data: true, iat: 'not an iat' }, keyobject, 'HS256')
				.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
				.then(
					(valid) => {
						expect(valid).not.toBeTruthy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err).toBeInstanceOf(Error);
						expect(err).toHaveProperty(
							'message',
							'invalid jwt payload: /iat Expected integer'
						);
					}
				);
		});

		it('a signed token carries exp', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign(
				{ data: true, exp: epochTime() - 3600 },
				keyobject,
				'HS256'
			)
				.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
				.then(
					(valid) => {
						expect(valid).not.toBeTruthy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err).toBeInstanceOf(Error);
						expect(err).toHaveProperty('message', 'jwt expired');
					}
				);
		});

		it('expiry is not checked only where the caller explicitly asks', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign(
				{ data: true, exp: epochTime() - 3600 },
				keyobject,
				'HS256'
			).then((jwt) =>
				JWT.verify(jwt, new KeyStore([jwk]), {
					ignoreExpiration: true
				})
			);
		});

		it('exp accepted within set clock tolerance', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign(
				{ data: true, exp: epochTime() - 5 },
				keyobject,
				'HS256'
			).then((jwt) =>
				JWT.verify(jwt, new KeyStore([jwk]), {
					clockTolerance: 10
				})
			);
		});

		it('an expired token is refused', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign({ data: true, exp: 'not an exp' }, keyobject, 'HS256')
				.then((jwt) => JWT.verify(jwt, new KeyStore([jwk])))
				.then(
					(valid) => {
						expect(valid).not.toBeTruthy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err).toBeInstanceOf(Error);
						expect(err).toHaveProperty(
							'message',
							'invalid jwt payload: /exp Expected integer'
						);
					}
				);
		});

		it('accepts a token whose single audience matches', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign({ data: true }, keyobject, 'HS256', {
				audience: 'client'
			}).then((jwt) =>
				JWT.verify(jwt, new KeyStore([jwk]), {
					audience: 'client'
				})
			);
		});

		it('accepts a token whose audience list contains the expected one', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign({ data: true }, keyobject, 'HS256', {
				audience: ['client', 'momma']
			}).then((jwt) =>
				JWT.verify(jwt, new KeyStore([jwk]), {
					audience: 'client'
				})
			);
		});

		it('a token for another audience is refused', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign({ data: true }, keyobject, 'HS256', {
				audience: 'client'
			})
				.then((jwt) =>
					JWT.verify(jwt, new KeyStore([jwk]), {
						audience: 'pappa'
					})
				)
				.then((valid) => {
					expect(valid).not.toBeTruthy();
				})
				.catch((err) => {
					expect(err).toBeTruthy();
					expect(err).toBeInstanceOf(Error);
					expect(err).toHaveProperty('message', 'jwt audience missing pappa');
				});
		});

		it('refuses a token whose audience list omits the expected one', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign({ data: true }, keyobject, 'HS256', {
				audience: ['client', 'momma']
			})
				.then((jwt) =>
					JWT.verify(jwt, new KeyStore([jwk]), {
						audience: 'pappa'
					})
				)
				.then((valid) => {
					expect(valid).not.toBeTruthy();
				})
				.catch((err) => {
					expect(err).toBeTruthy();
					expect(err).toBeInstanceOf(Error);
					expect(err).toHaveProperty('message', 'jwt audience missing pappa');
				});
		});

		it('a token from the expected issuer is accepted', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign({ data: true }, keyobject, 'HS256', {
				issuer: 'me'
			}).then((jwt) =>
				JWT.verify(jwt, new KeyStore([jwk]), {
					issuer: 'me'
				})
			);
		});

		it('a token from another issuer is refused', async () => {
			const keyobject = await generateSecret('HS256', { extractable: true });
			const jwk = await exportJWK(keyobject);
			return JWT.sign({ data: true }, keyobject, 'HS256', {
				issuer: 'me'
			})
				.then((jwt) =>
					JWT.verify(jwt, new KeyStore([jwk]), {
						issuer: 'you'
					})
				)
				.then((valid) => {
					expect(valid).not.toBeTruthy();
				})
				.catch((err) => {
					expect(err).toBeTruthy();
					expect(err).toBeInstanceOf(Error);
					expect(err).toHaveProperty('message');
					expect(err.message).toMatch(/jwt issuer invalid/);
				});
		});
	});
});

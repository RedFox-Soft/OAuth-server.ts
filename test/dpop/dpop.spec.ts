import * as url from 'node:url';
import { hash, randomBytes, randomUUID } from 'node:crypto';
import {
	describe,
	it,
	beforeAll,
	beforeEach,
	spyOn,
	afterEach,
	mock,
	expect
} from 'bun:test';

import sinon from 'sinon';
import {
	SignJWT,
	exportJWK,
	calculateJwkThumbprint,
	generateKeyPair
} from 'jose';

import nanoid from '../../lib/helpers/nanoid.ts';
import epochTime from '../../lib/helpers/epoch_time.ts';
import bootstrap, { agent } from '../test_helper.js';
import * as base64url from '../../lib/helpers/base64url.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { provider } from 'lib/provider.js';
import { ISSUER } from 'lib/configs/env.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';

function ath(accessToken) {
	return hash('sha256', accessToken, 'base64url');
}

async function DPoP(
	keypair,
	htu,
	htm,
	nonce = undefined,
	accessToken = undefined
) {
	return new SignJWT({
		htu,
		htm,
		nonce,
		ath: accessToken ? ath(accessToken) : undefined
	})
		.setProtectedHeader({
			alg: 'ES256',
			typ: 'dpop+jwt',
			jwk: await exportJWK(keypair.publicKey)
		})
		.setJti(nanoid())
		.setIssuedAt()
		.sign(keypair.privateKey);
}

describe('features.dPoP', () => {
	let setup = null;
	let cookie = null;
	let keypair = null;
	let jwk = null;
	let thumbprint = null;

	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
		cookie = await setup.login({ scope: 'openid offline_access' });
		keypair = await generateKeyPair('ES256', { extractable: true });
		jwk = await exportJWK(keypair.publicKey);
		thumbprint = await calculateJwkThumbprint(jwk);
	});

	beforeEach(function () {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(function () {
		mock.restore();
	});

	it('extends discovery', async function () {
		const { data, status } =
			await agent['.well-known']['openid-configuration'].get();

		expect(status).toBe(200);
		expect(data).toHaveProperty('dpop_signing_alg_values_supported', [
			'ES256',
			'PS256'
		]);
	});

	describe('userinfo', () => {
		it('validates the way DPoP proof JWT is provided', async function () {
			const at = new provider.AccessToken({
				accountId: 'account',
				client: await provider.Client.find('client'),
				scope: 'openid'
			});
			at.setThumbprint('jkt', thumbprint);

			expect(() => at.setThumbprint('x5t', 'foo')).toThrow(
				expect.objectContaining({
					error_description:
						'multiple proof-of-posession mechanisms are not allowed'
				})
			);

			const dpop = await at.save();

			const bearer = await agent.userinfo.get({
				headers: {
					authorization: `Bearer ${dpop}`
				}
			});
			expect(bearer.status).toBe(401);
			expect(bearer.error.value).toEqual({
				error: 'invalid_token',
				error_description: 'invalid token provided'
			});
			expect(bearer.headers.get('www-authenticate')).toMatch(/^Bearer /);
			expect(bearer.headers.get('www-authenticate')).toMatch(
				/error="invalid_token"/
			);

			const dpopEmpty = await agent.userinfo.get({
				headers: {
					authorization: `DPoP ${dpop}`
				}
			});
			expect(dpopEmpty.status).toBe(401);
			expect(dpopEmpty.error.value).toEqual({
				error: 'invalid_header_authorization',
				error_description: '`DPoP` header not provided'
			});
			expect(dpopEmpty.headers.get('www-authenticate')).toMatch(/^DPoP /);
			expect(dpopEmpty.headers.get('www-authenticate')).toMatch(
				/algs="ES256 PS256"/
			);

			const dpopKey = await DPoP(
				keypair,
				`${ISSUER}/userinfo`,
				'POST',
				undefined,
				dpop
			);
			const dpopRes = await agent.userinfo.get({
				headers: {
					dpop: `DPoP ${dpopKey}`,
					authorization: `Bearer ${dpop}`
				}
			});
			expect(dpopRes.status).toBe(401);
			expect(dpopRes.error.value).toEqual({
				error: 'invalid_header_authorization',
				error_description:
					'authorization header scheme must be `DPoP` when DPoP is used'
			});
			expect(dpopRes.headers.get('www-authenticate')).toMatch(/^DPoP /);
			expect(dpopRes.headers.get('www-authenticate')).toMatch(
				/algs="ES256 PS256"/
			);
		});

		describe('validates the DPoP proof JWT is conform', () => {
			before(async function () {
				const at = new provider.AccessToken({
					accountId: this.loggedInAccountId,
					grantId: this.getGrantId(),
					client: await provider.Client.find('client'),
					scope: 'openid'
				});
				at.setThumbprint('jkt', this.thumbprint);

				this.access_token = await at.save();
				this.ath = hash('sha256', this.access_token, 'base64url');
			});

			afterEach(function () {
				provider.removeAllListeners('userinfo.error');
			});

			it('invalid typ', async function () {
				const spy = sinon.spy();
				provider.on('userinfo.error', spy);

				for (const value of ['JWT', 'secevent+jwt']) {
					await this.agent
						.get('/me')
						.set(
							'DPoP',
							await new SignJWT({})
								.setProtectedHeader({
									alg: 'ES256',
									jwk: this.jwk,
									typ: value
								})
								.sign(this.keypair.privateKey)
						)
						.set('Authorization', `DPoP ${this.access_token}`)
						.expect(401)
						.expect({
							error: 'invalid_dpop_proof',
							error_description: 'invalid DPoP key binding'
						})
						.expect('WWW-Authenticate', /^DPoP /)
						.expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
						.expect('WWW-Authenticate', /algs="ES256 PS256"/);
				}

				for (const {
					args: [, err]
				} of spy.getCalls()) {
					expect(err.error_detail).to.eql('unexpected "typ" JWT header value');
				}
			});

			it('alg mismatch', async function () {
				const spy = sinon.spy();
				provider.on('userinfo.error', spy);
				for (const value of [1, true, 'none', 'HS256', 'unsupported']) {
					await this.agent
						.get('/me')
						.set(
							'DPoP',
							`${base64url.encode(JSON.stringify({ jwk: this.jwk, typ: 'dpop+jwt', alg: value }))}.e30.`
						)
						.set('Authorization', `DPoP ${this.access_token}`)
						.expect(401)
						.expect({
							error: 'invalid_dpop_proof',
							error_description: 'invalid DPoP key binding'
						})
						.expect('WWW-Authenticate', /^DPoP /)
						.expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
						.expect('WWW-Authenticate', /algs="ES256 PS256"/);
				}

				for (const {
					args: [, err]
				} of spy.getCalls()) {
					expect(err.error_detail).to.be.oneOf([
						'"alg" (Algorithm) Header Parameter value not allowed',
						'JWS "alg" (Algorithm) Header Parameter missing or invalid'
					]);
				}
			});

			it('embedded jwk header', async function () {
				const spy = sinon.spy();
				provider.on('userinfo.error', spy);
				for (const value of [undefined, '', 1, true, null, 'foo', []]) {
					await this.agent
						.get('/me')
						.set(
							'DPoP',
							await new SignJWT({})
								.setProtectedHeader({
									alg: 'ES256',
									jwk: value,
									typ: 'dpop+jwt'
								})
								.sign(this.keypair.privateKey)
						)
						.set('Authorization', `DPoP ${this.access_token}`)
						.expect(401)
						.expect({
							error: 'invalid_dpop_proof',
							error_description: 'invalid DPoP key binding'
						})
						.expect('WWW-Authenticate', /^DPoP /)
						.expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
						.expect('WWW-Authenticate', /algs="ES256 PS256"/);
				}

				for (const {
					args: [, err]
				} of spy.getCalls()) {
					expect(err.error_detail).to.eql(
						'"jwk" (JSON Web Key) Header Parameter must be a JSON object'
					);
				}
			});

			it('no private key in header', async function () {
				const spy = sinon.spy();
				provider.on('userinfo.error', spy);
				await this.agent
					.get('/me')
					.set(
						'DPoP',
						await new SignJWT({})
							.setProtectedHeader({
								alg: 'ES256',
								jwk: await exportJWK(this.keypair.privateKey),
								typ: 'dpop+jwt'
							})
							.sign(this.keypair.privateKey)
					)
					.set('Authorization', `DPoP ${this.access_token}`)
					.expect(401)
					.expect({
						error: 'invalid_dpop_proof',
						error_description: 'invalid DPoP key binding'
					})
					.expect('WWW-Authenticate', /^DPoP /)
					.expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
					.expect('WWW-Authenticate', /algs="ES256 PS256"/);

				for (const {
					args: [, err]
				} of spy.getCalls()) {
					expect(err.error_detail).to.eql(
						'"jwk" (JSON Web Key) Header Parameter must be a public key'
					);
				}
			});

			it('no symmetric key in header', async function () {
				const spy = sinon.spy();
				provider.on('userinfo.error', spy);
				await this.agent
					.get('/me')
					.set(
						'DPoP',
						await new SignJWT({})
							.setProtectedHeader({
								alg: 'ES256',
								jwk: await exportJWK(randomBytes(32)),
								typ: 'dpop+jwt'
							})
							.sign(this.keypair.privateKey)
					)
					.set('Authorization', `DPoP ${this.access_token}`)
					.expect(401)
					.expect({
						error: 'invalid_dpop_proof',
						error_description: 'invalid DPoP key binding'
					})
					.expect('WWW-Authenticate', /^DPoP /)
					.expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
					.expect('WWW-Authenticate', /algs="ES256 PS256"/);

				for (const {
					args: [, err]
				} of spy.getCalls()) {
					expect(err.error_detail).to.eql(
						'"jwk" (JSON Web Key) Header Parameter must be a public key'
					);
				}
			});

			it('missing jti', async function () {
				await this.agent
					.get('/me')
					.set(
						'DPoP',
						await new SignJWT({
							htm: 'POST',
							htu: `${ISSUER}${this.suitePath('/me')}`
						})
							.setProtectedHeader({
								alg: 'ES256',
								typ: 'dpop+jwt',
								jwk: this.jwk
							})
							.setIssuedAt()
							.sign(this.keypair.privateKey)
					)
					.set('Authorization', `DPoP ${this.access_token}`)
					.expect(401)
					.expect({
						error: 'invalid_dpop_proof',
						error_description: 'DPoP proof must have a jti string property'
					})
					.expect('WWW-Authenticate', /^DPoP /)
					.expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
					.expect('WWW-Authenticate', /algs="ES256 PS256"/);
			});

			it('htm mismatch', async function () {
				await this.agent
					.get('/me')
					.set(
						'DPoP',
						await new SignJWT({
							htm: 'POST',
							htu: `${ISSUER}${this.suitePath('/me')}`,
							ath: this.ath
						})
							.setProtectedHeader({
								alg: 'ES256',
								typ: 'dpop+jwt',
								jwk: this.jwk
							})
							.setIssuedAt()
							.setJti(randomUUID())
							.sign(this.keypair.privateKey)
					)
					.set('Authorization', `DPoP ${this.access_token}`)
					.expect(401)
					.expect({
						error: 'invalid_dpop_proof',
						error_description: 'DPoP proof htm mismatch'
					})
					.expect('WWW-Authenticate', /^DPoP /)
					.expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
					.expect('WWW-Authenticate', /algs="ES256 PS256"/);
			});

			it('htu mismatch', async function () {
				await this.agent
					.get('/me')
					.set(
						'DPoP',
						await new SignJWT({
							htm: 'GET',
							htu: `${ISSUER}${this.suitePath('/token')}`,
							ath: this.ath
						})
							.setProtectedHeader({
								alg: 'ES256',
								typ: 'dpop+jwt',
								jwk: this.jwk
							})
							.setIssuedAt()
							.setJti(randomUUID())
							.sign(this.keypair.privateKey)
					)
					.set('Authorization', `DPoP ${this.access_token}`)
					.expect(401)
					.expect({
						error: 'invalid_dpop_proof',
						error_description: 'DPoP proof htu mismatch'
					})
					.expect('WWW-Authenticate', /^DPoP /)
					.expect('WWW-Authenticate', /error="invalid_dpop_proof"/)
					.expect('WWW-Authenticate', /algs="ES256 PS256"/);
			});

			for (const enabled of [true, false]) {
				describe(`with DPoP-Nonces ${enabled ? 'enabled' : 'disabled'}`, () => {
					before(function () {
						({ DPoPNonces: this.DPoPNonces } = i(provider));
						if (enabled) {
							i(provider).DPoPNonces = this.DPoPNonces;
						} else {
							i(provider).DPoPNonces = undefined;
						}
					});

					after(function () {
						i(provider).DPoPNonces = this.DPoPNonces;
					});

					for (const offset of [301, -301]) {
						it(`iat too ${offset > 0 ? 'far in the future' : 'old'}`, async function () {
							await this.agent
								.get('/me')
								.set(
									'DPoP',
									await new SignJWT({
										htm: 'GET',
										htu: `${ISSUER}${this.suitePath('/me')}`,
										ath: this.ath
									})
										.setProtectedHeader({
											alg: 'ES256',
											typ: 'dpop+jwt',
											jwk: this.jwk
										})
										.setIssuedAt(epochTime() - 301)
										.setJti(randomUUID())
										.sign(this.keypair.privateKey)
								)
								.set('Authorization', `DPoP ${this.access_token}`)
								.expect(401)
								.expect('WWW-Authenticate', /^DPoP /)
								.expect('WWW-Authenticate', /algs="ES256 PS256"/)
								.expect(
									'WWW-Authenticate',
									/DPoP proof iat is not recent enough/
								)
								.expect(({ headers }) => {
									if (enabled) {
										expect(headers)
											.to.have.property('dpop-nonce')
											.that.matches(/^[\w-]{43}$/);
										expect(headers)
											.to.have.property('www-authenticate')
											.that.matches(/error="use_dpop_nonce"/);
										expect(headers)
											.to.have.property('www-authenticate')
											.that.matches(/use a DPoP nonce instead/);
									} else {
										expect(headers).not.to.have.property('dpop-nonce');
										expect(headers)
											.to.have.property('www-authenticate')
											.that.matches(/error="invalid_dpop_proof"/);
									}
								});
						});
					}
				});
			}
		});

		it('acts like an RS checking the DPoP proof and thumbprint now', async function () {
			const at = new provider.AccessToken({
				accountId: this.loggedInAccountId,
				grantId: this.getGrantId(),
				client: await provider.Client.find('client'),
				scope: 'openid'
			});
			at.setThumbprint('jkt', this.thumbprint);

			const dpop = await at.save();
			const proof = await DPoP(
				this.keypair,
				`${ISSUER}${this.suitePath('/me')}`,
				'GET',
				undefined,
				dpop
			);

			await this.agent
				.get('/me')
				.set('Authorization', `DPoP ${dpop}`)
				.set('DPoP', proof)
				.expect(200);

			let spy = sinon.spy();
			provider.once('userinfo.error', spy);

			await this.agent
				.get('/me')
				.set('Authorization', `DPoP ${dpop}`)
				.set('DPoP', proof)
				.expect(401)
				.expect({
					error: 'invalid_token',
					error_description: 'invalid token provided'
				});

			expect(spy).to.have.property('calledOnce', true);
			expect(spy.args[0][1]).to.have.property(
				'error_detail',
				'DPoP proof JWT Replay detected'
			);

			spy = sinon.spy();
			provider.once('userinfo.error', spy);

			await this.agent
				.get('/me')
				.set('Authorization', `DPoP ${dpop}`)
				.set(
					'DPoP',
					await DPoP(
						await generateKeyPair('ES256', { extractable: true }),
						`${ISSUER}${this.suitePath('/me')}`,
						'GET',
						undefined,
						dpop
					)
				)
				.expect({
					error: 'invalid_token',
					error_description: 'invalid token provided'
				})
				.expect(401);

			await this.agent
				.get('/me')
				.set('Authorization', `DPoP ${dpop}`)
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/me')}`,
						'GET',
						undefined,
						'anotherAccessTokenValue'
					)
				)
				.expect({
					error: 'invalid_dpop_proof',
					error_description: 'DPoP proof ath mismatch'
				})
				.expect(401);

			expect(spy).to.have.property('calledOnce', true);
			expect(spy.args[0][1]).to.have.property(
				'error_detail',
				'failed jkt verification'
			);

			spy = sinon.spy();
			provider.once('userinfo.error', spy);

			await this.agent
				.get('/me')
				.set('Authorization', `Bearer ${dpop}`)
				.expect({
					error: 'invalid_token',
					error_description: 'invalid token provided'
				})
				.expect(401);

			expect(spy).to.have.property('calledOnce', true);
			expect(spy.args[0][1]).to.have.property(
				'error_detail',
				'failed jkt verification'
			);
		});
	});

	describe('introspection', () => {
		it('exposes cnf and DPoP proof JWT type now', async function () {
			const at = new provider.AccessToken({
				accountId: 'account',
				client: await provider.Client.find('client'),
				scope: 'openid'
			});
			at.setThumbprint('jkt', thumbprint);

			const token = await at.save();

			const { data, status } = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toHaveProperty('active', true);
			expect(data).toHaveProperty('token_type', 'DPoP');
			expect(data).toHaveProperty('cnf');
			expect(data.cnf).toHaveProperty('jkt', thumbprint);
		});
	});

	describe('urn:ietf:params:oauth:grant-type:device_code', () => {
		beforeEach(async function () {
			await this.agent
				.post('/device/auth')
				.auth('client', 'secret')
				.send({ scope: 'openid' })
				.type('form')
				.expect(200)
				.expect(({ body: { device_code: dc } }) => {
					this.dc = dc;
				});

			TestAdapter.for('DeviceCode').syncUpdate(this.getTokenJti(this.dc), {
				scope: 'openid offline_access',
				accountId: this.loggedInAccountId,
				grantId: this.getGrantId()
			});
		});

		it('binds the access token to the jwk', async function () {
			const spy = sinon.spy();
			provider.once('grant.success', spy);

			await this.agent
				.post('/token')
				.auth('client', 'secret')
				.send({
					grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
					device_code: this.dc
				})
				.type('form')
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/token')}`,
						'POST'
					)
				)
				.expect(200);

			expect(spy).to.have.property('calledOnce', true);
			const {
				oidc: {
					entities: { AccessToken, RefreshToken }
				}
			} = spy.args[0][0];
			expect(AccessToken).to.have.property('jkt', this.thumbprint);
			expect(RefreshToken).not.to.have.property('jkt');
		});

		it('binds the refresh token to the jwk for public clients', async function () {
			const spy = sinon.spy();
			provider.once('grant.success', spy);

			// changes the code to client-none
			TestAdapter.for('DeviceCode').syncUpdate(this.getTokenJti(this.dc), {
				clientId: 'client-none',
				accountId: this.loggedInAccountId,
				grantId: this.getGrantId('client-none')
			});

			await this.agent
				.post('/token')
				.send({
					client_id: 'client-none',
					grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
					device_code: this.dc
				})
				.type('form')
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/token')}`,
						'POST'
					)
				)
				.expect(200);

			expect(spy).to.have.property('calledOnce', true);
			const {
				oidc: {
					entities: { AccessToken, RefreshToken }
				}
			} = spy.args[0][0];
			expect(AccessToken).to.have.property('jkt', this.thumbprint);
			expect(RefreshToken).to.have.property('jkt', this.thumbprint);
		});
	});

	describe('urn:openid:params:grant-type:ciba', () => {
		beforeEach(async function () {
			await this.agent
				.post('/backchannel')
				.auth('client', 'secret')
				.send({
					scope: 'openid offline_access',
					login_hint: 'accountId'
				})
				.type('form')
				.expect(200)
				.expect(({ body: { auth_req_id: reqId } }) => {
					this.reqId = reqId;
				});
		});

		it('binds the access token to the jwk', async function () {
			const spy = sinon.spy();
			provider.once('grant.success', spy);

			await this.agent
				.post('/token')
				.auth('client', 'secret')
				.send({
					grant_type: 'urn:openid:params:grant-type:ciba',
					auth_req_id: this.reqId
				})
				.type('form')
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/token')}`,
						'POST'
					)
				)
				.expect(200);

			expect(spy).to.have.property('calledOnce', true);
			const {
				oidc: {
					entities: { AccessToken, RefreshToken }
				}
			} = spy.args[0][0];
			expect(AccessToken).to.have.property('jkt', this.thumbprint);
			expect(RefreshToken).not.to.have.property('jkt');
		});

		it('binds the refresh token to the jwk for public clients', async function () {
			const spy = sinon.spy();
			provider.once('grant.success', spy);

			// changes the code to client-none
			TestAdapter.for('BackchannelAuthenticationRequest').syncUpdate(
				this.getTokenJti(this.reqId),
				{
					clientId: 'client-none'
				}
			);
			const { grantId } = TestAdapter.for(
				'BackchannelAuthenticationRequest'
			).syncFind(this.getTokenJti(this.reqId));
			TestAdapter.for('Grant').syncUpdate(grantId, {
				clientId: 'client-none'
			});

			await this.agent
				.post('/token')
				.send({
					client_id: 'client-none',
					grant_type: 'urn:openid:params:grant-type:ciba',
					auth_req_id: this.reqId
				})
				.type('form')
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/token')}`,
						'POST'
					)
				)
				.expect(200);

			expect(spy).to.have.property('calledOnce', true);
			const {
				oidc: {
					entities: { AccessToken, RefreshToken }
				}
			} = spy.args[0][0];
			expect(AccessToken).to.have.property('jkt', this.thumbprint);
			expect(RefreshToken).to.have.property('jkt', this.thumbprint);
		});
	});

	describe('pushed authorization request', () => {
		it('checks dpop_jkt equals the jwk thumbprint when both are present', async function () {
			const code_verifier = randomBytes(32).toString('base64url');

			await this.agent
				.post('/request')
				.auth('client', 'secret')
				.send({
					response_type: 'code',
					client_id: 'client',
					dpop_jkt: thumbprint,
					code_challenge_method: 'S256',
					code_challenge: hash('sha256', code_verifier, 'base64url')
				})
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/request')}`,
						'POST'
					)
				)
				.type('form')
				.expect(201);

			await this.agent
				.post('/request')
				.auth('client', 'secret')
				.send({
					response_type: 'code',
					client_id: 'client',
					dpop_jkt: 'cbaZgHZazjgQq0Q2-Hy_o2-OCDpPu02S30lNhTsNU1Q',
					code_challenge_method: 'S256',
					code_challenge: hash('sha256', code_verifier, 'base64url')
				})
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/request')}`,
						'POST'
					)
				)
				.type('form')
				.expect(400)
				.expect({
					error: 'invalid_request',
					error_description: 'DPoP proof key thumbprint does not match dpop_jkt'
				});
		});

		it('sets the request dpop_jkt automatically when missing (no request object used)', async function () {
			const code_verifier = randomBytes(32).toString('base64url');

			let request_uri;
			await this.agent
				.post('/request')
				.auth('client', 'secret')
				.send({
					scope: 'openid',
					response_type: 'code',
					client_id: 'client',
					code_challenge_method: 'S256',
					code_challenge: hash('sha256', code_verifier, 'base64url')
				})
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/request')}`,
						'POST'
					)
				)
				.type('form')
				.expect(201)
				.expect(({ body }) => {
					({ request_uri } = body);
				});

			const auth = new AuthorizationRequest({ request_uri });

			let code;
			await this.wrap({ route: '/auth', verb: 'get', auth })
				.expect(303)
				.expect(auth.validateClientLocation)
				.expect(({ headers: { location } }) => {
					({
						query: { code }
					} = url.parse(location, true));
				});

			const { dpopJkt } = TestAdapter.for('AuthorizationCode').syncFind(code);
			expect(dpopJkt).to.be.a('string').of.length(43);
		});

		it('sets the request dpop_jkt automatically when missing (request object used)', async function () {
			const code_verifier = randomBytes(32).toString('base64url');

			let request_uri;
			await this.agent
				.post('/request')
				.auth('client', 'secret')
				.send({
					client_id: 'client',
					request: await new SignJWT({
						client_id: 'client',
						scope: 'openid',
						response_type: 'code',
						iss: 'client',
						aud: ISSUER,
						code_challenge_method: 'S256',
						code_challenge: hash('sha256', code_verifier, 'base64url')
					})
						.setProtectedHeader({ alg: 'HS256' })
						.setIssuedAt()
						.setIssuer('client')
						.setAudience(ISSUER)
						.setExpirationTime('1m')
						.setNotBefore('0s')
						.sign(Buffer.from('secret'))
				})
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/request')}`,
						'POST'
					)
				)
				.type('form')
				.expect(201)
				.expect(({ body }) => {
					({ request_uri } = body);
				});

			const auth = new AuthorizationRequest({ request_uri });

			let code;
			await this.wrap({ route: '/auth', verb: 'get', auth })
				.expect(303)
				.expect(auth.validateClientLocation)
				.expect(({ headers: { location } }) => {
					({
						query: { code }
					} = url.parse(location, true));
				});

			const { dpopJkt } = TestAdapter.for('AuthorizationCode').syncFind(code);
			expect(dpopJkt).to.be.a('string').of.length(43);
		});
	});

	describe('authorization flow', () => {
		describe('without dpop_jkt', () => {
			beforeEach(async function () {
				const auth = (this.auth = new AuthorizationRequest({
					scope: 'openid offline_access',
					prompt: 'consent'
				}));

				await this.wrap({ route: '/auth', verb: 'get', auth })
					.expect(303)
					.expect(auth.validateClientLocation)
					.expect(({ headers: { location } }) => {
						const {
							query: { code }
						} = url.parse(location, true);
						this.code = code;
					});
			});

			describe('authorization_code', () => {
				it('binds the access token to the jwk', async function () {
					const spy = sinon.spy();
					provider.once('grant.success', spy);

					await this.agent
						.post('/token')
						.auth('client', 'secret')
						.send({
							grant_type: 'authorization_code',
							code_verifier: this.auth.code_verifier,
							code: this.code,
							redirect_uri: 'https://client.example.com/cb'
						})
						.type('form')
						.set(
							'DPoP',
							await DPoP(
								this.keypair,
								`${ISSUER}${this.suitePath('/token')}`,
								'POST'
							)
						)
						.expect(200);

					expect(spy).to.have.property('calledOnce', true);
					const {
						oidc: {
							entities: { AccessToken, RefreshToken }
						}
					} = spy.args[0][0];
					expect(AccessToken).to.have.property('jkt', this.thumbprint);
					expect(RefreshToken).not.to.have.property('jkt');
				});
			});
		});

		describe('with dpop_jkt', () => {
			beforeEach(async function () {
				const auth = (this.auth = new AuthorizationRequest({
					scope: 'openid offline_access',
					prompt: 'consent',
					dpop_jkt: this.thumbprint
				}));

				await this.wrap({ route: '/auth', verb: 'get', auth })
					.expect(303)
					.expect(auth.validateClientLocation)
					.expect(({ headers: { location } }) => {
						const {
							query: { code }
						} = url.parse(location, true);
						this.code = code;
					});
			});

			describe('authorization_code', () => {
				it('binds the access token to the jwk', async function () {
					const spy = sinon.spy();
					provider.once('grant.success', spy);

					await this.agent
						.post('/token')
						.auth('client', 'secret')
						.send({
							grant_type: 'authorization_code',
							code_verifier: this.auth.code_verifier,
							code: this.code,
							redirect_uri: 'https://client.example.com/cb'
						})
						.type('form')
						.set(
							'DPoP',
							await DPoP(
								this.keypair,
								`${ISSUER}${this.suitePath('/token')}`,
								'POST'
							)
						)
						.expect(200);

					expect(spy).to.have.property('calledOnce', true);
					const {
						oidc: {
							entities: { AccessToken, RefreshToken }
						}
					} = spy.args[0][0];
					expect(AccessToken).to.have.property('jkt', this.thumbprint);
					expect(RefreshToken).not.to.have.property('jkt');
				});

				it('checks the dpop_jkt matches the proof jwk thumbprint', async function () {
					const spy = sinon.spy();
					provider.once('grant.error', spy);

					await this.agent
						.post('/token')
						.auth('client', 'secret')
						.send({
							grant_type: 'authorization_code',
							code_verifier: this.auth.code_verifier,
							code: this.code,
							redirect_uri: 'https://client.example.com/cb'
						})
						.type('form')
						.set(
							'DPoP',
							await DPoP(
								await generateKeyPair('ES256', { extractable: true }),
								`${ISSUER}${this.suitePath('/token')}`,
								'POST'
							)
						)
						.expect(400)
						.expect({
							error: 'invalid_grant',
							error_description: 'grant request is invalid'
						});

					expect(spy).to.have.property('calledOnce', true);
					expect(spy.args[0][1]).to.have.property(
						'error_detail',
						'DPoP proof key thumbprint does not match dpop_jkt'
					);
				});

				it('requires dpop to be used when dpop_jkt was present', async function () {
					const spy = sinon.spy();
					provider.once('grant.error', spy);

					await this.agent
						.post('/token')
						.auth('client', 'secret')
						.send({
							grant_type: 'authorization_code',
							code_verifier: this.auth.code_verifier,
							code: this.code,
							redirect_uri: 'https://client.example.com/cb'
						})
						.type('form')
						.expect(400)
						.expect({
							error: 'invalid_grant',
							error_description: 'grant request is invalid'
						});

					expect(spy).to.have.property('calledOnce', true);
					expect(spy.args[0][1]).to.have.property(
						'error_detail',
						'missing DPoP proof JWT'
					);
				});
			});
		});

		describe('refresh_token', () => {
			beforeEach(async function () {
				const auth = (this.auth = new AuthorizationRequest({
					scope: 'openid offline_access',
					prompt: 'consent'
				}));

				await this.wrap({ route: '/auth', verb: 'get', auth })
					.expect(303)
					.expect(auth.validateClientLocation)
					.expect(({ headers: { location } }) => {
						const {
							query: { code }
						} = url.parse(location, true);
						this.code = code;
					});

				await this.agent
					.post('/token')
					.auth('client', 'secret')
					.send({
						grant_type: 'authorization_code',
						code_verifier: this.auth.code_verifier,
						code: this.code,
						redirect_uri: 'https://client.example.com/cb'
					})
					.type('form')
					.set(
						'DPoP',
						await DPoP(
							this.keypair,
							`${ISSUER}${this.suitePath('/token')}`,
							'POST'
						)
					)
					.expect(({ body }) => {
						this.rt = body.refresh_token;
					});
			});

			it('binds the access token to the jwk', async function () {
				const spy = sinon.spy();
				provider.once('grant.success', spy);

				await this.agent
					.post('/token')
					.auth('client', 'secret')
					.send({
						grant_type: 'refresh_token',
						refresh_token: this.rt
					})
					.type('form')
					.set(
						'DPoP',
						await DPoP(
							this.keypair,
							`${ISSUER}${this.suitePath('/token')}`,
							'POST'
						)
					)
					.expect(200);

				expect(spy).to.have.property('calledOnce', true);
				const {
					oidc: {
						entities: { AccessToken, RefreshToken }
					}
				} = spy.args[0][0];
				expect(AccessToken).to.have.property('jkt', this.thumbprint);
				expect(RefreshToken.jkt).to.be.undefined;
			});
		});
	});

	describe('authorization flow (public client)', () => {
		beforeEach(async function () {
			const auth = (this.auth = new AuthorizationRequest({
				client_id: 'client-none',
				scope: 'openid offline_access',
				prompt: 'consent'
			}));

			await this.wrap({ route: '/auth', verb: 'get', auth })
				.expect(303)
				.expect(auth.validateClientLocation)
				.expect(({ headers: { location } }) => {
					const {
						query: { code }
					} = url.parse(location, true);
					this.code = code;
				});
		});

		describe('authorization_code', () => {
			it('binds the access token to the jwk', async function () {
				const spy = sinon.spy();
				provider.once('grant.success', spy);

				await this.agent
					.post('/token')
					.send({
						client_id: 'client-none',
						grant_type: 'authorization_code',
						code_verifier: this.auth.code_verifier,
						code: this.code,
						redirect_uri: 'https://client.example.com/cb'
					})
					.type('form')
					.set(
						'DPoP',
						await DPoP(
							this.keypair,
							`${ISSUER}${this.suitePath('/token')}`,
							'POST'
						)
					)
					.expect(200);

				expect(spy).to.have.property('calledOnce', true);
				const {
					oidc: {
						entities: { AccessToken, RefreshToken }
					}
				} = spy.args[0][0];
				expect(AccessToken).to.have.property('jkt', this.thumbprint);
				expect(RefreshToken).to.have.property('jkt', this.thumbprint);
			});
		});

		describe('refresh_token', () => {
			beforeEach(async function () {
				await this.agent
					.post('/token')
					.send({
						client_id: 'client-none',
						grant_type: 'authorization_code',
						code_verifier: this.auth.code_verifier,
						code: this.code,
						redirect_uri: 'https://client.example.com/cb'
					})
					.type('form')
					.set(
						'DPoP',
						await DPoP(
							this.keypair,
							`${ISSUER}${this.suitePath('/token')}`,
							'POST'
						)
					)
					.expect(({ body }) => {
						this.rt = body.refresh_token;
					});
			});

			it('binds the access token to the jwk', async function () {
				const spy = sinon.spy();
				provider.once('grant.success', spy);

				await this.agent
					.post('/token')
					.send({
						client_id: 'client-none',
						grant_type: 'refresh_token',
						refresh_token: this.rt
					})
					.type('form')
					.set(
						'DPoP',
						await DPoP(
							this.keypair,
							`${ISSUER}${this.suitePath('/token')}`,
							'POST'
						)
					)
					.expect(200);

				expect(spy).to.have.property('calledOnce', true);
				const {
					oidc: {
						entities: { AccessToken, RefreshToken }
					}
				} = spy.args[0][0];
				expect(AccessToken).to.have.property('jkt', this.thumbprint);
				expect(RefreshToken).to.have.property('jkt', this.thumbprint);
			});

			it('verifies the request made with the same cert jwk', async function () {
				const spy = sinon.spy();
				provider.once('grant.error', spy);

				await this.agent
					.post('/token')
					.send({
						client_id: 'client-none',
						grant_type: 'refresh_token',
						refresh_token: this.rt
					})
					.set(
						'DPoP',
						await DPoP(
							await generateKeyPair('ES256', { extractable: true }),
							`${ISSUER}${this.suitePath('/token')}`,
							'POST'
						)
					)
					.type('form')
					.expect(400)
					.expect({
						error: 'invalid_grant',
						error_description: 'grant request is invalid'
					});

				expect(spy).to.have.property('calledOnce', true);
				expect(spy.args[0][1]).to.have.property(
					'error_detail',
					'failed jkt verification'
				);
			});
		});
	});

	describe('client_credentials', () => {
		it('binds the access token to the jwk', async function () {
			const spy = sinon.spy();
			provider.once('grant.success', spy);

			await this.agent
				.post('/token')
				.auth('client', 'secret')
				.send({ grant_type: 'client_credentials' })
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/token')}`,
						'POST'
					)
				)
				.type('form')
				.expect(200);

			expect(spy).to.have.property('calledOnce', true);
			const {
				oidc: {
					entities: { ClientCredentials }
				}
			} = spy.args[0][0];
			expect(ClientCredentials).to.have.property('jkt', this.thumbprint);
		});
	});

	describe('status codes at the token endpoint', () => {
		it('should be 400 for invalid_dpop_proof', async function () {
			await this.agent
				.post('/token')
				.auth('client', 'secret')
				.send({ grant_type: 'client_credentials' })
				.set('DPoP', 'invalid')
				.type('form')
				.expect(400)
				.expect({
					error: 'invalid_dpop_proof',
					error_description: 'invalid DPoP key binding'
				});
		});
	});

	describe('invalid nonce', () => {
		it('@ userinfo', async function () {
			let nonce;
			await this.agent
				.get('/me')
				.set('Authorization', 'DPoP foo')
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/me')}`,
						'GET',
						'foo',
						'foo'
					)
				)
				.expect(401)
				.expect({
					error: 'use_dpop_nonce',
					error_description: 'invalid nonce in DPoP proof'
				})
				.expect(({ headers }) => {
					nonce = headers['dpop-nonce'];
				});

			await this.agent
				.get('/me')
				.set('Authorization', 'DPoP foo')
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/me')}`,
						'GET',
						nonce,
						'foo'
					)
				)
				.expect(401)
				.expect({
					error: 'invalid_token',
					error_description: 'invalid token provided'
				});
		});

		it('@ token endpoint', async function () {
			let nonce;
			await this.agent
				.post('/token')
				.auth('client', 'secret')
				.send({ grant_type: 'client_credentials' })
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/token')}`,
						'POST',
						'foo'
					)
				)
				.type('form')
				.expect(400)
				.expect({
					error: 'use_dpop_nonce',
					error_description: 'invalid nonce in DPoP proof'
				})
				.expect(({ headers }) => {
					nonce = headers['dpop-nonce'];
				});

			await this.agent
				.post('/token')
				.auth('client', 'secret')
				.send({ grant_type: 'client_credentials' })
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/token')}`,
						'POST',
						nonce
					)
				)
				.type('form')
				.expect(200);
		});
	});

	describe('required nonce', () => {
		before(function () {
			this.orig = i(provider).features.dPoP.requireNonce;
			i(provider).features.dPoP.requireNonce = () => true;
		});

		after(function () {
			i(provider).features.dPoP.requireNonce = this.orig;
		});

		it('@ PAR endpoint', async function () {
			const code_verifier = randomBytes(32).toString('base64url');

			let nonce;
			await this.agent
				.post('/request')
				.auth('client', 'secret')
				.send({
					response_type: 'code',
					client_id: 'client',
					code_challenge_method: 'S256',
					code_challenge: hash('sha256', code_verifier, 'base64url')
				})
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/request')}`,
						'POST'
					)
				)
				.type('form')
				.expect(400)
				.expect('DPoP-Nonce', /^[\w-]{43}$/)
				.expect({
					error: 'use_dpop_nonce',
					error_description: 'nonce is required in the DPoP proof'
				})
				.expect(({ headers }) => {
					nonce = headers['dpop-nonce'];
				});

			await this.agent
				.post('/request')
				.auth('client', 'secret')
				.send({
					response_type: 'code',
					client_id: 'client',
					code_challenge_method: 'S256',
					code_challenge: hash('sha256', code_verifier, 'base64url')
				})
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/request')}`,
						'POST',
						nonce
					)
				)
				.type('form')
				.expect(201)
				.expect((response) => {
					// because the sent one is fresh
					expect(response.headers).not.to.have.property('dpop-nonce');
				});
		});

		it('@ userinfo', async function () {
			let nonce;
			await this.agent
				.get('/me')
				.set('Authorization', 'DPoP foo')
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/me')}`,
						'GET',
						undefined,
						'foo'
					)
				)
				.expect(401)
				.expect({
					error: 'use_dpop_nonce',
					error_description: 'nonce is required in the DPoP proof'
				})
				.expect(({ headers }) => {
					nonce = headers['dpop-nonce'];
				});

			await this.agent
				.get('/me')
				.set('Authorization', 'DPoP foo')
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/me')}`,
						'GET',
						nonce,
						'foo'
					)
				)
				.expect(401)
				.expect((response) => {
					// because the sent one is fresh
					expect(response.headers).not.to.have.property('dpop-nonce');
				})
				.expect({
					error: 'invalid_token',
					error_description: 'invalid token provided'
				});
		});

		it('@ token endpoint', async function () {
			let nonce;
			await this.agent
				.post('/token')
				.auth('client', 'secret')
				.send({ grant_type: 'client_credentials' })
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/token')}`,
						'POST'
					)
				)
				.type('form')
				.expect(400)
				.expect({
					error: 'use_dpop_nonce',
					error_description: 'nonce is required in the DPoP proof'
				})
				.expect(({ headers }) => {
					nonce = headers['dpop-nonce'];
				});

			await this.agent
				.post('/token')
				.auth('client', 'secret')
				.send({ grant_type: 'client_credentials' })
				.set(
					'DPoP',
					await DPoP(
						this.keypair,
						`${ISSUER}${this.suitePath('/token')}`,
						'POST',
						nonce
					)
				)
				.type('form')
				.expect(200)
				.expect((response) => {
					// because the sent one is fresh
					expect(response.headers).not.to.have.property('dpop-nonce');
				});
		});
	});
});

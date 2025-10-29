import { createPrivateKey, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { request } from 'node:http';

import { importJWK } from 'jose';
import sinon from 'sinon';
import { expect } from 'chai';
import cloneDeep from 'lodash/cloneDeep.js';

import nanoid from '../../lib/helpers/nanoid.ts';
import provider from '../../lib/index.ts';
import bootstrap, {
	assertNoPendingInterceptors,
	mock
} from '../test_helper.js';
import clientKey from '../client.sig.key.js';
import * as JWT from '../../lib/helpers/jwt.ts';
import { JWA } from '../../lib/consts/index.ts';
import { ISSUER } from 'lib/configs/env.js';

const mtlsKeys = JSON.parse(
	readFileSync('test/jwks/jwks.json', {
		encoding: 'utf-8'
	})
);

const rsacrt = new X509Certificate(
	readFileSync('test/jwks/rsa.crt', { encoding: 'ascii' })
);
const eccrt = new X509Certificate(
	readFileSync('test/jwks/ec.crt', { encoding: 'ascii' })
);

const route = '/token';

const tokenAuthSucceeded = { success: true };

const introspectionAuthSucceeded = {
	active: false
};

const tokenAuthRejected = {
	error: 'invalid_client',
	error_description: 'client authentication failed'
};

function errorDetail(spy) {
	return spy.args[0][1].error_detail;
}

describe('client authentication options', () => {
	before(bootstrap(import.meta.url));

	afterEach(assertNoPendingInterceptors);

	before(function () {
		provider.registerGrantType('foo', (ctx) => {
			ctx.body = { success: true };
		});
	});

	it('expects auth to be provided', function () {
		return this.agent.post(route).send({}).type('form').expect(400).expect({
			error: 'invalid_request',
			error_description: 'no client authentication mechanism provided'
		});
	});

	it('rejects when no client is found', function () {
		return this.agent
			.post(route)
			.send({
				grant_type: 'foo',
				client_id: 'client-not-found'
			})
			.type('form')
			.expect(401)
			.expect(tokenAuthRejected);
	});

	describe('none "auth"', () => {
		it('accepts the "auth"', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_id: 'client-none'
				})
				.type('form')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('rejects the "auth" if secret was also provided', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_id: 'client-none',
					client_secret: 'foobar'
				})
				.type('form')
				.expect(() => {
					expect(spy.calledOnce).to.be.true;
					expect(errorDetail(spy)).to.equal(
						'the provided authentication mechanism does not match the registered client authentication method'
					);
				})
				.expect(401)
				.expect(tokenAuthRejected);
		});
	});

	describe('client_secret_basic auth', () => {
		it('accepts the auth', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.auth('client-basic', 'secret')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('accepts the auth (but client configured with post)', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.auth('client-post', 'secret')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('accepts the auth even with id in the body', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_id: 'client-basic'
				})
				.type('form')
				.auth('client-basic', 'secret')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('rejects the auth when body id differs', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_id: 'client-basic-other'
				})
				.type('form')
				.auth('client-basic', 'secret')
				.expect(400)
				.expect({
					error: 'invalid_request',
					error_description: 'mismatch in body and authorization client ids'
				});
		});

		it('accepts the auth (https://tools.ietf.org/html/rfc6749#appendix-B)', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.auth(' %&+', ' %&+')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('accepts the auth (https://tools.ietf.org/html/rfc6749#appendix-B again)', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.auth('an:identifier', 'some secure & non-standard secret')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('rejects improperly encoded headers', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.set('Authorization', `Basic ${btoa('foo with %:foo with $')}`)
				.expect({
					error: 'invalid_request',
					error_description:
						'client_id and client_secret in the authorization header are not properly encoded'
				});
		});

		it('validates the Basic scheme format (parts)', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.set('Authorization', 'Basic')
				.expect(400)
				.expect({
					error: 'invalid_request',
					error_description: 'invalid authorization header value format'
				});
		});

		it('validates the Basic scheme format (Basic)', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.auth('foo', { type: 'bearer' })
				.expect(400)
				.expect({
					error: 'invalid_request',
					error_description: 'invalid authorization header value format'
				});
		});

		it('validates the Basic scheme format (no :)', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.set('Authorization', 'Basic Zm9v')
				.expect(400)
				.expect({
					error: 'invalid_request',
					error_description: 'invalid authorization header value format'
				});
		});

		it('rejects invalid secrets', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.auth('client-basic', 'invalid secret')
				.expect(() => {
					expect(spy.calledOnce).to.be.true;
					expect(errorDetail(spy)).to.equal('invalid secret provided');
				})
				.expect(401)
				.expect(tokenAuthRejected);
		});

		it('rejects double auth', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_id: 'client-basic',
					client_secret: 'secret'
				})
				.type('form')
				.auth('client-basic', 'invalid secret')
				.expect(400)
				.expect({
					error: 'invalid_request',
					error_description:
						'client authentication must only be provided using one mechanism'
				});
		});

		it('rejects double auth (no client_id in body)', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_secret: 'secret'
				})
				.type('form')
				.auth('client-basic', 'invalid secret')
				.expect(400)
				.expect({
					error: 'invalid_request',
					error_description:
						'client authentication must only be provided using one mechanism'
				});
		});

		it('requires the client_secret to be sent', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.auth('client-basic', '')
				.expect(400)
				.expect({
					error: 'invalid_request',
					error_description:
						'client_secret must be provided in the Authorization header'
				});
		});

		it('rejects expired secrets', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo'
				})
				.type('form')
				.auth('secret-expired-basic', 'secret')
				.expect(400)
				.expect({
					error: 'invalid_client',
					error_description:
						'could not authenticate the client - its client secret is expired'
				});
		});
	});

	describe('client_secret_post auth', () => {
		it('accepts the auth', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_id: 'client-post',
					client_secret: 'secret'
				})
				.type('form')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('can use transfer-encoding: chunked', function (done) {
			const { address, port } = globalThis.server.address();

			const req = request(
				{
					hostname: address,
					port,
					path: this.suitePath(route),
					method: 'POST',
					headers: {
						'Content-Type': 'application/x-www-form-urlencoded',
						'Transfer-Encoding': 'chunked'
					}
				},
				(res) => {
					let data = '';

					res.on('data', (chunk) => {
						data += chunk;
					});

					res.on('end', () => {
						try {
							expect(JSON.parse(data)).to.deep.eql(tokenAuthSucceeded);
							done();
						} catch (err) {
							done(err);
						}
					});

					res.on('error', done);
				}
			);

			req.write('grant_type=foo&client_id');
			req.write('=client-post&client_secret=secret');
			req.end();
			req.on('error', done);
		});

		it('accepts the auth (but client configured with basic)', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_id: 'client-basic',
					client_secret: 'secret'
				})
				.type('form')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('rejects invalid secrets', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_id: 'client-post',
					client_secret: 'invalid'
				})
				.type('form')
				.expect(() => {
					expect(spy.calledOnce).to.be.true;
					expect(errorDetail(spy)).to.equal('invalid secret provided');
				})
				.expect(401)
				.expect(tokenAuthRejected);
		});

		it('requires the client_secret to be sent', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_id: 'client-post',
					client_secret: ''
				})
				.type('form')
				.expect(() => {
					expect(spy.calledOnce).to.be.true;
					expect(errorDetail(spy)).to.equal(
						'the provided authentication mechanism does not match the registered client authentication method'
					);
				})
				.expect(401)
				.expect(tokenAuthRejected);
		});

		it('rejects expired secrets', function () {
			return this.agent
				.post(route)
				.send({
					grant_type: 'foo',
					client_id: 'secret-expired-basic',
					client_secret: 'secret'
				})
				.type('form')
				.expect(400)
				.expect({
					error: 'invalid_client',
					error_description:
						'could not authenticate the client - its client secret is expired'
				});
		});
	});

	describe('client_secret_jwt auth', () => {
		before(async function () {
			this.key = await importJWK(
				(
					await provider.Client.find('client-jwt-secret')
				).symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]
			);
		});

		it('accepts the auth', function () {
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				this.key,
				'HS256',
				{ expiresIn: 60 }
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(tokenAuthSucceeded)
			);
		});

		describe('additional audience values', () => {
			it('accepts the auth when aud is an array', function () {
				return JWT.sign(
					{
						jti: nanoid(),
						aud: [ISSUER],
						sub: 'client-jwt-secret',
						iss: 'client-jwt-secret'
					},
					this.key,
					'HS256',
					{ expiresIn: 60 }
				).then((assertion) =>
					this.agent
						.post(route)
						.send({
							client_assertion: assertion,
							grant_type: 'foo',
							client_assertion_type:
								'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
						})
						.type('form')
						.expect(tokenAuthSucceeded)
				);
			});

			it('accepts the auth when aud is the token endpoint', async function () {
				for (const aud of [
					ISSUER + this.suitePath('/token'),
					[ISSUER + this.suitePath('/token')]
				]) {
					await JWT.sign(
						{
							jti: nanoid(),
							aud,
							sub: 'client-jwt-secret',
							iss: 'client-jwt-secret'
						},
						this.key,
						'HS256',
						{ expiresIn: 60 }
					).then((assertion) =>
						this.agent
							.post(route)
							.send({
								client_assertion: assertion,
								grant_type: 'foo',
								client_assertion_type:
									'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
							})
							.type('form')
							.expect(tokenAuthSucceeded)
					);
				}
			});

			it('accepts the auth when aud is the token endpoint at another endpoint', async function () {
				for (const aud of [
					ISSUER + this.suitePath('/token'),
					[ISSUER + this.suitePath('/token')]
				]) {
					await JWT.sign(
						{
							jti: nanoid(),
							aud,
							sub: 'client-jwt-secret',
							iss: 'client-jwt-secret'
						},
						this.key,
						'HS256',
						{ expiresIn: 60 }
					).then((assertion) =>
						this.agent
							.post('/token/introspection')
							.send({
								client_assertion: assertion,
								client_assertion_type:
									'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
								token: 'foo'
							})
							.type('form')
							.expect(introspectionAuthSucceeded)
					);
				}
			});

			it('accepts the auth when aud is the url of another endpoint it is used at', async function () {
				for (const aud of [
					ISSUER + this.suitePath('/token/introspection'),
					[ISSUER + this.suitePath('/token/introspection')]
				]) {
					await JWT.sign(
						{
							jti: nanoid(),
							aud,
							sub: 'client-jwt-secret',
							iss: 'client-jwt-secret'
						},
						this.key,
						'HS256',
						{ expiresIn: 60 }
					).then((assertion) =>
						this.agent
							.post('/token/introspection')
							.send({
								client_assertion: assertion,
								client_assertion_type:
									'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
								token: 'foo'
							})
							.type('form')
							.expect(introspectionAuthSucceeded)
					);
				}
			});
		});

		it('rejects the auth if this is actually a none-client', async function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-none',
					iss: 'client-none'
				},
				this.key,
				'HS256',
				{ expiresIn: 60 }
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_id: 'client-none',
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(401)
					.expect(tokenAuthRejected)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
						expect(errorDetail(spy)).to.equal(
							'the provided authentication mechanism does not match the registered client authentication method'
						);
					})
			);
		});

		it('rejects the auth if authorization header is also present', function () {
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				this.key,
				'HS256',
				{ expiresIn: 60 }
			).then((assertion) =>
				this.agent
					.post(route)
					.auth('client-basic', 'secret')
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(400)
					.expect({
						error: 'invalid_request',
						error_description:
							'client authentication must only be provided using one mechanism'
					})
			);
		});

		it('rejects the auth if client secret is also present', function () {
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				this.key,
				'HS256',
				{ expiresIn: 60 }
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
						client_secret: 'foo'
					})
					.type('form')
					.expect(400)
					.expect({
						error: 'invalid_request',
						error_description:
							'client authentication must only be provided using one mechanism'
					})
			);
		});

		it('rejects malformed assertions', function () {
			return this.agent
				.post(route)
				.send({
					client_id: 'client-jwt-secret',
					client_assertion:
						'.eyJzdWIiOiJjbGllbnQtand0LXNlY3JldCIsImFsZyI6IkhTMjU2In0.',
					grant_type: 'foo',
					client_assertion_type:
						'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
				})
				.type('form')
				.expect(400)
				.expect({
					error: 'invalid_request',
					error_description: 'invalid client_assertion format'
				});
		});

		it('exp must be set', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret',
					exp: ''
				},
				this.key,
				'HS256',
				{
					// expiresIn: 60
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(401)
					.expect(tokenAuthRejected)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
						expect(errorDetail(spy)).to.equal(
							'expiration must be specified in the client_assertion JWT'
						);
					})
			);
		});

		it('aud must be set', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return JWT.sign(
				{
					jti: nanoid(),
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				this.key,
				'HS256',
				{
					expiresIn: 60
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(401)
					.expect(tokenAuthRejected)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
						expect(errorDetail(spy)).to.equal(
							'aud (JWT audience) must be provided in the client_assertion JWT'
						);
					})
			);
		});

		it('jti must be set', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return JWT.sign(
				{
					// jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				this.key,
				'HS256',
				{
					expiresIn: 60
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(401)
					.expect(tokenAuthRejected)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
						expect(errorDetail(spy)).to.equal(
							'unique jti (JWT ID) must be provided in the client_assertion JWT'
						);
					})
			);
		});

		it('iss must be set', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret'
					// iss: 'client-jwt-secret',
				},
				this.key,
				'HS256',
				{
					expiresIn: 60
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(401)
					.expect(tokenAuthRejected)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
						expect(errorDetail(spy)).to.equal(
							'iss (JWT issuer) must be provided in the client_assertion JWT'
						);
					})
			);
		});

		it('sub must be set', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					// sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				this.key,
				'HS256',
				{
					expiresIn: 60
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(401)
					.expect(tokenAuthRejected)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
						expect(errorDetail(spy)).to.equal(
							'sub (JWT subject) must be provided in the client_assertion JWT'
						);
					})
			);
		});

		it('iss must be the client id', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'not equal to clientid'
				},
				this.key,
				'HS256',
				{
					expiresIn: 60
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(401)
					.expect(tokenAuthRejected)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
						expect(errorDetail(spy)).to.equal(
							'iss (JWT issuer) must be the client_id'
						);
					})
			);
		});

		it('checks for mismatch in client_assertion client_id and body client_id', function () {
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				this.key,
				'HS256',
				{ expiresIn: 60 }
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_id: 'mismatching-client-id',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(400)
					.expect({
						error: 'invalid_request',
						error_description:
							'subject of client_assertion must be the same as client_id provided in the body'
					})
			);
		});

		it('requires client_assertion_type', function () {
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				this.key,
				'HS256',
				{
					expiresIn: 60
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo'
						// client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(400)
					.expect({
						error: 'invalid_request',
						error_description: 'client_assertion_type must be provided'
					})
			);
		});

		it('requires client_assertion_type of specific value', function () {
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				this.key,
				'HS256',
				{
					expiresIn: 60
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type: 'urn:ietf:mycustom'
					})
					.type('form')
					.expect(400)
					.expect({
						error: 'invalid_request',
						error_description:
							'client_assertion_type must have value urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
			);
		});

		it('rejects invalid assertions', function () {
			return this.agent
				.post(route)
				.send({
					client_assertion: 'this.notatall.valid',
					grant_type: 'foo',
					client_assertion_type:
						'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
				})
				.type('form')
				.expect(400)
				.expect({
					error: 'invalid_request',
					error_description: 'invalid client_assertion format'
				});
		});

		it('rejects valid format and signature but expired/invalid jwts', function () {
			const spy = sinon.spy();
			provider.once('grant.error', spy);
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-secret',
					iss: 'client-jwt-secret'
				},
				this.key,
				'HS256',
				{
					expiresIn: -300
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(401)
					.expect(tokenAuthRejected)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
						expect(errorDetail(spy)).to.equal('jwt expired');
					})
			);
		});

		it('rejects assertions when the secret is expired', async function () {
			const key = await importJWK(
				(
					await provider.Client.find('secret-expired-jwt')
				).symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]
			);
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'secret-expired-jwt',
					iss: 'secret-expired-jwt'
				},
				key,
				'HS256',
				{
					expiresIn: -1
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(400)
					.expect({
						error: 'invalid_client',
						error_description:
							'could not authenticate the client - its client secret used for the client_assertion is expired'
					})
			);
		});

		describe('JTI uniqueness', () => {
			it('reused jtis must be rejected', function () {
				const spy = sinon.spy();
				return JWT.sign(
					{
						jti: nanoid(),
						aud: ISSUER,
						sub: 'client-jwt-secret',
						iss: 'client-jwt-secret'
					},
					this.key,
					'HS256',
					{
						expiresIn: 60
					}
				).then((assertion) =>
					this.agent
						.post(route)
						.send({
							client_assertion: assertion,
							grant_type: 'foo',
							client_assertion_type:
								'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
						})
						.type('form')
						.expect(tokenAuthSucceeded)
						.then(() => {
							provider.once('grant.error', spy);
						})
						.then(() =>
							this.agent
								.post(route)
								.send({
									client_assertion: assertion,
									grant_type: 'foo',
									client_assertion_type:
										'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
								})
								.type('form')
								.expect(401)
								.expect(tokenAuthRejected)
								.expect(() => {
									expect(spy.calledOnce).to.be.true;
									expect(errorDetail(spy)).to.equal(
										'client assertion tokens must only be used once'
									);
								})
						)
				);
			});
		});

		describe('when token_endpoint_auth_signing_alg is set on the client', () => {
			before(async function () {
				(
					await provider.Client.find('client-jwt-secret')
				).tokenEndpointAuthSigningAlg = 'HS384';
			});
			after(async function () {
				delete (await provider.Client.find('client-jwt-secret'))
					.tokenEndpointAuthSigningAlg;
			});
			it('rejects signatures with different algorithm', function () {
				const spy = sinon.spy();
				provider.once('grant.error', spy);
				return JWT.sign(
					{
						jti: nanoid(),
						aud: ISSUER,
						sub: 'client-jwt-secret',
						iss: 'client-jwt-secret'
					},
					this.key,
					'HS256',
					{
						expiresIn: 60
					}
				).then((assertion) =>
					this.agent
						.post(route)
						.send({
							client_assertion: assertion,
							grant_type: 'foo',
							client_assertion_type:
								'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
						})
						.type('form')
						.expect(401)
						.expect(tokenAuthRejected)
						.expect(() => {
							expect(spy.calledOnce).to.be.true;
							expect(errorDetail(spy)).to.equal('alg mismatch');
						})
				);
			});
		});
	});

	describe('private_key_jwt auth', () => {
		const privateKey = createPrivateKey({ format: 'jwk', key: clientKey });

		it('accepts the auth', function () {
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-key',
					iss: 'client-jwt-key'
				},
				privateKey,
				'RS256',
				{
					expiresIn: 60
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(tokenAuthSucceeded)
			);
		});

		it('accepts client assertions issued within acceptable system clock skew', function () {
			return JWT.sign(
				{
					jti: nanoid(),
					aud: ISSUER,
					sub: 'client-jwt-key',
					iss: 'client-jwt-key',
					iat: Math.ceil(Date.now() / 1000) + 5
				},
				privateKey,
				'RS256',
				{
					expiresIn: 60
				}
			).then((assertion) =>
				this.agent
					.post(route)
					.send({
						client_assertion: assertion,
						grant_type: 'foo',
						client_assertion_type:
							'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
					})
					.type('form')
					.expect(tokenAuthSucceeded)
			);
		});
	});

	describe('tls_client_auth auth', () => {
		it('accepts the auth', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
				.set('x-ssl-client-verify', 'SUCCESS')
				.set('x-ssl-client-san-dns', 'rp.example.com')
				.send({
					client_id: 'client-pki-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('fails the auth when getCertificate() does not return a cert', function () {
			return this.agent
				.post(route)
				.send({
					client_id: 'client-pki-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(tokenAuthRejected);
		});

		it('fails the auth when certificateAuthorized() fails', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
				.set('x-ssl-client-verify', 'FAILED: self signed certificate')
				.set('x-ssl-client-san-dns', 'rp.example.com')
				.send({
					client_id: 'client-pki-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(tokenAuthRejected);
		});

		it('fails the auth when certificateSubjectMatches() return false', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
				.set('x-ssl-client-verify', 'SUCCESS')
				.set('x-ssl-client-san-dns', 'foobarbaz')
				.send({
					client_id: 'client-pki-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(tokenAuthRejected);
		});
	});

	describe('self_signed_tls_client_auth auth', () => {
		it('accepts the auth [1/2]', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
				.send({
					client_id: 'client-self-signed-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('accepts the auth [2/2]', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', eccrt.raw.toString('base64'))
				.send({
					client_id: 'client-self-signed-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});

		it('fails the auth when x-ssl-client-cert is not passed by the proxy', function () {
			return this.agent
				.post(route)
				.send({
					client_id: 'client-self-signed-mtls',
					grant_type: 'foo'
				})
				.type('form')
				.expect(tokenAuthRejected);
		});

		it('fails the auth when x-ssl-client-cert does not match the registered ones', function () {
			return this.agent
				.post(route)
				.set('x-ssl-client-cert', eccrt.raw.toString('base64'))
				.send({
					client_id: 'client-self-signed-mtls-rsa',
					grant_type: 'foo'
				})
				.type('form')
				.expect(tokenAuthRejected);
		});

		it('handles rotation of stale jwks', function () {
			mock('https://client.example.com')
				.intercept({
					path: '/jwks'
				})
				.reply(200, JSON.stringify(mtlsKeys));

			return this.agent
				.post(route)
				.set('x-ssl-client-cert', rsacrt.raw.toString('base64'))
				.send({
					client_id: 'client-self-signed-mtls-jwks_uri',
					grant_type: 'foo'
				})
				.type('form')
				.expect(200)
				.expect(tokenAuthSucceeded);
		});
	});
});

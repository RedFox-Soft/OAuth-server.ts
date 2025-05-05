/* eslint-disable no-underscore-dangle */

import { parse, pathToFileURL } from 'node:url';
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import * as querystring from 'node:querystring';

import { setGlobalDispatcher, MockAgent } from 'undici';
import sinon from 'sinon';
import { dirname } from 'desm';
import flatten from 'lodash/flatten.js';
import { Request } from 'superagent';
import { expect } from 'chai';

import base64url from 'base64url';
import { CookieAccessInfo } from 'cookiejar';
import { treaty } from '@elysiajs/eden';

import nanoid from '../lib/helpers/nanoid.ts';
import epochTime from '../lib/helpers/epoch_time.ts';
import Provider from '../lib/index.ts';
import instance from '../lib/helpers/weak_cache.ts';

import { Account, TestAdapter } from './models.js';
import keys from './keys.js';

const fetchAgent = new MockAgent();
// fetchAgent.disableNetConnect();
setGlobalDispatcher(fetchAgent);

const { _auth } = Request.prototype;

const { info, warn } = console;
console.info = function (...args) {
	if (!args[0].includes('NOTICE: ')) info.apply(this, args);
};
console.warn = function (...args) {
	if (!args[0].includes('WARNING: ')) warn.apply(this, args);
};

function encodeToken(token) {
	return encodeURIComponent(token).replace(
		/(?:[-_.!~*'()]|%20)/g,
		(substring) => {
			switch (substring) {
				case '-':
					return '%2D';
				case '_':
					return '%5F';
				case '.':
					return '%2E';
				case '!':
					return '%21';
				case '~':
					return '%7E';
				case '*':
					return '%2A';
				case "'":
					return '%27';
				case '(':
					return '%28';
				case ')':
					return '%29';
				case '%20':
					return '+';
				default:
					throw new Error();
			}
		}
	);
}

Request.prototype._auth = function (user, pass, options, encoder) {
	if (options?.type === 'basic') {
		return _auth.call(
			this,
			encodeToken(user),
			encodeToken(pass),
			options,
			encoder
		);
	}

	return _auth.call(this, user, pass, options, encoder);
};

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

globalThis.i = instance;

Object.defineProperties(Provider.prototype, {
	enable: {
		value(feature, options = {}) {
			const config = i(this).features[feature];
			if (!config) {
				throw new Error(`invalid feature: ${feature}`);
			}

			Object.keys(options).forEach((key) => {
				if (!(key in config)) {
					throw new Error(`invalid option: ${key}`);
				}
			});

			config.enabled = true;
			Object.assign(config, options);

			return this;
		}
	}
});

function getSetCookies(cookies) {
	return cookies.filter(
		(val) => !val.includes('Thu, 01 Jan 1970 00:00:00 GMT')
	);
}

function readCookie(value) {
	expect(value).to.exist;
	const parsed = querystring.parse(value, '; ');
	const key = Object.keys(parsed)[0];
	return parsed[key];
}

const jwt = (token) => JSON.parse(base64url.decode(token.split('.')[1])).jti;

export default function testHelper(
	importMetaUrl,
	{
		config: base,
		protocol = 'http:',
		mountVia = process.env.MOUNT_VIA,
		mountTo = mountVia ? process.env.MOUNT_TO || '/' : '/'
	} = {}
) {
	const dir = dirname(importMetaUrl);
	base ??= path.basename(dir);

	return async function () {
		const conf = pathToFileURL(
			path.format({ dir, base: `${base}.config.js` })
		).toString();
		const { default: mod } = await import(conf);
		const { config, client } = mod;
		let { clients } = mod;

		if (client && !clients) {
			clients = [client];
		}

		if (!config.findAccount) {
			config.findAccount = Account.findAccount;
		}

		const issuerIdentifier = `${protocol}//127.0.0.1:3000`;
		TestAdapter.clear();

		const provider = new Provider(issuerIdentifier, {
			clients,
			jwks: { keys },
			adapter: TestAdapter,
			...config
		});
		globalThis.provider = provider;

		let agent;
		let lastSession;

		function logout() {
			const expire = new Date(0);
			const cookies = [
				`_session=; path=/; expires=${expire.toGMTString()}; httponly`
			];

			return agent._saveCookies.bind(agent)({
				request: { url: provider.issuer },
				headers: { 'set-cookie': cookies }
			});
		}

		async function login({
			scope = 'openid',
			claims,
			resources = {},
			rejectedScopes = [],
			rejectedClaims = [],
			accountId = nanoid()
		} = {}) {
			const sessionId = nanoid();
			const loginTs = epochTime();
			const expire = new Date();
			expire.setDate(expire.getDate() + 1);
			this.loggedInAccountId = accountId;

			const session = new provider.Session({
				jti: sessionId,
				loginTs,
				accountId
			});
			lastSession = session;
			const sessionCookie = `_session=${sessionId}; path=/; expires=${expire.toGMTString()}; httponly`;
			const cookies = [sessionCookie];

			session.authorizations = {};
			const ctx = new provider.OIDCContext({ req: { socket: {} }, res: {} });
			ctx.params = { scope, claims };

			if (ctx.params.claims && typeof ctx.params.claims !== 'string') {
				ctx.params.claims = JSON.stringify(ctx.params.claims);
			}

			for (const cl of clients) {
				const grant = new provider.Grant({ clientId: cl.client_id, accountId });
				grant.addOIDCScope(scope);
				if (ctx.params.claims) {
					grant.addOIDCClaims(
						Object.keys(JSON.parse(ctx.params.claims).id_token || {})
					);
					grant.addOIDCClaims(
						Object.keys(JSON.parse(ctx.params.claims).userinfo || {})
					);
				}
				if (rejectedScopes.length) {
					grant.rejectOIDCScope(rejectedScopes.join(' '));
				}
				if (rejectedClaims.length) {
					grant.rejectOIDCClaims(rejectedClaims);
				}

				for (const [key, value] of Object.entries(resources)) {
					grant.addResourceScope(key, value);
				}

				const grantId = await grant.save();
				session.authorizations[cl.client_id] = {
					sid: nanoid(),
					grantId
				};
			}

			let ttl = i(provider).configuration.ttl.Session;

			if (typeof ttl === 'function') {
				ttl = ttl(ctx, session);
			}

			return Account.findAccount({}, accountId)
				.then(session.save(ttl))
				.then(() => {
					return cookies;
				});
		}

		class AuthorizationRequest {
			params = {};
			client = {};
			res = {};
			code_verifier = crypto.randomBytes(32).toString('base64url');
			client_id = '';
			grant_type = 'authorization_code';

			constructor(parameters = {}) {
				if (parameters.claims && typeof parameters.claims !== 'string') {
					parameters.claims = JSON.stringify(parameters.claims);
				}
				this.params = parameters;
				this.params.client_id ??= clients[0].client_id;
				this.client_id = this.params.client_id;
				this.client = clients.find(
					(cl) => cl.client_id === this.params.client_id
				);
				this.params.state ??= crypto.randomBytes(16).toString('base64url');
				this.params.redirect_uri ??= this.client?.redirect_uris[0];

				if (this.params.scope?.includes('openid')) {
					this.params.nonce ??= crypto.randomBytes(16).toString('base64url');
				}

				this.params.response_type ??= 'code';
				if (this.params.response_type === 'code') {
					this.params.code_challenge_method ??= 'S256';
					this.params.code_challenge ??= crypto.hash(
						'sha256',
						this.code_verifier,
						'base64url'
					);
				}
			}

			get basicAuthHeader() {
				if (this.client.token_endpoint_auth_method === 'none') {
					return {};
				}

				const { client_secret } = this.client;
				return {
					Authorization: `Basic ${base64url.encode(`${this.client_id}:${client_secret}`)}`
				};
			}

			validateClientLocation(response) {
				const actual = parse(response.headers.get('location'), true);
				let expected;
				if (this.redirect_uri) {
					expect(response.headers.get('location')).to.match(
						new RegExp(this.redirect_uri)
					);
					expected = parse(this.redirect_uri, true);
				} else {
					expect(response.headers.get('location')).to.match(
						new RegExp(this.client.redirect_uris[0])
					);
					expected = parse(this.client.redirect_uris[0], true);
				}

				['protocol', 'host', 'pathname'].forEach((attr) => {
					expect(actual[attr]).to.equal(expected[attr]);
				});
			}

			validateState(response) {
				const {
					query: { state }
				} = parse(response.headers.get('location'), true);
				expect(state).to.equal(this.params.state);
			}

			validateIss(response) {
				const {
					query: { iss }
				} = parse(response.headers.get('location'), true);
				expect(iss).to.equal(issuerIdentifier);
			}

			validateInteractionRedirect(response) {
				const { hostname, search, query } = parse(
					response.headers.get('location')
				);
				expect(hostname).to.be.null;
				expect(search).to.be.null;
				expect(query).to.be.null;
				const cookies = response.headers.getSetCookie();
				expect(Array.isArray(cookies)).to.be.true;

				const uid = readCookie(getSetCookies(cookies)[0]);
				expect(readCookie(getSetCookies(cookies)[0])).to.equal(
					readCookie(getSetCookies(cookies)[1])
				);

				const interaction = TestAdapter.for('Interaction').syncFind(uid);

				Object.entries(this.params).forEach(([key, value]) => {
					if (key === 'res') return;
					if (key === 'request') return;
					if (key === 'code_verifier') return;
					if (key === 'request_uri') return;
					if (key === 'max_age' && value === 0) {
						expect(interaction.params).not.to.have.property('max_age');
						expect(interaction.params)
							.to.have.property('prompt')
							.that.contains('login');
					} else {
						expect(interaction.params).to.have.property(key, value);
					}
				});
			}
		}

		AuthorizationRequest.prototype.validateInteraction = (
			eName,
			...eReasons
		) => {
			// eslint-disable-line arrow-body-style
			return (response) => {
				const uid = readCookie(getSetCookies(response)[0]);
				const {
					prompt: { name, reasons }
				} = TestAdapter.for('Interaction').syncFind(uid);
				expect(name).to.equal(eName);
				expect(reasons).to.contain.members(eReasons);
			};
		};

		AuthorizationRequest.prototype.validatePresence = function (
			response,
			properties,
			all
		) {
			let absolute;
			if (all === undefined) {
				absolute = true;
			} else {
				absolute = all;
			}

			properties =
				!absolute ||
				properties.includes('id_token') ||
				properties.includes('response')
					? properties
					: [...new Set(properties.concat('iss'))];

			const { query } = parse(response.headers.get('location'), true);
			if (absolute) {
				expect(query).to.have.keys(properties);
			} else {
				expect(query).to.contain.keys(properties);
			}
			properties.forEach((key) => {
				this.res[key] = query[key];
			});
		};

		AuthorizationRequest.prototype.validateResponseParameter = function (
			parameter,
			expected
		) {
			return (response) => {
				const {
					query: { [parameter]: value }
				} = parse(response.headers.location, true);
				if (expected.exec) {
					expect(value).to.match(expected);
				} else {
					expect(value).to.equal(expected);
				}
			};
		};

		AuthorizationRequest.prototype.validateError = function (expected) {
			return this.validateResponseParameter('error', expected);
		};

		AuthorizationRequest.prototype.validateScope = function (expected) {
			return this.validateResponseParameter('scope', expected);
		};

		AuthorizationRequest.prototype.validateErrorDescription = function (
			expected
		) {
			return this.validateResponseParameter('error_description', expected);
		};

		AuthorizationRequest.prototype.getToken = async function (code) {
			const isBasicAuth = this.client.token_endpoint_auth_method !== 'none';
			return await agent.token.post(
				{
					client_id: isBasicAuth ? undefined : this.client_id,
					code,
					grant_type: this.grant_type,
					code_verifier: this.code_verifier,
					redirect_uri: this.params.redirect_uri
				},
				{
					headers: this.basicAuthHeader
				}
			);
		};

		async function getToken(auth, options = {}) {
			let code;
			await wrap({
				route: '/auth',
				verb: 'get',
				auth,
				...options
			})
				.expect(303)
				.expect((response) => {
					code = parse(response.headers.location, true).query.code;
				});

			return auth.getToken(code);
		}

		function getLastSession() {
			return lastSession;
		}

		function getSessionId() {
			const { value: sessionId } =
				agent.jar.getCookie('_session', CookieAccessInfo.All) || {};
			return sessionId;
		}

		function getSession({ instantiate } = { instantiate: false }) {
			const sessionId = getLastSession().jti;
			const raw = TestAdapter.for('Session').syncFind(sessionId);

			if (instantiate) {
				return new provider.Session(raw);
			}

			return raw;
		}

		function getGrantId(client_id) {
			const session = getSession();
			let clientId = client_id;

			if (!clientId && client) clientId = client.client_id;
			if (!clientId && clients) clientId = clients[0].client_id;
			try {
				return session.authorizations[clientId].grantId;
			} catch (err) {
				throw new Error('getGrantId() failed');
			}
		}

		function wrap(opts) {
			const { route, verb, auth, params, user, secret } = opts;
			switch (verb) {
				case 'get': {
					if (user && secret) {
						return agent
							.get(route)
							.auth(user, secret)
							.query(auth || params);
					}
					return agent.get(route).query(auth || params);
				}
				case 'post': {
					if (user && secret) {
						return agent
							.post(route)
							.auth(user, secret)
							.send(auth || params)
							.type('form');
					}
					return agent
						.post(route)
						.send(auth || params)
						.type('form');
				}

				default:
					throw new Error('invalid wrap verb');
			}
		}

		function assertOnce(ondone, done) {
			async function removeAfterUse(ctx, next) {
				await next().finally(() => {
					provider.middleware.splice(
						provider.middleware.indexOf(removeAfterUse),
						1
					);
					try {
						ondone(ctx);
						done();
					} catch (err) {
						done(err);
					}
				});
			}
			provider.use(removeAfterUse);
		}

		function getTokenJti(token) {
			try {
				return jwt(token);
			} catch (err) {}

			return token; // opaque
		}

		function failWith(code, error, error_description, scope) {
			return ({ status, body, headers: { 'www-authenticate': wwwAuth } }) => {
				const {
					provider: { issuer }
				} = this;
				expect(status).to.eql(code);
				expect(body).to.have.property('error', error);
				expect(body).to.have.property('error_description', error_description);
				expect(wwwAuth).to.match(new RegExp(`^Bearer realm="${issuer}"`));
				let check = expect(wwwAuth);
				if (error_description === 'no access token provided') {
					check = check.not.to;
				} else {
					check = check.to;
				}
				check.match(new RegExp(`error="${error}"`));
				check.match(
					new RegExp(
						`error_description="${error_description.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}"`
					)
				);
				if (scope) check.match(new RegExp(`scope="${scope}"`));
			};
		}

		agent = treaty(provider.elysia, {
			onRequest: (path, fetchInit) => {
				if (path === '/auth' && fetchInit.method === 'POST') {
					fetchInit.headers['content-type'] =
						'application/x-www-form-urlencoded';
				}
			}
		});

		if (mountTo !== '/') {
			['get', 'post', 'put', 'del', 'options', 'trace'].forEach((method) => {
				const orig = agent[method];
				agent[method] = function (route, ...args) {
					if (route.startsWith(mountTo)) {
						return orig.call(this, route, ...args);
					}
					return orig.call(this, `${mountTo}${route}`, ...args);
				};
			});
		}

		/*this.suitePath = (unprefixed) => {
			if (mountTo === '/') {
				return unprefixed;
			}

			return `${mountTo}${unprefixed}`;
		};*/

		return {
			assertOnce,
			AuthorizationRequest,
			failWith,
			getLastSession,
			getSession,
			getSessionId,
			getGrantId,
			getTokenJti,
			getToken,
			login,
			logout,
			provider,
			TestAdapter,
			wrap,
			fetchAgent,
			agent
		};
	};
}

export function passInteractionChecks(...reasons) {
	const cb = reasons.pop();

	const sandbox = sinon.createSandbox();

	context('', () => {
		before(function () {
			const { policy } = i(this.provider).configuration.interactions;

			const iChecks = flatten(policy.map((i) => i.checks));

			iChecks
				.filter((check) => reasons.includes(check.reason))
				.forEach((check) => {
					sandbox.stub(check, 'check').returns(false);
				});
		});

		after(sandbox.restore);

		cb();
	});
}

export function skipConsent() {
	const sandbox = sinon.createSandbox();

	before(function () {
		sandbox
			.stub(this.provider.OIDCContext.prototype, 'promptPending')
			.returns(false);
	});

	after(sandbox.restore);
}

export function enableNetConnect() {
	fetchAgent.enableNetConnect();
}

export function resetNetConnect() {
	fetchAgent.disableNetConnect();
}

export function disableNetConnect() {
	fetchAgent.disableNetConnect();
}

export function assertNoPendingInterceptors() {
	fetchAgent.assertNoPendingInterceptors();
}

export function mock(origin) {
	return fetchAgent.get(origin);
}

import { pathToFileURL } from 'node:url';
import * as path from 'node:path';

import sinon from 'sinon';
import { dirname } from 'desm';
import flatten from 'lodash/flatten.js';
import { expect } from 'chai';

import base64url from 'base64url';
import { CookieAccessInfo } from 'cookiejar';
import { treaty } from '@elysiajs/eden';

import nanoid from '../lib/helpers/nanoid.ts';
import epochTime from '../lib/helpers/epoch_time.ts';
import { provider, elysia } from '../lib/index.ts';
import instance from '../lib/helpers/weak_cache.ts';

import { Account, TestAdapter } from './models.js';
import keys from './keys.js';
import { AuthorizationRequest } from './AuthorizationRequest.js';

import { ApplicationConfig } from '../lib/configs/application.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

const applicationDefaultSettings = { ...ApplicationConfig };
const clientDefaultSettings = { ...ClientDefaults };

const { info, warn } = console;
console.info = function (...args) {
	if (!args[0].includes('NOTICE: ')) info.apply(this, args);
};
console.warn = function (...args) {
	if (!args[0].includes('WARNING: ')) warn.apply(this, args);
};

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

globalThis.i = instance;

Object.defineProperties(Object.getPrototypeOf(provider), {
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

const jwt = (token) => JSON.parse(base64url.decode(token.split('.')[1])).jti;

export const agent = treaty(elysia, {
	onRequest: (path, fetchInit) => {
		if (fetchInit.method === 'POST' && !fetchInit.body?.startsWith?.('{')) {
			fetchInit.headers['content-type'] = 'application/x-www-form-urlencoded';
		}
	}
});

export function jsonToFormUrlEncoded(json: Record<string, unknown>) {
	const searchParams = new URLSearchParams();
	for (const [key, value] of Object.entries(json)) {
		if (Array.isArray(value)) {
			value.forEach((v) => searchParams.append(key, v));
		} else {
			searchParams.append(key, String(value));
		}
	}
	return searchParams.toString();
}

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
		const {
			default: mod,
			ApplicationConfig: app,
			ClientDefaults: clientSettings
		} = await import(conf);
		const { config, client } = mod;
		let { clients } = mod;

		if (client && !clients) {
			clients = [client];
		}
		AuthorizationRequest.clients = clients;

		if (!config.findAccount) {
			config.findAccount = Account.findAccount;
		}

		Object.assign(ApplicationConfig, applicationDefaultSettings, app || {});
		Object.assign(ClientDefaults, clientDefaultSettings, clientSettings || {});
		const issuerIdentifier = `${protocol}//127.0.0.1:3000`;
		TestAdapter.clear();

		provider.init(issuerIdentifier, {
			clients,
			jwks: { keys },
			adapter: TestAdapter,
			...config
		});

		let agent;
		let lastSession;
		let lastAccountId;

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
			lastAccountId = accountId;

			const session = new provider.Session({
				jti: sessionId,
				loginTs,
				accountId
			});
			lastSession = session;
			const sessionCookie = `_session=${sessionId}; path=/; expires=${expire.toGMTString()}; httponly`;
			const cookies = [sessionCookie];

			session.authorizations = {};
			const ctx = new OIDCContext({ req: { socket: {} }, res: {} });
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
			failWith,
			getLastSession,
			getSession,
			getAccountId() {
				return lastAccountId;
			},
			getSessionId,
			getGrantId,
			getTokenJti,
			login,
			TestAdapter
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

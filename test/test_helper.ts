import { pathToFileURL } from 'node:url';
import * as path from 'node:path';

import { dirname } from 'desm';
import { beforeAll, afterAll, expect } from 'bun:test';

import base64url from 'base64url';
import { treaty } from '@elysiajs/eden';

import nanoid from '../lib/helpers/nanoid.js';
import epochTime from '../lib/helpers/epoch_time.js';
import { provider, elysia } from '../lib/index.ts';
import instance from '../lib/helpers/weak_cache.ts';

import { Account, TestAdapter } from './models.js';
import { AuthorizationRequest } from './AuthorizationRequest.js';

import { ApplicationConfig } from '../lib/configs/application.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { Session } from 'lib/models/session.js';
import { ttl } from 'lib/configs/liveTime.js';
import { Grant } from 'lib/models/grant.js';
import { ISSUER } from 'lib/configs/env.js';
export { Grant } from 'lib/models/grant.js';

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

const jwt = (token: string) =>
	JSON.parse(base64url.decode(token.split('.')[1])).jti;

export const agent = treaty(elysia);

// Faithful port of oidc-provider's test helper: the leading arguments are interaction-policy
// check reasons that must be made to "pass" (i.e. never trigger a prompt) for the wrapped cases,
// and the final argument is the callback that registers the nested describe/it cases. The named
// checks are disabled around the block and restored afterwards.
export function passInteractionChecks(...args: unknown[]) {
	const fn = args[args.length - 1] as () => void;
	const reasons = args.slice(0, -1) as string[];
	const disabled: Array<{ check: { check: unknown }; original: unknown }> = [];

	beforeAll(() => {
		const { policy } = instance(provider).configuration.interactions;
		for (const prompt of policy) {
			for (const check of prompt.checks) {
				if (reasons.includes(check.reason)) {
					disabled.push({ check, original: check.check });
					check.check = () => false;
				}
			}
		}
	});

	afterAll(() => {
		for (const { check, original } of disabled) {
			check.check = original;
		}
		disabled.length = 0;
	});

	return fn();
}

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

export default function (
	importMetaUrl: string,
	{ config: base }: { config?: string } = {}
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
		TestAdapter.clear();

		provider.init({
			clients,
			adapter: TestAdapter,
			...config
		});

		let lastSession: Session;
		let lastAccountId: string;

		async function login({
			scope = 'openid',
			claims,
			resources = {},
			rejectedScopes = [],
			rejectedClaims = [],
			accountId = nanoid()
		}: {
			scope?: string;
			claims?: {
				id_token?: Record<string, unknown>;
				userinfo?: Record<string, unknown>;
			};
			resources?: Record<string, string>;
			rejectedScopes?: string[];
			rejectedClaims?: string[];
			accountId?: string;
		} = {}) {
			const sessionId = nanoid();
			const loginTs = epochTime();
			const expire = new Date();
			expire.setDate(expire.getDate() + 1);
			lastAccountId = accountId;

			const session = new Session({
				jti: sessionId,
				loginTs,
				accountId
			});
			lastSession = session;
			const sessionCookie = `_session=${sessionId}; path=/; expires=${expire.toGMTString()}; httponly`;
			const cookies = [sessionCookie];

			session.payload.authorizations = {};
			const oidc = new OIDCContext({ scope, claims });

			if (oidc.params.claims && typeof oidc.params.claims !== 'string') {
				oidc.params.claims = JSON.stringify(oidc.params.claims);
			}

			for (const cl of clients) {
				const grant = new Grant({ clientId: cl.clientId, accountId });
				grant.addOIDCScope(scope);
				if (oidc.params.claims) {
					grant.addOIDCClaims(
						Object.keys(JSON.parse(oidc.params.claims).id_token || {})
					);
					grant.addOIDCClaims(
						Object.keys(JSON.parse(oidc.params.claims).userinfo || {})
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
				session.payload.authorizations[cl.clientId] = {
					sid: nanoid(),
					grantId
				};
			}

			return Account.findAccount({}, accountId)
				.then(session.save(ttl.Session))
				.then(() => {
					return cookies;
				});
		}

		function getLastSession() {
			return lastSession;
		}

		function getSessionId() {
			return getLastSession().id;
		}

		function getSession(id?: string) {
			const sessionId = id ?? getLastSession().id;
			return TestAdapter.for('Session').syncFind(sessionId);
		}

		function getGrantId(clientId?: string) {
			const session = getSession();

			if (!clientId && client) clientId = client.clientId;
			if (!clientId && clients) clientId = clients[0].clientId;
			try {
				return session.authorizations[clientId].grantId;
			} catch (err) {
				throw new Error('getGrantId() failed');
			}
		}

		function getTokenJti(token: string) {
			try {
				return jwt(token);
			} catch (err) {}

			return token; // opaque
		}

		function failWith(
			code: number,
			error: string,
			error_description: string,
			scope?: string
		) {
			return ({
				status,
				body,
				headers: { 'www-authenticate': wwwAuth }
			}: {
				status: number;
				body: unknown;
				headers: Record<string, string | undefined>;
			}) => {
				expect(status).toEqual(code);
				expect(body).toHaveProperty('error', error);
				expect(body).toHaveProperty('error_description', error_description);
				expect(wwwAuth).toMatch(new RegExp(`^Bearer realm="${ISSUER}"`));
				const present = error_description !== 'no access token provided';
				const check = (re: RegExp) => {
					if (present) expect(wwwAuth).toMatch(re);
					else expect(wwwAuth).not.toMatch(re);
				};
				check(new RegExp(`error="${error}"`));
				check(
					new RegExp(
						`error_description="${error_description.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}"`
					)
				);
				if (scope) check(new RegExp(`scope="${scope}"`));
			};
		}

		return {
			failWith,
			getLastSession,
			getSession,
			getAccountId() {
				return lastAccountId;
			},
			getSessionId,
			getGrantId,
			getTokenJti,
			login
		};
	};
}

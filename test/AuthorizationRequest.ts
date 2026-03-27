import { expect } from 'bun:test';
import crypto from 'node:crypto';
import { parse } from 'node:url';
import querystring from 'node:querystring';

import { TestAdapter } from './models.js';
import { agent } from './test_helper.js';
import { type AuthorizationParameters } from '../lib/consts/param_list.js';
import { type Static } from 'elysia';
import { type ClientSchemaType } from 'lib/configs/clientSchema.js';
import { ISSUER } from 'lib/configs/env.js';

function getSetCookies(cookies: string[]) {
	return cookies.filter(
		(val) => !val.includes('Thu, 01 Jan 1970 00:00:00 GMT')
	);
}

function getLocation(res: Response) {
	const location = res.headers.get('location');
	if (!location) {
		throw new Error('missing location header');
	}
	return location;
}

function readCookie(value: string) {
	expect(value).toBeTruthy();
	const parsed = querystring.parse(value, '; ');
	const key = Object.keys(parsed)[0];
	return parsed[key];
}

type AuthParams = Static<typeof AuthorizationParameters> & {
	claims?: object | string;
};

export class AuthorizationRequest {
	static clients: ClientSchemaType[] = [];

	params: AuthParams;
	client: ClientSchemaType;
	res = {};
	code_verifier = crypto.randomBytes(32).toString('base64url');
	clientId: string;
	grant_type = 'authorization_code';

	constructor(parameters: Partial<AuthParams> = {}) {
		if (parameters.claims && typeof parameters.claims !== 'string') {
			parameters.claims = JSON.stringify(parameters.claims);
		}
		if (!AuthorizationRequest.clients[0]) {
			throw new Error('No clients have been registered');
		}

		parameters.client_id ??= AuthorizationRequest.clients[0].clientId;
		this.params = parameters;
		this.clientId = this.params.client_id;
		this.client = AuthorizationRequest.clients.find(
			(cl) => cl.clientId === this.params.client_id
		);
		this.params.state ??= crypto.randomBytes(16).toString('base64url');
		this.params.redirect_uri ??= this.client?.redirectUris[0];

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

		const { clientSecret } = this.client;
		return AuthorizationRequest.basicAuthHeader(this.clientId, clientSecret);
	}

	static basicAuthHeader(clientId: string, clientSecret: string) {
		const enc = encodeURIComponent;
		const str = Buffer.from(`${enc(clientId)}:${enc(clientSecret)}`).toString(
			'base64url'
		);
		return { authorization: `Basic ${str}` };
	}

	validateClientLocation(response: Response) {
		const location = getLocation(response);
		const actual = parse(location, true);
		let expected;
		if (this.params.redirect_uri) {
			expect(location).toMatch(new RegExp(this.params.redirect_uri));
			expected = parse(this.params.redirect_uri, true);
		} else {
			expect(location).toMatch(new RegExp(this.client.redirectUris[0]));
			expected = parse(this.client.redirectUris[0], true);
		}

		['protocol', 'host', 'pathname'].forEach((attr) => {
			expect(actual[attr]).toBe(expected[attr]);
		});
	}

	validateState(response: Response) {
		const location = getLocation(response);
		const {
			query: { state }
		} = parse(location, true);
		expect(state).toBe(this.params.state);
	}

	validateIss(response: Response) {
		const location = getLocation(response);
		const {
			query: { iss }
		} = parse(location, true);
		expect(iss).toBe(ISSUER);
	}

	validateInteractionRedirect(response: Response) {
		const location = getLocation(response);
		const { hostname, search, query } = parse(location);
		expect(hostname).toBeNull();
		expect(search).toBeNull();
		expect(query).toBeNull();
		const cookies = response.headers.getSetCookie();
		expect(Array.isArray(cookies)).toBeTrue();

		const [, , uid] = location.split('/');

		const interaction = TestAdapter.for('Interaction').syncFind(uid);
		const cookieID = readCookie(getSetCookies(cookies)[0]);
		expect(cookieID).toBe(interaction.cookieID);

		if (interaction.params.claims) {
			interaction.params.claims = JSON.stringify(interaction.params.claims);
		}

		Object.entries(this.params).forEach(([key, value]) => {
			if (key === 'res') return;
			if (key === 'request') return;
			if (key === 'code_verifier') return;
			if (key === 'request_uri') return;
			if (key === 'max_age' && value === 0) {
				expect(interaction.params).not.toHaveProperty('max_age');
				expect(interaction.params.prompt).toContain('login');
			} else {
				expect(interaction.params).toHaveProperty(key, value);
			}
		});
	}

	validateInteraction(
		response: Response,
		eName: string,
		...eReasons: string[]
	) {
		const location = getLocation(response);
		const [, , uid] = location.split('/');
		const {
			prompt: { name, reasons }
		} = TestAdapter.for('Interaction').syncFind(uid);
		expect(name).toBe(eName);
		expect(reasons).toEqual(expect.arrayContaining(eReasons));
	}

	validatePresence(response: Response, properties: string[], all = true) {
		properties =
			!all || properties.includes('id_token') || properties.includes('response')
				? properties
				: [...new Set(properties.concat('iss'))];

		const { query } = parse(getLocation(response), true);
		if (all) {
			expect(Object.keys(query)).toEqual(properties);
		} else {
			expect(Object.keys(query)).toEqual(expect.arrayContaining(properties));
		}
		properties.forEach((key) => {
			this.res[key] = query[key];
		});
	}

	validateResponseParameter(
		response: Response,
		parameter: string,
		expected: string | RegExp
	) {
		const {
			query: { [parameter]: value }
		} = parse(getLocation(response), true);
		if (expected instanceof RegExp) {
			expect(value).toMatch(expected);
		} else {
			expect(value).toBe(expected);
		}
	}

	validateError(response: Response, expected: string) {
		this.validateResponseParameter(response, 'error', expected);
	}

	validateScope(response: Response, expected: string) {
		this.validateResponseParameter(response, 'scope', expected);
	}

	validateErrorDescription(response: Response, expected: string) {
		this.validateResponseParameter(response, 'error_description', expected);
	}

	async getToken(code: string, { headers = {} } = {}) {
		const isBasicAuth = this.client.token_endpoint_auth_method !== 'none';
		return await agent.token.post(
			{
				client_id: isBasicAuth ? undefined : this.clientId,
				code,
				grant_type: this.grant_type,
				code_verifier: this.code_verifier,
				redirect_uri: this.params.redirect_uri
			},
			{
				headers: { ...this.basicAuthHeader, ...headers }
			}
		);
	}
}

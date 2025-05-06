import crypto from 'node:crypto';
import { parse } from 'node:url';
import querystring from 'node:querystring';

import { expect } from 'chai';
import { TestAdapter } from './models.js';
import base64url from 'base64url';

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

export class AuthorizationRequest {
	static clients = [];

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
		this.params.client_id ??= AuthorizationRequest.clients[0].client_id;
		this.client_id = this.params.client_id;
		this.client = AuthorizationRequest.clients.find(
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
		if (this.params.redirect_uri) {
			expect(response.headers.get('location')).to.match(
				new RegExp(this.params.redirect_uri)
			);
			expected = parse(this.params.redirect_uri, true);
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
		const { hostname, search, query } = parse(response.headers.get('location'));
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

	validateInteraction(eName, ...eReasons) {
		return (response) => {
			const uid = readCookie(getSetCookies(response)[0]);
			const {
				prompt: { name, reasons }
			} = TestAdapter.for('Interaction').syncFind(uid);
			expect(name).to.equal(eName);
			expect(reasons).to.contain.members(eReasons);
		};
	}

	validatePresence(response, properties, all = true) {
		properties =
			!all || properties.includes('id_token') || properties.includes('response')
				? properties
				: [...new Set(properties.concat('iss'))];

		const { query } = parse(response.headers.get('location'), true);
		if (all) {
			expect(query).to.have.keys(properties);
		} else {
			expect(query).to.contain.keys(properties);
		}
		properties.forEach((key) => {
			this.res[key] = query[key];
		});
	}

	validateResponseParameter(response, parameter, expected) {
		const {
			query: { [parameter]: value }
		} = parse(response.headers.get('location'), true);
		if (expected.exec) {
			expect(value).to.match(expected);
		} else {
			expect(value).to.equal(expected);
		}
	}

	validateError(response, expected) {
		return this.validateResponseParameter(response, 'error', expected);
	}

	validateScope(response, expected) {
		return this.validateResponseParameter(response, 'scope', expected);
	}

	validateErrorDescription(response, expected) {
		return this.validateResponseParameter(
			response,
			'error_description',
			expected
		);
	}

	async getToken(code) {
		const isBasicAuth = this.client.token_endpoint_auth_method !== 'none';
		return await AuthorizationRequest.agent.token.post(
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
	}
}

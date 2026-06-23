import { describe, it } from 'bun:test';
import { strict as assert } from 'node:assert';
import * as util from 'node:util';

import { expect } from 'chai';
import merge from 'lodash/merge.js';
import omit from 'lodash/omit.js';
import cloneDeep from 'lodash/cloneDeep.js';

import { provider } from 'lib/provider.js';
import { InvalidClientMetadata } from 'lib/helpers/errors.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import sectorIdentifier from '../../lib/helpers/sector_identifier.ts';
import keys, { stripPrivateJWKFields } from '../keys.js';
import addClient from '../../lib/helpers/add_client.ts';
import { TestAdapter } from '../models.js';
import getConfig from '../default.config.js';

const sigKey = stripPrivateJWKFields(keys[0]);
const privateKey = keys[0];

// The provider is a process-wide singleton configured via `provider.init`
// (there is no `new provider(url, config)` any more). Each `register` call
// re-initialises it from a fresh base so per-test `configuration` overrides
// cannot leak into the next case.
const baseConfig = () => ({
	...getConfig(),
	jwks: { keys },
	adapter: TestAdapter
});

// Some features (PAR, client_credentials) are flat ApplicationConfig flags read
// directly from the global rather than through provider.init's nested config, so
// dotted keys in a test's `configuration` are routed there and reset each call.
const applicationDefaults = { ...ApplicationConfig };

describe('Client metadata validation', () => {
	function register(metadata, configuration) {
		Object.assign(ApplicationConfig, applicationDefaults);
		const initConfig = configuration
			? merge(baseConfig(), cloneDeep(configuration))
			: baseConfig();
		for (const key of Object.keys(initConfig)) {
			if (key.includes('.')) {
				ApplicationConfig[key] = initConfig[key];
				delete initConfig[key];
			}
		}
		provider.init(initConfig);

		return addClient(provider, {
			clientId: 'client',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb'],
			...metadata
		});
	}

	const mustBeString = (
		prop,
		values = [[], 123, true, null, false, {}, ''],
		metadata,
		configuration
	) => {
		values.forEach((value) => {
			let msg = util.format('must be a string, %j provided', value);
			if (metadata)
				msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
			if (configuration)
				msg = util.format(`${msg}, [provider %j]`, configuration);

			it(msg, () =>
				assert.rejects(
					register({ ...metadata, [prop]: value }, configuration),
					(err) => {
						if (prop === 'redirectUris') {
							expect(err.message).to.equal('invalid_redirect_uri');
						} else {
							expect(err.message).to.equal('invalid_client_metadata');
						}
						expect(err.error_description).to.equal(
							`${prop} must be a non-empty string if provided`
						);
						return true;
					}
				)
			);
		});
	};

	const mustBeUri = (prop, protocols, configuration, metadata) => {
		it('must be a uri', () =>
			assert.rejects(
				register(
					{
						...metadata,
						[prop]: 'whatever://not but not a uri'
					},
					configuration
				),
				(err) => {
					if (prop === 'redirectUris') {
						expect(err.message).to.equal('invalid_redirect_uri');
						if (protocols.length === 1 && protocols[0] === 'https') {
							expect(err.error_description).to.equal(
								`${prop} must be a https uri`
							);
						} else {
							expect(err.error_description).to.equal(
								`${prop} must be a web uri`
							);
						}
					} else {
						// URL shape is now enforced by ClientSchema (TypeBox format); the
						// exact description is TypeBox's, so assert the error code only.
						expect(err.message).to.equal('invalid_client_metadata');
					}
					return true;
				}
			));

		protocols.forEach((protocol) => {
			it(`can be ${protocol} uri`, () =>
				register({
					[prop]: `${protocol}://example.com/${prop}`
				}));
		});
	};

	const mustBeArray = (
		prop,
		values = [{}, 'string', 123, true, null, false],
		configuration
	) => {
		values.forEach((value) => {
			let msg = util.format('must be a array, %j provided', value);
			if (configuration)
				msg = util.format(`${msg}, [provider %j]`, configuration);
			it(msg, () =>
				assert.rejects(
					register(
						{
							[prop]: value
						},
						configuration
					),
					(err) => {
						if (prop === 'redirectUris') {
							expect(err.message).to.equal('invalid_redirect_uri');
						} else {
							expect(err.message).to.equal('invalid_client_metadata');
						}
						expect(err.error_description).to.equal(`${prop} must be an array`);
						return true;
					}
				)
			);
		});
	};

	const mustBeBoolean = (prop, metadata, configuration) => {
		[{}, 'string', 123, null, []].forEach((value) => {
			let msg = util.format('must be a boolean, %j provided', value);
			if (metadata)
				msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
			if (configuration)
				msg = util.format(`${msg}, [provider %j]`, configuration);
			it(msg, () =>
				assert.rejects(
					register(
						{
							[prop]: value
						},
						configuration
					),
					(err) => {
						// Boolean type is now enforced by ClientSchema (TypeBox); the exact
						// description is TypeBox's, so assert the error code only.
						expect(err.message).to.equal('invalid_client_metadata');
						return true;
					}
				)
			);
		});
	};

	const defaultsTo = (
		prop,
		value,
		metadata,
		configuration,
		additionalAssertion
	) => {
		let msg = util.format('defaults to %s', value);
		if (metadata)
			msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
		if (configuration)
			msg = util.format(`${msg}, [provider %j]`, configuration);

		it(msg, () =>
			register(metadata, configuration).then((client) => {
				if (value === undefined) {
					expect(client.metadata()).not.to.have.property(prop);
				} else {
					expect(client.metadata()).to.have.property(prop).and.eql(value);
				}

				if (additionalAssertion) {
					return additionalAssertion(client);
				}

				return undefined;
			})
		);
	};

	const isRequired = (prop, values, configuration, metadata) => {
		(values || [null, undefined, '']).forEach((value) => {
			let msg = util.format('is required, %j provided', value);
			if (configuration)
				msg = util.format(`${msg}, [provider %j]`, configuration);
			it(msg, () =>
				assert.rejects(
					register(
						{
							[prop]: value,
							...metadata
						},
						configuration
					),
					(err) => {
						if (prop === 'redirectUris') {
							expect(err.message).to.equal('invalid_redirect_uri');
						} else {
							expect(err.message).to.equal('invalid_client_metadata');
						}
						expect(err.error_description).to.equal(
							`${prop} is mandatory property`
						);
						return true;
					}
				)
			);
		});
	};

	const allows = (
		prop,
		value,
		metadata,
		configuration,
		assertion = (client) => {
			expect(client.metadata()[prop]).to.eql(value);
		}
	) => {
		let msg = util.format('passes %j', value);
		if (metadata)
			msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
		if (configuration)
			msg = util.format(`${msg}, [provider %j]`, configuration);

		it(msg, () =>
			register({ ...metadata, [prop]: value }, configuration).then(
				assertion,
				(err) => {
					if (err instanceof InvalidClientMetadata) {
						throw new Error(
							`InvalidClientMetadata received ${err.message} ${err.error_description}`
						);
					}
				}
			)
		);
	};

	const rejects = (prop, value, description, metadata, configuration) => {
		let msg = util.format('rejects %j', value);
		if (metadata)
			msg = util.format(`${msg}, [client %j]`, omit(metadata, ['jwks.keys']));
		if (configuration)
			msg = util.format(`${msg}, [provider %j]`, configuration);

		it(msg, () =>
			assert.rejects(
				register({ ...metadata, [prop]: value }, configuration),
				(err) => {
					if (prop === 'redirectUris') {
						expect(err.message).to.equal('invalid_redirect_uri');
					} else {
						expect(err.message).to.equal('invalid_client_metadata');
					}
					if (description) {
						expect(err.error_description).to[
							description.exec ? 'match' : 'equal'
						](description);
					}
					return true;
				}
			)
		);
	};

	describe('applicationType', function () {
		defaultsTo('applicationType', 'web');
		mustBeString('applicationType');

		allows('applicationType', 'web');
		allows('applicationType', 'native', {
			redirectUris: ['com.example.myapp:/localhost/redirect']
		});
		rejects(
			'applicationType',
			'foobar',
			"applicationType must be 'native' or 'web'"
		);
	});

	describe('clientId', function () {
		isRequired('clientId');
		mustBeString('clientId', [123, {}, [], true]);

		allows('clientId', 'whatever client id');
		rejects('clientId', '£', 'invalid client_id value');
	});

	describe('client_name', function () {
		mustBeString('client_name');
		allows('client_name', 'whatever client name');
	});

	describe('clientSecret', function () {
		isRequired('clientSecret');
		mustBeString('clientSecret', [123, {}, [], true]);
		allows('clientSecret', 'whatever client secret');
		rejects('clientSecret', '£', 'invalid client_secret value');
		// must of certain length => GOTO: client_secrets.test.js
	});

	describe('contacts', function () {
		mustBeArray('contacts');
		allows('contacts', [
			'developer@example.com',
			'info@example.com',
			'info+some@example.com'
		]);
		rejects('contacts', [123], /must only contain strings$/);
		rejects(
			'contacts',
			['john doe'],
			'contacts can only contain email addresses'
		);
	});

	describe('default_acr_values', function () {
		mustBeArray('default_acr_values');
		const acrValues = ['0', '1', '2'];

		allows('default_acr_values', []);
		acrValues.forEach((value) => {
			allows('default_acr_values', [value], undefined, { acrValues });
		});
		allows('default_acr_values', acrValues, undefined, { acrValues });
		rejects('default_acr_values', [123], /must only contain strings$/);
		rejects(
			'default_acr_values',
			['not a member'],
			'default_acr_values must be empty (no values are allowed)'
		);
		rejects('default_acr_values', [
			'not a member',
			'1',
			'default_acr_values must be empty (no values are allowed)'
		]);
		rejects(
			'default_acr_values',
			['not a member'],
			"default_acr_values can only contain '0', '1', or '2'",
			undefined,
			{ acrValues }
		);
		rejects(
			'default_acr_values',
			['not a member', '1'],
			"default_acr_values can only contain '0', '1', or '2'",
			undefined,
			{ acrValues }
		);
	});

	describe('require_signed_request_object', function () {
		const configuration = (value = false, enabled = true) => ({
			features: {
				requestObjects: {
					enabled,
					requireSignedRequestObject: value
				}
			}
		});
		mustBeBoolean('require_signed_request_object', undefined, configuration());
		defaultsTo(
			'require_signed_request_object',
			undefined,
			undefined,
			configuration(false, false)
		);
		defaultsTo(
			'require_signed_request_object',
			false,
			undefined,
			configuration()
		);
		defaultsTo(
			'require_signed_request_object',
			true,
			undefined,
			configuration(true)
		);
		defaultsTo(
			'require_signed_request_object',
			true,
			{
				require_signed_request_object: false
			},
			configuration(true)
		);
		defaultsTo('require_signed_request_object', true, undefined, {
			...configuration(),
			clientDefaults: { require_signed_request_object: true }
		});
	});

	describe('default_max_age', function () {
		allows('default_max_age', 5);
		allows('default_max_age', 0);
		rejects('default_max_age', Number.MAX_SAFE_INTEGER + 1);
		rejects('default_max_age', -1);
		rejects('default_max_age', true);
		rejects('default_max_age', 'string');
		rejects('default_max_age', {});
		rejects('default_max_age', []);
	});

	describe('grantTypes', function () {
		defaultsTo('grantTypes', ['authorization_code']);
		allows('grantTypes', ['authorization_code', 'refresh_token']);

		// grantTypes structure (an array of strings) is enforced by the TypeBox
		// ClientSchema rather than the schema engine, so a structurally invalid
		// value is rejected with the generic schema validation error.
		it('is rejected by the schema when not an array of strings', () =>
			assert.rejects(
				register({ grantTypes: 123, responseTypes: [] }),
				(err) => {
					expect(err.message).to.equal('invalid_client_metadata');
					expect(err.error_description).to.equal(
						'client metadata validation error'
					);
					return true;
				}
			));

		rejects('grantTypes', []);
		rejects('grantTypes', ['not-a-type']);
		rejects('grantTypes', ['implicit'], undefined, {
			// misses authorization_code
			responseTypes: ['id_token', 'code']
		});
	});

	describe('id_token_signed_response_alg', function () {
		defaultsTo('id_token_signed_response_alg', 'RS256');
		mustBeString('id_token_signed_response_alg');
		rejects('id_token_signed_response_alg', 'none', undefined, {
			responseTypes: ['code id_token']
		});
		rejects('id_token_signed_response_alg', 'none');
	});

	['client_uri', 'logo_uri', 'policy_uri', 'tos_uri'].forEach((prop) => {
		describe(prop, function () {
			mustBeString(prop);
			mustBeUri(prop, ['http', 'https']);
		});
	});

	describe('initiate_login_uri', function () {
		mustBeString('initiate_login_uri');
		mustBeUri('initiate_login_uri', ['https']);
	});

	describe('scope', function () {
		mustBeString('scope');
		allows('scope', undefined);
		allows('scope', 'openid');
		allows('scope', 'offline_access');
		allows('scope', 'openid offline_access');
		allows('scope', 'openid profile', undefined, { scopes: ['profile'] });
		allows('scope', 'openid profile', undefined, {
			claims: { profile: ['given_name'] }
		});
		allows('scope', 'profile', undefined, { scopes: ['profile'] });
		allows('scope', 'profile', undefined, {
			claims: { profile: ['given_name'] }
		});
		rejects(
			'scope',
			'foo',
			'scope must only contain Authorization Server supported scope values'
		);
	});

	describe('redirectUris', function () {
		isRequired('redirectUris');
		mustBeArray('redirectUris', [{}, 'string', 123, true]);
		rejects('redirectUris', [123], /must only contain strings$/);
		rejects('redirectUris', [], /must contain members$/);

		allows('redirectUris', ['http://some'], {
			applicationType: 'web'
		});
		allows('redirectUris', ['https://some'], {
			applicationType: 'web'
		});
		describe('PAR allowUnregisteredRedirectUris', () => {
			allows(
				'redirectUris',
				[],
				{
					'authorization.requirePushedAuthorizationRequests': true
				},
				{
					'par.enabled': true,
					'par.allowUnregisteredRedirectUris': true
				}
			);
			allows(
				'redirectUris',
				[],
				{
					applicationType: 'native',
					'authorization.requirePushedAuthorizationRequests': true
				},
				{
					'par.enabled': true,
					'par.allowUnregisteredRedirectUris': true
				}
			);
			rejects(
				'redirectUris',
				[],
				/redirectUris must contain members/,
				{
					'authorization.requirePushedAuthorizationRequests': true
				},
				{
					'par.enabled': false,
					'par.allowUnregisteredRedirectUris': true
				}
			);
			rejects(
				'redirectUris',
				[],
				/redirectUris must contain members/,
				{
					'authorization.requirePushedAuthorizationRequests': true,
					token_endpoint_auth_method: 'none'
				},
				{
					'par.enabled': true,
					'par.allowUnregisteredRedirectUris': true
				}
			);
			rejects(
				'redirectUris',
				[],
				/redirectUris must contain members/,
				{
					'authorization.requirePushedAuthorizationRequests': true,
					sector_identifier_uri: 'https://foobar.example.com/sector'
				},
				{
					'par.enabled': true,
					'par.allowUnregisteredRedirectUris': true
				}
			);
			rejects(
				'redirectUris',
				[],
				/redirectUris must contain members/,
				{
					'authorization.requirePushedAuthorizationRequests': true
				},
				{
					'par.enabled': true,
					'par.allowUnregisteredRedirectUris': false
				}
			);
			rejects(
				'redirectUris',
				[],
				/redirectUris must contain members/,
				{
					'authorization.requirePushedAuthorizationRequests': false
				},
				{
					'par.enabled': true,
					'par.allowUnregisteredRedirectUris': true
				}
			);
		});
		rejects(
			'redirectUris',
			['https://rp.example.com#whatever'],
			/redirectUris must not contain fragments$/,
			{
				applicationType: 'web'
			}
		);
		rejects('redirectUris', ['no-dot-reverse-notation:/some'], undefined, {
			applicationType: 'web'
		});
		allows('redirectUris', ['http://localhost'], {
			applicationType: 'web'
		});
		rejects('redirectUris', ['http://some'], undefined, {
			applicationType: 'native'
		});
		rejects('redirectUris', ['not-a-uri'], undefined, {
			applicationType: 'native'
		});
	});

	describe('post_logout_redirect_uris', function () {
		defaultsTo('post_logout_redirect_uris', []);
		defaultsTo('post_logout_redirect_uris', undefined, undefined, {
			features: { rpInitiatedLogout: { enabled: false } }
		});
		mustBeArray('post_logout_redirect_uris', [{}, 'string', 123, true]);
		rejects('post_logout_redirect_uris', [123], /must only contain strings$/);

		allows('post_logout_redirect_uris', ['http://some'], {
			applicationType: 'web'
		});
		allows('post_logout_redirect_uris', ['https://some'], {
			applicationType: 'web'
		});
		rejects(
			'post_logout_redirect_uris',
			['https://rp.example.com#whatever'],
			/post_logout_redirect_uris must not contain fragments$/,
			{
				applicationType: 'web'
			}
		);
		rejects(
			'post_logout_redirect_uris',
			['no-dot-reverse-notation:/some'],
			undefined,
			{
				applicationType: 'web'
			}
		);
		rejects('post_logout_redirect_uris', ['https://localhost'], undefined, {
			applicationType: 'web',
			grantTypes: ['implicit', 'authorization_code'],
			responseTypes: ['code id_token']
		});
		allows('post_logout_redirect_uris', ['http://localhost'], {
			applicationType: 'web'
		});
		rejects('post_logout_redirect_uris', ['http://some'], undefined, {
			applicationType: 'native'
		});
		rejects('post_logout_redirect_uris', ['not-a-uri'], undefined, {
			applicationType: 'native'
		});
	});

	describe('requestObject.signingAlg', function () {
		const configuration = {
			features: {
				requestObjects: { enabled: true }
			}
		};
		// Canonical dotted key (Model B), validated by a TypeBox literal union — so
		// non-string / invalid values are rejected by the schema (the exact message is
		// TypeBox's, no longer the engine's "must be a string" text).
		[[], 123, true, null, false, {}, ''].forEach((value) => {
			rejects(
				'requestObject.signingAlg',
				value,
				undefined,
				undefined,
				configuration
			);
		});
		['HS256', 'RS256', 'PS256', 'ES256', 'Ed25519', 'EdDSA'].forEach((alg) => {
			allows(
				'requestObject.signingAlg',
				alg,
				{ jwks: { keys: [sigKey] } },
				configuration
			);
		});
		rejects(
			'requestObject.signingAlg',
			'not-an-alg',
			undefined,
			undefined,
			configuration
		);
		rejects(
			'requestObject.signingAlg',
			'none',
			undefined,
			undefined,
			configuration
		);
	});

	describe('require_auth_time', function () {
		defaultsTo('require_auth_time', false);
		mustBeBoolean('require_auth_time');
	});

	describe('responseTypes', function () {
		defaultsTo('responseTypes', ['code']);

		// responseTypes structure (an array of the code/none enum) is enforced by the
		// TypeBox ClientSchema, so a structurally invalid value is rejected with the
		// generic schema validation error.
		it('is rejected by the schema when not an array', () =>
			assert.rejects(register({ responseTypes: 'string' }), (err) => {
				expect(err.message).to.equal('invalid_client_metadata');
				expect(err.error_description).to.equal(
					'client metadata validation error'
				);
				return true;
			}));

		const responseTypes = ['code', 'none'];
		responseTypes.forEach((value) => {
			const grants = [];
			if (value.includes('code')) {
				grants.push('authorization_code');
			}
			allows(
				'responseTypes',
				[value],
				{
					grantTypes: grants
				},
				{ responseTypes }
			);
		});
		allows(
			'responseTypes',
			responseTypes,
			{
				grantTypes: ['authorization_code']
			},
			{ responseTypes }
		);

		rejects('responseTypes', [123], 'client metadata validation error');
		rejects('responseTypes', [], /must contain members$/);
		rejects('responseTypes', ['not-a-type']);
		rejects('responseTypes', ['not-a-type', 'none']);
	});

	describe('responseModes', function () {
		defaultsTo('responseModes', undefined, undefined, undefined, (client) => {
			expect(client.responseModeAllowed('query')).to.be.true;
			expect(client.responseModeAllowed('fragment')).to.be.true;
			expect(client.responseModeAllowed('form_post')).to.be.true;
		});

		// responseModes structure (an array of the response_mode enum) is enforced by
		// the TypeBox ClientSchema, so a structurally invalid value is rejected with
		// the generic schema validation error.
		it('is rejected by the schema when not an array', () =>
			assert.rejects(register({ responseModes: 'string' }), (err) => {
				expect(err.message).to.equal('invalid_client_metadata');
				expect(err.error_description).to.equal(
					'client metadata validation error'
				);
				return true;
			}));

		allows('responseModes', ['query', 'form_post']);
		allows('responseModes', ['query']);
		allows('responseModes', ['form_post']);

		// 'fragment' is not a registrable response_mode in this codebase's
		// ClientSchema; responseModeAllowed still treats an absent list as
		// allowing it (the `!== false` rule), exercised by the defaultsTo above.
		allows('responseModes', ['query'], undefined, undefined, (client) => {
			expect(client.responseModeAllowed('query')).to.be.true;
			expect(client.responseModeAllowed('form_post')).to.be.false;
		});

		allows('responseModes', ['jwt'], undefined, {
			features: { jwtResponseModes: { enabled: true } }
		});
		allows('responseModes', ['jwt.query'], undefined, {
			features: { jwtResponseModes: { enabled: true } }
		});
		allows('responseModes', ['jwt.form_post'], undefined, {
			features: { jwtResponseModes: { enabled: true } }
		});

		rejects('responseModes', [123], 'client metadata validation error');
		rejects('responseModes', [], /must contain members$/);
		rejects('responseModes', ['not-a-mode']);
		rejects('responseModes', ['not-a-mode']);
	});

	describe('sector_identifier_uri', function () {
		mustBeString('sector_identifier_uri');
		// must be a valid sector uri => GOTO: pairwise_clients.test.js
	});

	describe('subjectType', function () {
		defaultsTo('subjectType', 'public');
		// This codebase fixes subject_types_supported to ['public','pairwise'];
		// there is no `subjectTypes` configuration option to change the default.
		mustBeString('subjectType');
		allows('subjectType', 'public');
		rejects('subjectType', 'not-a-type');
	});

	{
		const configuration = {
			clientAuthMethods: [
				'none',
				'client_secret_basic',
				'client_secret_post',
				'private_key_jwt',
				'client_secret_jwt',
				'tls_client_auth'
			],
			features: {
				mTLS: {
					enabled: true,
					selfSignedTlsClientAuth: true,
					tlsClientAuth: true
				}
			}
		};

		describe('token_endpoint_auth_method', function () {
			defaultsTo(
				'token_endpoint_auth_method',
				'client_secret_basic',
				undefined,
				configuration
			);
			mustBeString(
				'token_endpoint_auth_method',
				undefined,
				undefined,
				configuration
			);
			rejects(
				'token_endpoint_auth_method',
				'foo',
				'token_endpoint_auth_method must not be provided (no values are allowed)',
				undefined,
				{
					...configuration,
					clientAuthMethods: []
				}
			);

			[
				'client_secret_basic',
				'client_secret_jwt',
				'client_secret_post',
				'private_key_jwt',
				'tls_client_auth'
			].forEach((value) => {
				switch (value) {
					case 'private_key_jwt':
						allows(
							'token_endpoint_auth_method',
							value,
							{
								jwks: { keys: [sigKey] }
							},
							configuration
						);
						break;
					case 'tls_client_auth':
						allows(
							'token_endpoint_auth_method',
							value,
							{
								tls_client_auth_subject_dn: 'foo'
							},
							configuration
						);
						allows(
							'token_endpoint_auth_method',
							value,
							{
								tls_client_auth_san_dns: 'foo'
							},
							configuration
						);
						allows(
							'token_endpoint_auth_method',
							value,
							{
								tls_client_auth_san_uri: 'foo'
							},
							configuration
						);
						allows(
							'token_endpoint_auth_method',
							value,
							{
								tls_client_auth_san_ip: 'foo'
							},
							configuration
						);
						allows(
							'token_endpoint_auth_method',
							value,
							{
								tls_client_auth_san_email: 'foo'
							},
							configuration
						);
						rejects(
							'token_endpoint_auth_method',
							value,
							'tls_client_auth requires one of the certificate subject value parameters',
							undefined,
							configuration
						);
						rejects(
							'token_endpoint_auth_method',
							value,
							'only one tls_client_auth certificate subject value must be provided',
							{
								tls_client_auth_san_ip: 'foo',
								tls_client_auth_san_email: 'foo'
							},
							configuration
						);
						break;
					default: {
						allows(
							'token_endpoint_auth_method',
							value,
							undefined,
							configuration
						);
					}
				}
			});
			rejects(
				'token_endpoint_auth_method',
				'not-a-method',
				undefined,
				undefined,
				configuration
			);
		});

		describe('token_endpoint_auth_signing_alg', function () {
			rejects('token_endpoint_auth_signing_alg', 'none');
			Object.entries({
				client_secret_jwt: ['HS', 'RS'],
				private_key_jwt: ['RS', 'HS', { jwks: { keys: [sigKey] } }]
			}).forEach(([method, [accepted, rejected, additional]]) => {
				allows(
					'token_endpoint_auth_signing_alg',
					`${accepted}256`,
					{
						token_endpoint_auth_method: method,
						...additional
					},
					configuration
				);

				rejects(
					'token_endpoint_auth_signing_alg',
					`${rejected}256`,
					/^token_endpoint_auth_signing_alg must be/,
					{
						token_endpoint_auth_method: method,
						...additional
					},
					configuration
				);
			});
		});
	}

	describe('userinfo_signed_response_alg', function () {
		const configuration = { features: { jwtUserinfo: { enabled: true } } };
		defaultsTo(
			'userinfo_signed_response_alg',
			undefined,
			undefined,
			configuration
		);
		mustBeString(
			'userinfo_signed_response_alg',
			undefined,
			undefined,
			configuration
		);
		allows('userinfo_signed_response_alg', 'HS256', undefined, configuration);
		rejects(
			'userinfo_signed_response_alg',
			'not-an-alg',
			undefined,
			undefined,
			configuration
		);
		rejects(
			'userinfo_signed_response_alg',
			'none',
			undefined,
			undefined,
			configuration
		);
		rejects(
			'userinfo_signed_response_alg',
			undefined,
			'userinfo_signed_response_alg is mandatory property when userinfo_encrypted_response_alg is provided',
			{ userinfo_encrypted_response_alg: 'dir' },
			merge({ features: { encryption: { enabled: true } } }, configuration)
		);
	});

	describe('introspection_signed_response_alg', function () {
		const configuration = {
			features: {
				introspection: { enabled: true },
				jwtIntrospection: { enabled: true }
			}
		};
		defaultsTo(
			'introspection_signed_response_alg',
			'RS256',
			undefined,
			configuration
		);
		mustBeString(
			'introspection_signed_response_alg',
			undefined,
			undefined,
			configuration
		);
		allows(
			'introspection_signed_response_alg',
			'HS256',
			undefined,
			configuration
		);
		rejects(
			'introspection_signed_response_alg',
			'not-an-alg',
			undefined,
			undefined,
			configuration
		);
		rejects(
			'introspection_signed_response_alg',
			'none',
			undefined,
			undefined,
			configuration
		);
	});

	describe('authorization_signed_response_alg', function () {
		const configuration = { features: { jwtResponseModes: { enabled: true } } };
		defaultsTo(
			'authorization_signed_response_alg',
			'RS256',
			undefined,
			configuration
		);
		mustBeString(
			'authorization_signed_response_alg',
			undefined,
			undefined,
			configuration
		);
		allows(
			'authorization_signed_response_alg',
			'HS256',
			undefined,
			configuration
		);
		rejects(
			'authorization_signed_response_alg',
			'not-an-alg',
			undefined,
			undefined,
			configuration
		);
		rejects(
			'authorization_signed_response_alg',
			'none',
			undefined,
			undefined,
			configuration
		);
	});

	describe('features.encryption', () => {
		const configuration = {
			features: {
				encryption: { enabled: true },
				introspection: { enabled: true },
				jwtIntrospection: { enabled: true },
				jwtResponseModes: { enabled: true },
				jwtUserinfo: { enabled: true }
			}
		};

		describe('id_token_encrypted_response_alg', function () {
			defaultsTo('id_token_encrypted_response_alg', undefined);
			defaultsTo(
				'id_token_encrypted_response_alg',
				undefined,
				undefined,
				configuration
			);
			mustBeString(
				'id_token_encrypted_response_alg',
				undefined,
				{
					jwks: { keys: [sigKey] }
				},
				configuration
			);
			it('is required when id_token_encrypted_response_enc is also provided', () =>
				assert.rejects(
					register(
						{
							id_token_encrypted_response_enc: 'whatever'
						},
						configuration
					),
					(err) => {
						expect(err.message).to.equal('invalid_client_metadata');
						expect(err.error_description).to.equal(
							'id_token_encrypted_response_alg is mandatory property when id_token_encrypted_response_enc is provided'
						);
						return true;
					}
				));
			allows(
				'id_token_encrypted_response_alg',
				'dir',
				undefined,
				configuration
			);
			['RSA-OAEP', 'RSA-OAEP-256', 'ECDH-ES', 'A128KW', 'A256KW'].forEach(
				(value) => {
					allows(
						'id_token_encrypted_response_alg',
						value,
						{
							jwks: { keys: [sigKey] }
						},
						configuration
					);
				}
			);
			rejects(
				'id_token_encrypted_response_alg',
				'not-an-alg',
				undefined,
				undefined,
				configuration
			);
			rejects(
				'id_token_encrypted_response_alg',
				'none',
				undefined,
				undefined,
				configuration
			);
		});

		describe('id_token_encrypted_response_enc', function () {
			defaultsTo('id_token_encrypted_response_enc', undefined);
			defaultsTo(
				'id_token_encrypted_response_enc',
				'A128CBC-HS256',
				{
					['id_token_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
			mustBeString(
				'id_token_encrypted_response_enc',
				undefined,
				{
					['id_token_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
			['A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
				(value) => {
					allows(
						'id_token_encrypted_response_enc',
						value,
						{
							['id_token_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
								'RSA-OAEP',
							jwks: { keys: [sigKey] }
						},
						configuration
					);
					allows(
						'id_token_encrypted_response_enc',
						value,
						{
							['id_token_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
								'dir'
						},
						configuration
					);
				}
			);
			rejects(
				'id_token_encrypted_response_enc',
				'not-an-enc',
				undefined,
				{
					['id_token_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
		});

		describe('userinfo_encrypted_response_alg', function () {
			const metadata = {
				jwks: { keys: [sigKey] },
				userinfo_signed_response_alg: 'RS256'
			};
			defaultsTo('userinfo_encrypted_response_alg', undefined);
			defaultsTo(
				'userinfo_encrypted_response_alg',
				undefined,
				undefined,
				configuration
			);
			mustBeString(
				'userinfo_encrypted_response_alg',
				undefined,
				metadata,
				configuration
			);
			it('is required when userinfo_encrypted_response_enc is also provided', () =>
				assert.rejects(
					register(
						{
							userinfo_encrypted_response_enc: 'whatever'
						},
						configuration
					),
					(err) => {
						expect(err.message).to.equal('invalid_client_metadata');
						expect(err.error_description).to.equal(
							'userinfo_encrypted_response_alg is mandatory property when userinfo_encrypted_response_enc is provided'
						);
						return true;
					}
				));
			allows('userinfo_encrypted_response_alg', 'dir', metadata, configuration);
			['RSA-OAEP', 'RSA-OAEP-256', 'ECDH-ES', 'A128KW', 'A256KW'].forEach(
				(value) => {
					allows(
						'userinfo_encrypted_response_alg',
						value,
						metadata,
						configuration
					);
				}
			);
			rejects(
				'userinfo_encrypted_response_alg',
				'not-an-alg',
				undefined,
				undefined,
				configuration
			);
			rejects(
				'userinfo_encrypted_response_alg',
				'none',
				undefined,
				undefined,
				configuration
			);
		});

		describe('userinfo_encrypted_response_enc', function () {
			defaultsTo('userinfo_encrypted_response_enc', undefined);
			defaultsTo(
				'userinfo_encrypted_response_enc',
				undefined,
				undefined,
				configuration
			);
			defaultsTo(
				'userinfo_encrypted_response_enc',
				'A128CBC-HS256',
				{
					['userinfo_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					['userinfo_encrypted_response_enc'
						.replace('encrypted', 'signed')
						.replace('_enc', '_alg')]: 'RS256',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
			mustBeString(
				'userinfo_encrypted_response_enc',
				undefined,
				{
					['userinfo_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					['userinfo_encrypted_response_enc'
						.replace('encrypted', 'signed')
						.replace('_enc', '_alg')]: 'RS256',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
			['A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
				(value) => {
					allows(
						'userinfo_encrypted_response_enc',
						value,
						{
							['userinfo_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
								'RSA-OAEP',
							['userinfo_encrypted_response_enc'
								.replace('encrypted', 'signed')
								.replace('_enc', '_alg')]: 'RS256',
							jwks: { keys: [sigKey] }
						},
						configuration
					);
					allows(
						'userinfo_encrypted_response_enc',
						value,
						{
							['userinfo_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
								'dir',
							['userinfo_encrypted_response_enc'
								.replace('encrypted', 'signed')
								.replace('_enc', '_alg')]: 'RS256'
						},
						configuration
					);
				}
			);
			rejects(
				'userinfo_encrypted_response_enc',
				'not-an-enc',
				undefined,
				{
					['userinfo_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					['userinfo_encrypted_response_enc'
						.replace('encrypted', 'signed')
						.replace('_enc', '_alg')]: 'RS256',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
		});

		describe('introspection_encrypted_response_alg', function () {
			const metadata = {
				jwks: { keys: [sigKey] },
				introspection_signed_response_alg: 'RS256'
			};
			defaultsTo('introspection_encrypted_response_alg', undefined);
			defaultsTo(
				'introspection_encrypted_response_alg',
				undefined,
				undefined,
				configuration
			);
			mustBeString(
				'introspection_encrypted_response_alg',
				undefined,
				metadata,
				configuration
			);
			it('is required when introspection_encrypted_response_enc is also provided', () =>
				assert.rejects(
					register(
						{
							introspection_encrypted_response_enc: 'whatever'
						},
						configuration
					),
					(err) => {
						expect(err.message).to.equal('invalid_client_metadata');
						expect(err.error_description).to.equal(
							'introspection_encrypted_response_alg is mandatory property when introspection_encrypted_response_enc is provided'
						);
						return true;
					}
				));
			allows(
				'introspection_encrypted_response_alg',
				'dir',
				metadata,
				configuration
			);
			['RSA-OAEP', 'RSA-OAEP-256', 'ECDH-ES', 'A128KW', 'A256KW'].forEach(
				(value) => {
					allows(
						'introspection_encrypted_response_alg',
						value,
						metadata,
						configuration
					);
				}
			);
			rejects(
				'introspection_encrypted_response_alg',
				'not-an-alg',
				undefined,
				undefined,
				configuration
			);
			rejects(
				'introspection_encrypted_response_alg',
				'none',
				undefined,
				undefined,
				configuration
			);
		});

		describe('introspection_encrypted_response_enc', function () {
			defaultsTo('introspection_encrypted_response_enc', undefined);
			defaultsTo(
				'introspection_encrypted_response_enc',
				undefined,
				undefined,
				configuration
			);
			defaultsTo(
				'introspection_encrypted_response_enc',
				'A128CBC-HS256',
				{
					['introspection_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
			mustBeString(
				'introspection_encrypted_response_enc',
				undefined,
				{
					['introspection_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
			['A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
				(value) => {
					allows(
						'introspection_encrypted_response_enc',
						value,
						{
							['introspection_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
								'RSA-OAEP',
							jwks: { keys: [sigKey] }
						},
						configuration
					);
					allows(
						'introspection_encrypted_response_enc',
						value,
						{
							['introspection_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
								'dir'
						},
						configuration
					);
				}
			);
			rejects(
				'introspection_encrypted_response_enc',
				'not-an-enc',
				undefined,
				{
					['introspection_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
		});

		describe('authorization_encrypted_response_alg', function () {
			const metadata = {
				jwks: { keys: [sigKey] },
				authorization_signed_response_alg: 'RS256'
			};
			defaultsTo('authorization_encrypted_response_alg', undefined);
			defaultsTo(
				'authorization_encrypted_response_alg',
				undefined,
				undefined,
				configuration
			);
			mustBeString(
				'authorization_encrypted_response_alg',
				undefined,
				metadata,
				configuration
			);
			it('is required when authorization_encrypted_response_enc is also provided', () =>
				assert.rejects(
					register(
						{
							authorization_encrypted_response_enc: 'whatever'
						},
						configuration
					),
					(err) => {
						expect(err.message).to.equal('invalid_client_metadata');
						expect(err.error_description).to.equal(
							'authorization_encrypted_response_alg is mandatory property when authorization_encrypted_response_enc is provided'
						);
						return true;
					}
				));
			allows(
				'authorization_encrypted_response_alg',
				'dir',
				metadata,
				configuration
			);
			['RSA-OAEP', 'RSA-OAEP-256', 'ECDH-ES', 'A128KW', 'A256KW'].forEach(
				(value) => {
					allows(
						'authorization_encrypted_response_alg',
						value,
						metadata,
						configuration
					);
				}
			);
			rejects(
				'authorization_encrypted_response_alg',
				'not-an-alg',
				undefined,
				undefined,
				configuration
			);
			rejects(
				'authorization_encrypted_response_alg',
				'none',
				undefined,
				undefined,
				configuration
			);
		});

		describe('authorization_encrypted_response_enc', function () {
			defaultsTo('authorization_encrypted_response_enc', undefined);
			defaultsTo(
				'authorization_encrypted_response_enc',
				undefined,
				undefined,
				configuration
			);
			defaultsTo(
				'authorization_encrypted_response_enc',
				'A128CBC-HS256',
				{
					['authorization_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
			mustBeString(
				'authorization_encrypted_response_enc',
				undefined,
				{
					['authorization_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
			['A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
				(value) => {
					allows(
						'authorization_encrypted_response_enc',
						value,
						{
							['authorization_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
								'RSA-OAEP',
							jwks: { keys: [sigKey] }
						},
						configuration
					);
					allows(
						'authorization_encrypted_response_enc',
						value,
						{
							['authorization_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
								'dir'
						},
						configuration
					);
				}
			);
			rejects(
				'authorization_encrypted_response_enc',
				'not-an-enc',
				undefined,
				{
					['authorization_encrypted_response_enc'.replace(/(enc$)/, 'alg')]:
						'RSA-OAEP',
					jwks: { keys: [sigKey] }
				},
				configuration
			);
		});
	});

	describe('features.encryption & features.request', () => {
		const configuration = {
			features: {
				encryption: { enabled: true },
				requestObjects: { enabled: true }
			}
		};
		describe('request_object_encryption_alg', function () {
			defaultsTo('request_object_encryption_alg', undefined);
			defaultsTo(
				'request_object_encryption_alg',
				undefined,
				undefined,
				configuration
			);
			mustBeString(
				'request_object_encryption_alg',
				undefined,
				undefined,
				configuration
			);
			it('is required when request_object_encryption_enc is also provided', () =>
				assert.rejects(
					register(
						{
							request_object_encryption_enc: 'whatever'
						},
						configuration
					),
					(err) => {
						expect(err.message).to.equal('invalid_client_metadata');
						expect(err.error_description).to.equal(
							'request_object_encryption_alg is mandatory property when request_object_encryption_enc is provided'
						);
						return true;
					}
				));
			allows('request_object_encryption_alg', 'dir', undefined, configuration);
			['A128KW', 'A256KW'].forEach((value) => {
				allows(
					'request_object_encryption_alg',
					value,
					undefined,
					configuration
				);
			});
			rejects(
				'request_object_encryption_alg',
				'not-an-alg',
				undefined,
				undefined,
				configuration
			);
			rejects(
				'request_object_encryption_alg',
				'none',
				undefined,
				undefined,
				configuration
			);
		});

		describe('request_object_encryption_enc', function () {
			defaultsTo('request_object_encryption_enc', undefined);
			defaultsTo(
				'request_object_encryption_enc',
				undefined,
				undefined,
				configuration
			);
			defaultsTo(
				'request_object_encryption_enc',
				'A128CBC-HS256',
				{
					['request_object_encryption_enc'.replace(/(enc$)/, 'alg')]: 'A128KW'
				},
				configuration
			);
			mustBeString(
				'request_object_encryption_enc',
				undefined,
				{
					['request_object_encryption_enc'.replace(/(enc$)/, 'alg')]: 'A128KW'
				},
				configuration
			);
			['A128CBC-HS256', 'A128GCM', 'A256CBC-HS512', 'A256GCM'].forEach(
				(value) => {
					allows(
						'request_object_encryption_enc',
						value,
						{
							['request_object_encryption_enc'.replace(/(enc$)/, 'alg')]:
								'A128KW'
						},
						configuration
					);
					allows(
						'request_object_encryption_enc',
						value,
						{
							['request_object_encryption_enc'.replace(/(enc$)/, 'alg')]: 'dir'
						},
						configuration
					);
				}
			);
			rejects(
				'request_object_encryption_enc',
				'not-an-enc',
				undefined,
				{
					['request_object_encryption_enc'.replace(/(enc$)/, 'alg')]: 'A128KW'
				},
				configuration
			);
		});
	});

	describe('features.pushedAuthorizationRequests', () => {
		// QUARANTINED (codebase divergence): upstream's
		// `require_pushed_authorization_requests` boolean client-metadata property
		// and its provider forcing-flag are modelled differently here — the client
		// property is `authorization.requirePushedAuthorizationRequests` (a dotted
		// camelCase key validated by ClientSchema, not via the snake BOOL pass) and
		// PAR is configured through the flat `par.*` keys. Its registration-time
		// effect (allowing unregistered redirect URIs) is covered by the
		// `redirectUris > PAR allowUnregisteredRedirectUris` cases above and by
		// pushed_authorization_requests.spec.ts.
		describe.skip('require_pushed_authorization_requests', function () {});
	});

	describe('features.ciba', () => {
		const configuration = {
			features: {
				ciba: { enabled: true, deliveryModes: ['ping', 'poll'] }
			}
		};
		const metadata = {
			grantTypes: ['urn:openid:params:grant-type:ciba'],
			redirectUris: [],
			responseTypes: [],
			backchannel_token_delivery_mode: 'poll'
		};

		describe('backchannel_user_code_parameter', function () {
			mustBeBoolean(
				'backchannel_user_code_parameter',
				undefined,
				configuration
			);
			defaultsTo(
				'backchannel_user_code_parameter',
				false,
				undefined,
				configuration
			);
		});

		describe('backchannel_token_delivery_mode', function () {
			mustBeString(
				'backchannel_token_delivery_mode',
				undefined,
				undefined,
				configuration
			);
			isRequired('backchannel_token_delivery_mode', undefined, configuration, {
				...metadata,
				backchannel_token_delivery_mode: undefined
			});
		});

		describe('backchannel_client_notification_endpoint', function () {
			isRequired(
				'backchannel_client_notification_endpoint',
				undefined,
				configuration,
				{
					...metadata,
					backchannel_token_delivery_mode: 'ping'
				}
			);
			mustBeUri(
				'backchannel_client_notification_endpoint',
				['https'],
				configuration,
				{
					...metadata,
					backchannel_token_delivery_mode: 'ping'
				}
			);
		});

		describe('requestObject.backChannelSigningAlg', function () {
			const withRequestObjects = merge({}, configuration, {
				features: { requestObjects: { enabled: true } }
			});
			// Canonical dotted key (Model B), validated by a TypeBox literal union of the
			// asymmetric algorithms; non-string / invalid values are rejected by the schema.
			[[], 123, true, null, false, {}, ''].forEach((value) => {
				rejects(
					'requestObject.backChannelSigningAlg',
					value,
					undefined,
					metadata,
					withRequestObjects
				);
			});
			['RS256', 'PS256', 'ES256', 'Ed25519', 'EdDSA'].forEach((alg) => {
				allows(
					'requestObject.backChannelSigningAlg',
					alg,
					{ ...metadata, jwks: { keys: [sigKey] } },
					withRequestObjects
				);
			});
			rejects(
				'requestObject.backChannelSigningAlg',
				'not-an-alg',
				undefined,
				metadata,
				withRequestObjects
			);
			rejects(
				'requestObject.backChannelSigningAlg',
				'none',
				undefined,
				metadata,
				withRequestObjects
			);
			rejects(
				'requestObject.backChannelSigningAlg',
				'HS256',
				undefined,
				metadata,
				withRequestObjects
			);
			rejects(
				'requestObject.backChannelSigningAlg',
				'HS384',
				undefined,
				metadata,
				withRequestObjects
			);
			rejects(
				'requestObject.backChannelSigningAlg',
				'HS512',
				undefined,
				metadata,
				withRequestObjects
			);
			defaultsTo(
				'requestObject.backChannelSigningAlg',
				undefined,
				undefined,
				withRequestObjects
			);
		});

		allows(
			'subjectType',
			'pairwise',
			{
				...metadata,
				token_endpoint_auth_method: 'private_key_jwt',
				subjectType: 'pairwise',
				jwks_uri: 'https://rp.example.com/jwks'
			},
			{ ...configuration, subjectTypes: ['pairwise', 'public'] },
			(client) => {
				expect(sectorIdentifier(client)).to.eql('rp.example.com');
			}
		);
		isRequired(
			'jwks_uri',
			[undefined],
			{ ...configuration, subjectTypes: ['pairwise', 'public'] },
			{ ...metadata, subjectType: 'pairwise' }
		);
		isRequired(
			'sector_identifier_uri',
			[undefined],
			{ ...configuration, subjectTypes: ['pairwise', 'public'] },
			{
				...metadata,
				jwks_uri: 'https://rp.example.com/sector',
				subjectType: 'pairwise',
				responseTypes: ['code'],
				grantTypes: [...metadata.grantTypes, 'authorization_code'],
				redirectUris: ['https://rp.example.com/cb']
			}
		);
		rejects(
			'subjectType',
			'pairwise',
			'pairwise urn:openid:params:grant-type:ciba clients must utilize private_key_jwt or self_signed_tls_client_auth token endpoint authentication methods',
			{
				...metadata,
				subjectType: 'pairwise',
				jwks_uri: 'https://rp.example.com/jwks'
			},
			{ ...configuration, subjectTypes: ['pairwise', 'public'] }
		);
	});

	describe('features.deviceFlow', () => {
		const configuration = { features: { deviceFlow: { enabled: true } } };
		const metadata = {
			grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
			responseTypes: [],
			redirectUris: undefined
		};

		defaultsTo('redirectUris', [], metadata, configuration);
		// `clientDefaults` only overrides recognised (snake_case) metadata defaults;
		// it does not apply to the camelCase base key `redirectUris` in this codebase.
		rejects(
			'redirectUris',
			null,
			'redirectUris must be an array',
			metadata,
			configuration
		);
		allows(
			'subjectType',
			'pairwise',
			{
				...metadata,
				token_endpoint_auth_method: 'private_key_jwt',
				subjectType: 'pairwise',
				jwks_uri: 'https://rp.example.com/jwks'
			},
			{ ...configuration, subjectTypes: ['pairwise', 'public'] },
			(client) => {
				expect(sectorIdentifier(client)).to.eql('rp.example.com');
			}
		);
		isRequired(
			'jwks_uri',
			[undefined],
			{ ...configuration, subjectTypes: ['pairwise', 'public'] },
			{ ...metadata, subjectType: 'pairwise' }
		);
		isRequired(
			'sector_identifier_uri',
			[undefined],
			{ ...configuration, subjectTypes: ['pairwise', 'public'] },
			{
				...metadata,
				jwks_uri: 'https://rp.example.com/sector',
				subjectType: 'pairwise',
				responseTypes: ['code'],
				grantTypes: [...metadata.grantTypes, 'authorization_code'],
				redirectUris: ['https://rp.example.com/cb']
			}
		);
		rejects(
			'subjectType',
			'pairwise',
			'pairwise urn:ietf:params:oauth:grant-type:device_code clients must utilize private_key_jwt or self_signed_tls_client_auth token endpoint authentication methods',
			{
				...metadata,
				subjectType: 'pairwise',
				jwks_uri: 'https://rp.example.com/jwks'
			},
			{ ...configuration, subjectTypes: ['pairwise', 'public'] }
		);
	});

	describe('features.clientCredentials', () => {
		const configuration = {
			'clientCredentials.enabled': true
		};
		const metadata = {
			grantTypes: ['client_credentials'],
			responseTypes: [],
			redirectUris: undefined
		};

		defaultsTo('redirectUris', [], metadata, configuration);
		// `clientDefaults` does not override the camelCase base key `redirectUris`.
		rejects(
			'redirectUris',
			null,
			'redirectUris must be an array',
			metadata,
			configuration
		);
	});

	describe('jwks', function () {
		const configuration = {
			features: {
				introspection: { enabled: true },
				jwtIntrospection: { enabled: true },
				revocation: { enabled: true },
				encryption: { enabled: true },
				jwtUserinfo: { enabled: true },
				ciba: { enabled: true },
				requestObjects: { enabled: true }
			}
		};

		[false, Boolean, 'foo', 123, null].forEach((value) => {
			rejects('jwks', { keys: [value] }, 'client metadata validation error');
		});

		[{ kty: null }, { kty: '' }].forEach((value) => {
			rejects('jwks', { keys: [value] }, 'client JSON Web Key Set is invalid');
		});
		rejects('jwks', 'string', 'client metadata validation error');
		rejects('jwks', null, 'client metadata validation error');
		rejects('jwks', {}, 'client metadata validation error');
		rejects('jwks', 1, 'client metadata validation error');
		rejects('jwks', 0, 'client metadata validation error');
		rejects('jwks', true, 'client metadata validation error');
		rejects(
			'jwks',
			{ keys: [privateKey] },
			'client JSON Web Key Set is invalid'
		);
		rejects(
			'jwks',
			{
				keys: [{ k: '6vl9Rlk88HO8onFHq0ZvTtga68vkUr-bRZ2Hvxu-rAw', kty: 'oct' }]
			},
			'client JSON Web Key Set is invalid'
		);
		rejects(
			'jwks',
			{
				keys: [
					{ kty: 'oct', kid: 'jf1nb1YotqxK9viWsXMsngnTCmO2r3w_moVIPtaf8wU' }
				]
			},
			'client JSON Web Key Set is invalid'
		);
		allows('jwks', { keys: [{ kty: 'unrecognized' }] });
		allows('jwks', { keys: [] });
		rejects(
			'jwks',
			undefined,
			'jwks or jwks_uri is mandatory for this client',
			{
				token_endpoint_auth_method: 'private_key_jwt'
			},
			configuration
		);

		for (const prop of [
			'requestObject.signingAlg',
			'requestObject.backChannelSigningAlg'
		]) {
			rejects(
				'jwks',
				undefined,
				'jwks or jwks_uri is mandatory for this client',
				{
					[prop]: 'RS256'
				},
				configuration
			);
			rejects(
				'jwks',
				undefined,
				'jwks or jwks_uri is mandatory for this client',
				{
					[prop]: 'ES384'
				},
				configuration
			);
		}

		[
			'id_token_encrypted_response_alg',
			'userinfo_encrypted_response_alg',
			'introspection_encrypted_response_alg'
		].forEach((prop) => {
			[
				'RSA-OAEP',
				'ECDH-ES',
				'ECDH-ES+A128KW',
				'ECDH-ES+A192KW',
				'ECDH-ES+A256KW'
			].forEach((alg) => {
				rejects(
					'jwks',
					undefined,
					'jwks or jwks_uri is mandatory for this client',
					{
						[prop]: alg,
						[prop.replace('encrypted', 'signed')]: 'RS256'
					},
					configuration
				);
			});
		});
	});

	describe('features.backchannelLogout', () => {
		const configuration = {
			features: {
				backchannelLogout: { enabled: true }
			}
		};

		describe('backchannel_logout_uri', function () {
			defaultsTo('backchannel_logout_uri', undefined);
			mustBeString(
				'backchannel_logout_uri',
				undefined,
				undefined,
				configuration
			);
			mustBeUri('backchannel_logout_uri', ['http', 'https'], configuration);
		});

		describe('backchannel_logout_session_required', function () {
			defaultsTo('backchannel_logout_session_required', undefined);
			defaultsTo(
				'backchannel_logout_session_required',
				false,
				undefined,
				configuration
			);
			mustBeBoolean(
				'backchannel_logout_session_required',
				undefined,
				configuration
			);
		});
	});

	{
		const configuration = {
			features: {
				mTLS: { enabled: true, tlsClientAuth: true },
				revocation: { enabled: true },
				introspection: { enabled: true }
			},
			clientAuthMethods: ['tls_client_auth', 'client_secret_basic']
		};

		describe('tls_client_auth_subject_dn', function () {
			mustBeString(
				'tls_client_auth_subject_dn',
				undefined,
				undefined,
				configuration
			);
			allows(
				'tls_client_auth_subject_dn',
				'foo',
				{
					token_endpoint_auth_method: 'tls_client_auth'
				},
				configuration
			);
			allows(
				'tls_client_auth_subject_dn',
				'foo',
				undefined,
				configuration,
				(client) => {
					expect(client.metadata()['tls_client_auth_subject_dn']).to.eql(
						undefined
					);
				}
			);
		});

		describe('tls_client_auth_san_dns', function () {
			mustBeString(
				'tls_client_auth_san_dns',
				undefined,
				undefined,
				configuration
			);
			allows(
				'tls_client_auth_san_dns',
				'foo',
				{
					token_endpoint_auth_method: 'tls_client_auth'
				},
				configuration
			);
			allows(
				'tls_client_auth_san_dns',
				'foo',
				undefined,
				configuration,
				(client) => {
					expect(client.metadata()['tls_client_auth_san_dns']).to.eql(
						undefined
					);
				}
			);
		});

		describe('tls_client_auth_san_uri', function () {
			mustBeString(
				'tls_client_auth_san_uri',
				undefined,
				undefined,
				configuration
			);
			allows(
				'tls_client_auth_san_uri',
				'foo',
				{
					token_endpoint_auth_method: 'tls_client_auth'
				},
				configuration
			);
			allows(
				'tls_client_auth_san_uri',
				'foo',
				undefined,
				configuration,
				(client) => {
					expect(client.metadata()['tls_client_auth_san_uri']).to.eql(
						undefined
					);
				}
			);
		});

		describe('tls_client_auth_san_ip', function () {
			mustBeString(
				'tls_client_auth_san_ip',
				undefined,
				undefined,
				configuration
			);
			allows(
				'tls_client_auth_san_ip',
				'foo',
				{
					token_endpoint_auth_method: 'tls_client_auth'
				},
				configuration
			);
			allows(
				'tls_client_auth_san_ip',
				'foo',
				undefined,
				configuration,
				(client) => {
					expect(client.metadata()['tls_client_auth_san_ip']).to.eql(undefined);
				}
			);
		});

		describe('tls_client_auth_san_email', function () {
			mustBeString(
				'tls_client_auth_san_email',
				undefined,
				undefined,
				configuration
			);
			allows(
				'tls_client_auth_san_email',
				'foo',
				{
					token_endpoint_auth_method: 'tls_client_auth'
				},
				configuration
			);
			allows(
				'tls_client_auth_san_email',
				'foo',
				undefined,
				configuration,
				(client) => {
					expect(client.metadata()['tls_client_auth_san_email']).to.eql(
						undefined
					);
				}
			);
		});
	}

	describe('jwks_uri', function () {
		mustBeString('jwks_uri');

		// more in client_keystore.test.js
	});

	it('allows unrecognized properties but does not yield them back', () =>
		register({
			unrecognized: true
		}).then((client) => {
			expect(client).not.to.have.property('unrecognized');
		}));

	it('allows clients without grants, for introspection, revocation (RS clients)', () =>
		register({
			clientId: 'authorization-server',
			clientSecret: 'foobar',
			redirectUris: [],
			responseTypes: [],
			grantTypes: []
		}).then((client) => {
			expect(client.grantTypes).to.be.empty;
			expect(client.responseTypes).to.be.empty;
			expect(client.redirectUris).to.be.empty;
		}));

	it('allows clients only with client_credentials', () =>
		register(
			{
				clientId: 'resource-server',
				clientSecret: 'foobar',
				redirectUris: [],
				responseTypes: [],
				grantTypes: ['client_credentials']
			},
			{
				'clientCredentials.enabled': true
			}
		).then((client) => {
			expect(client.grantTypes).not.to.be.empty;
			expect(client.responseTypes).to.be.empty;
			expect(client.redirectUris).to.be.empty;
		}));

	describe('authorization_details_types', function () {
		const features = {
			richAuthorizationRequests: {
				enabled: true,
				types: {
					foo: {
						validate() {}
					}
				}
			}
		};
		mustBeArray('authorization_details_types', undefined, { features });
		defaultsTo('authorization_details_types', [], undefined, { features });
		rejects(
			'authorization_details_types',
			[123],
			/must only contain strings$/,
			undefined,
			{
				features
			}
		);
		rejects(
			'authorization_details_types',
			['bar'],
			/can only contain 'foo'$/,
			undefined,
			{
				features
			}
		);
	});

	it('fails to determine sector identifier', () =>
		register(
			{
				clientId: 'authorization-server',
				clientSecret: 'foobar',
				redirectUris: [],
				responseTypes: [],
				grantTypes: [],
				subjectType: 'pairwise'
			},
			{ subjectTypes: ['pairwise', 'public'] }
		).then((client) => {
			expect(client.grantTypes).to.be.empty;
			expect(client.responseTypes).to.be.empty;
			expect(client.redirectUris).to.be.empty;
			expect(() => sectorIdentifier(client)).to.throw();
			try {
				sectorIdentifier(client);
			} catch (err) {
				expect(err.error).to.eql('invalid_client_metadata');
				expect(err.error_description).to.eql(
					'could not determine a sector identifier'
				);
			}
		}));

	describe('clientDefaults configuration option allows for default client metadata to be changed', () => {
		defaultsTo('token_endpoint_auth_method', 'client_secret_post', undefined, {
			clientDefaults: {
				token_endpoint_auth_method: 'client_secret_post'
			}
		});
		defaultsTo('id_token_signed_response_alg', 'ES256', undefined, {
			clientDefaults: {
				id_token_signed_response_alg: 'ES256'
			}
		});
		// `grantTypes` is a camelCase base key; `clientDefaults` (which seeds the
		// snake_case recognised-metadata defaults) does not change its default here.
		defaultsTo('responseTypes', ['code'], undefined, {
			clientDefaults: {
				responseTypes: ['code'],
				grantTypes: ['authorization_code']
			}
		});
	});
});

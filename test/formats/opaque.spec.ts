import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	spyOn,
	mock
} from 'bun:test';

import epochTime from '../../lib/helpers/epoch_time.ts';
import bootstrap from '../test_helper.js';
import { Client } from 'lib/models/client.js';
import { TestAdapter } from 'test/models.js';
import { provider } from 'lib/provider.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { AccessToken } from 'lib/models/access_token.js';
import { ClientCredentials } from 'lib/models/client_credentials.js';

describe('opaque storage', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url)();
	});

	const accountId = 'account';
	const claims = {};
	const clientId = 'client';
	const grantId = 'grantid';
	const scope = 'openid';
	const sid = 'sid';
	const consumed = true;
	const acr = 'acr';
	const amr = ['amr'];
	const authTime = epochTime();
	const nonce = 'nonce';
	const redirectUri = 'https://rp.example.com/cb';
	const codeChallenge = 'codeChallenge';
	const codeChallengeMethod = 'codeChallengeMethod';
	const aud = [clientId, 'foo'];
	const gty = 'foo';
	const error = 'access_denied';
	const errorDescription = 'resource owner denied access';
	const params = { foo: 'bar' };
	const userCode = '1384-3217';
	const deviceInfo = { foo: 'bar' };
	const inFlight = true;
	const s256 = '_gPMqAT8BELhXwBa2nIT0OvdWtQCiF_g09nAyHhgCe0';
	const resource = 'urn:foo:bar';
	const policies = ['foo'];
	const sessionUid = 'foo';
	const expiresWithSession = false;
	const iiat = epochTime();
	const rotations = 1;
	const extra = { foo: 'bar' };
	const dpopJkt = 'cbaZgHZazjgQq0Q2-Hy_o2-OCDpPu02S30lNhTsNU1Q';

	// TODO: add Session and Interaction

	const fullPayload = {
		accountId,
		claims,
		grantId,
		scope,
		sid,
		consumed,
		acr,
		amr,
		authTime,
		nonce,
		redirectUri,
		codeChallenge,
		codeChallengeMethod,
		aud,
		error,
		errorDescription,
		params,
		userCode,
		deviceInfo,
		gty,
		resource,
		policies,
		sessionUid,
		expiresWithSession,
		'x5t#S256': s256,
		inFlight,
		iiat,
		rotations,
		extra,
		jkt: s256,
		dpopJkt
	};

	afterEach(() => mock.restore());

	it('for AccessToken', async () => {
		const kind = 'AccessToken';
		const adapter = TestAdapter.for(kind);
		const upsert = spyOn(adapter, 'upsert');
		const client = await Client.find(clientId);
		const token = new AccessToken({ client, ...fullPayload });
		await token.save();

		const [jti, saved] = upsert.mock.calls[0];
		expect(jti).toHaveLength(43);
		expect(saved).toEqual({
			accountId,
			aud,
			claims,
			clientId,
			exp: expect.any(Number),
			grantId,
			gty,
			iat: expect.any(Number),
			jti,
			kind,
			scope,
			sid,
			'x5t#S256': s256,
			jkt: s256,
			sessionUid,
			expiresWithSession,
			extra
		});
	});

	it('for AccessToken extraTokenClaims gets assigned upon save()', async () => {
		const client = await Client.find(clientId);
		const token = new AccessToken({
			client,
			...fullPayload,
			extra: undefined
		});
		expect(token.extra).toEqual(undefined);
		await token.save();
		expect(token.extra).toEqual(extra);
	});

	it('for AuthorizationCode', async () => {
		const kind = 'AuthorizationCode';
		const adapter = TestAdapter.for(kind);
		const upsert = spyOn(adapter, 'upsert');
		const client = await Client.find(clientId);
		const token = new AuthorizationCode({
			client,
			...fullPayload
		});
		await token.save();

		const [jti, saved] = upsert.mock.calls[0];
		expect(jti).toHaveLength(43);
		expect(saved).toEqual({
			accountId,
			acr,
			amr,
			authTime,
			claims,
			clientId,
			codeChallenge,
			codeChallengeMethod,
			consumed,
			exp: expect.any(Number),
			grantId,
			iat: expect.any(Number),
			jti,
			kind,
			nonce,
			redirectUri,
			resource,
			scope,
			sid,
			sessionUid,
			expiresWithSession,
			dpopJkt
		});
	});

	it('for DeviceCode', async () => {
		const kind = 'DeviceCode';
		const adapter = TestAdapter.for(kind);
		const upsert = spyOn(adapter, 'upsert');
		const client = await Client.find(clientId);
		const token = new DeviceCode({ client, ...fullPayload });
		await token.save();

		const [jti, saved] = upsert.mock.calls[0];
		expect(jti).toHaveLength(43);
		expect(saved).toEqual({
			accountId,
			acr,
			amr,
			authTime,
			claims,
			clientId,
			consumed,
			deviceInfo,
			error,
			errorDescription,
			exp: expect.any(Number),
			grantId,
			iat: expect.any(Number),
			jti,
			kind,
			nonce,
			params,
			resource,
			scope,
			sid,
			userCode,
			sessionUid,
			expiresWithSession,
			inFlight
		});
	});

	it('for BackchannelAuthenticationRequest', async () => {
		const kind = 'BackchannelAuthenticationRequest';
		const adapter = TestAdapter.for(kind);
		const upsert = spyOn(adapter, 'upsert');
		const client = await Client.find(clientId);
		const token = new provider.BackchannelAuthenticationRequest({
			client,
			...fullPayload
		});
		await token.save();

		const [jti, saved] = upsert.mock.calls[0];
		expect(jti).toHaveLength(43);
		expect(saved).toEqual({
			accountId,
			acr,
			amr,
			authTime,
			claims,
			clientId,
			consumed,
			error,
			errorDescription,
			exp: expect.any(Number),
			grantId,
			iat: expect.any(Number),
			jti,
			kind,
			nonce,
			params,
			resource,
			scope,
			sid,
			sessionUid,
			expiresWithSession
		});
	});

	it('for RefreshToken', async () => {
		const kind = 'RefreshToken';
		const adapter = TestAdapter.for(kind);
		const upsert = spyOn(adapter, 'upsert');
		const client = await Client.find(clientId);
		const token = new RefreshToken({ client, ...fullPayload });
		await token.save();

		const [jti, saved] = upsert.mock.calls[0];
		expect(jti).toHaveLength(43);
		expect(saved).toEqual({
			accountId,
			acr,
			amr,
			authTime,
			claims,
			iiat,
			rotations,
			clientId,
			consumed,
			exp: expect.any(Number),
			grantId,
			gty,
			iat: expect.any(Number),
			jti,
			kind,
			nonce,
			resource,
			scope,
			sid,
			'x5t#S256': s256,
			jkt: s256,
			sessionUid,
			expiresWithSession
		});
	});

	it('for ClientCredentials', async () => {
		const kind = 'ClientCredentials';
		const adapter = TestAdapter.for(kind);
		const upsert = spyOn(adapter, 'upsert');
		const client = await Client.find(clientId);
		const token = new ClientCredentials({
			client,
			...fullPayload
		});
		await token.save();

		const [jti, saved] = upsert.mock.calls[0];
		expect(jti).toHaveLength(43);
		expect(saved).toEqual({
			aud,
			clientId,
			exp: expect.any(Number),
			iat: expect.any(Number),
			jti,
			kind,
			scope,
			'x5t#S256': s256,
			jkt: s256,
			extra
		});
	});

	it('for ClientCredentials extraTokenClaims gets assigned upon save()', async () => {
		const client = await Client.find(clientId);
		const token = new ClientCredentials({
			client,
			...fullPayload,
			extra: undefined
		});
		expect(token.extra).toEqual(undefined);
		await token.save();
		expect(token.extra).toEqual(extra);
	});

	it('for InitialAccessToken', async () => {
		const kind = 'InitialAccessToken';
		const adapter = TestAdapter.for(kind);
		const upsert = spyOn(adapter, 'upsert');
		const token = new provider.InitialAccessToken({
			expiresIn: 100,
			...fullPayload
		});
		await token.save();

		const [jti, saved] = upsert.mock.calls[0];
		expect(jti).toHaveLength(43);
		expect(saved).toEqual({
			exp: expect.any(Number),
			iat: expect.any(Number),
			jti,
			kind,
			policies
		});
	});

	it('for RegistrationAccessToken', async () => {
		const kind = 'RegistrationAccessToken';
		const adapter = TestAdapter.for(kind);
		const upsert = spyOn(adapter, 'upsert');
		const client = await Client.find(clientId);
		const token = new provider.RegistrationAccessToken({
			client,
			expiresIn: 100,
			...fullPayload
		});
		await token.save();

		const [jti, saved] = upsert.mock.calls[0];
		expect(jti).toHaveLength(43);
		expect(saved).toEqual({
			clientId,
			kind,
			policies,
			jti,
			iat: expect.any(Number),
			exp: expect.any(Number)
		});
	});
});

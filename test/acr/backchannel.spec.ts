import {
	describe,
	it,
	expect,
	beforeAll,
	afterEach,
	spyOn,
	mock
} from 'bun:test';
import bootstrap, {
	agent,
	jsonToFormUrlEncoded,
	seedAccount
} from '../test_helper.ts';
import { backchannelResult } from 'lib/actions/authorization/backchannel_result.js';
import { BackchannelAuthenticationRequest } from 'lib/models/backchannel_authentication_request.js';
import { Grant } from 'lib/models/grant.js';
import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import { idTokenOf } from './response.ts';

const form = { 'content-type': 'application/x-www-form-urlencoded' };
const PWD = 'urn:example:acr:pwd';
const MFA = 'urn:example:acr:mfa';
const ACCOUNT = 'ciba-account';

/* Ask for a backchannel authentication, requiring or merely preferring a context. */
async function request(
	clientId: string,
	claims?: Record<string, unknown>,
	acrValues?: string
) {
	const res = await agent.backchannel.post(
		jsonToFormUrlEncoded({
			client_id: clientId,
			scope: 'openid',
			login_hint: ACCOUNT,
			// A ping-mode client supplies the token the server echoes back when it notifies.
			...(clientId === 'ciba-ping'
				? { client_notification_token: 'notification-token-value' }
				: {}),
			...(claims ? { claims: JSON.stringify(claims) } : {}),
			...(acrValues ? { acr_values: acrValues } : {})
		}),
		{ headers: form }
	);
	expect(res.response.status).toBe(200);
	return res.data.auth_req_id as string;
}

/* What the end user's authentication device reports back. */
async function report(
	authReqId: string,
	clientId: string,
	acr: string | undefined
) {
	const grant = new Grant({ clientId, accountId: ACCOUNT });
	grant.addOIDCScope('openid');
	await grant.save();
	await backchannelResult(authReqId, grant, acr ? { acr } : {});
}

/* What the relying party collects at the token endpoint — tokens, or the reason there are none. */
async function collect(authReqId: string, clientId: string) {
	const res = await agent.token.post(
		jsonToFormUrlEncoded({
			client_id: clientId,
			grant_type: 'urn:openid:params:grant-type:ciba',
			auth_req_id: authReqId
		}),
		{ headers: form }
	);
	return {
		data: (res.data ?? res.error?.value ?? {}) as Record<string, unknown>,
		status: res.response.status
	};
}

function requiring(values: string[]) {
	return { id_token: { acr: { essential: true, values } } };
}

/**
 * @proves A backchannel authentication that does not satisfy a context the relying party required
 * yields no token and a failed transaction rather than an end-user denial, while a context that was
 * merely preferred never fails the request.
 */
describe('a required authentication context on the backchannel', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'backchannel' });
		seedAccount(ACCOUNT);
	});

	afterEach(() => {
		mock.restore();
	});

	it('issues tokens carrying the reported context when it meets the requirement', async () => {
		const id = await request('ciba-poll', requiring([MFA]));
		await report(id, 'ciba-poll', MFA);

		const { data, status } = await collect(id, 'ciba-poll');

		expect(status).toBe(200);
		expect(decodeJWT(idTokenOf({ data })).payload.acr).toBe(MFA);
	});

	it('issues no token when the reported authentication does not meet the requirement', async () => {
		const id = await request('ciba-poll', requiring([MFA]));
		await report(id, 'ciba-poll', PWD);

		const { data, status } = await collect(id, 'ciba-poll');

		expect(status).toBe(400);
		expect(data).not.toHaveProperty('id_token');
		expect(data).not.toHaveProperty('access_token');
	});

	it('issues no token when the authentication is reported with no context at all', async () => {
		const id = await request('ciba-poll', requiring([MFA]));
		await report(id, 'ciba-poll', undefined);

		const { status, data } = await collect(id, 'ciba-poll');

		expect(status).toBe(400);
		expect(data).not.toHaveProperty('id_token');
	});

	it('reports a failed transaction rather than an end-user denial', async () => {
		const id = await request('ciba-poll', requiring([MFA]));
		await report(id, 'ciba-poll', PWD);

		const { data } = await collect(id, 'ciba-poll');

		// The end user authenticated; they denied nothing. A client branching on access_denied to
		// stop retrying, or to tell the person they refused, would be misled by that code.
		expect(data.error).toBe('transaction_failed');
		expect(data.error).not.toBe('access_denied');
	});

	it('reports the failure to a client that registered for ping delivery', async () => {
		// The notification is an outbound call; stubbed so this asserts the delivery, not the network.
		spyOn(globalThis, 'fetch').mockResolvedValue(
			new Response(null, { status: 204 })
		);
		const id = await request('ciba-ping', requiring([MFA]));
		await report(id, 'ciba-ping', PWD);
		expect(fetch).toHaveBeenCalled();

		const { data, status } = await collect(id, 'ciba-ping');

		expect(status).toBe(400);
		expect(data.error).toBe('transaction_failed');
	});

	it('makes the requested contexts available to the authentication device integration', async () => {
		const id = await request('ciba-poll', requiring([MFA]), MFA);

		// What the integration is handed: it chooses the channel, so a requirement it cannot see
		// could not be honoured by anyone.
		const stored = await BackchannelAuthenticationRequest.find(id);
		expect(stored.payload).toHaveProperty('params.acr_values', MFA);
		expect(stored.payload).toHaveProperty('claims.id_token.acr', {
			essential: true,
			values: [MFA]
		});
	});

	it('completes the request when a context was preferred rather than required', async () => {
		const id = await request('ciba-poll', undefined, MFA);
		await report(id, 'ciba-poll', PWD);

		const { data, status } = await collect(id, 'ciba-poll');

		expect(status).toBe(200);
		expect(decodeJWT(idTokenOf({ data })).payload.acr).toBe(PWD);
	});
});

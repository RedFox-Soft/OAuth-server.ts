import { randomBytes, createHash } from 'node:crypto';

import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, {
	DEFAULT_SESSION_COOKIE,
	agent,
	type Setup,
	formAgent
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { PushedAuthorizationRequest } from 'lib/models/pushed_authorization_request.js';
import { Interaction } from 'lib/models/interaction.js';
import epochTime from 'lib/helpers/epoch_time.js';

const clientId = 'client';
const redirectUri = 'https://rp.example.com/cb';
const expire = new Date();
expire.setDate(expire.getDate() + 1);

/**
 * @proves A pushed authorization request is spent by the authorization response it produces, so a
 * `request_uri` presented a second time yields a refusal rather than a second authorization code —
 * and that holds whether or not the end user had to sign in or consent along the way.
 */
describe('single use of a pushed request_uri', () => {
	let setup: Setup;

	beforeAll(async function () {
		setup = await bootstrap(import.meta.url);
	});

	async function push() {
		const codeVerifier = randomBytes(32).toString('base64url');
		const codeChallenge = createHash('sha256')
			.update(codeVerifier)
			.digest('base64url');

		const {
			data: { request_uri }
		} = await formAgent.par.post(
			{
				client_id: clientId,
				response_type: 'code',
				redirect_uri: redirectUri,
				scope: 'openid',
				code_challenge_method: 'S256',
				code_challenge: codeChallenge
			},
			{
				headers: {
					...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
				}
			}
		);

		return { request_uri, id: request_uri.split(':').at(-1) as string };
	}

	function present(request_uri: string, cookie?: string) {
		return agent.auth.get({
			query: { client_id: clientId, request_uri },
			headers: { cookie }
		});
	}

	/*
	 * The authorization pipeline hands a pushed request to an interaction by storing its id on the
	 * interaction record, and `respond` finds it again from there once the user comes back. This
	 * builds that record the way the pipeline would have, so the resume path can be driven without a
	 * browser — `interactionCount` says how many interactions the flow took before resuming, which is
	 * what separates a sign-in from a sign-in followed by a consent.
	 */
	async function resumeFrom(id: string, interactionCount: number) {
		const { accountId } = setup.getSession();
		let parJti: string | undefined = id;

		// Each hand-off copies parJti from the interaction before it; the last one is what resumes.
		for (let i = 1; i < interactionCount; i += 1) {
			const carried = new Interaction(`carry-${i}`, {
				uid: `carry-${i}`,
				cookieID: 'cookieID',
				parJti
			});
			await carried.save(30);
			parJti = (await Interaction.find(`carry-${i}`)).payload.parJti;
		}

		const resume = new Interaction('resume', {
			uid: 'resume',
			cookieID: 'cookieID',
			parJti,
			params: {
				client_id: clientId,
				response_type: 'code',
				redirect_uri: redirectUri,
				scope: 'openid'
			},
			result: { login: { accountId, ts: epochTime() } }
		});
		await resume.save(30);

		return agent.ui({ uid: 'resume' }).resume.get({
			headers: {
				cookie: `_interaction=cookieID; ${DEFAULT_SESSION_COOKIE}=${setup.getSession().jti}`
			}
		});
	}

	it('refuses a request_uri presented again after an authorization that needed no interaction', async function () {
		const cookie = await setup.login();
		const { request_uri, id } = await push();

		const first = await present(request_uri, cookie);
		expect(first.response.status).toBe(303);
		expect(first.response.headers.get('location')).toContain('code=');
		expect(
			(await PushedAuthorizationRequest.find(id)).payload.consumed
		).toBeTruthy();

		const second = await present(request_uri, cookie);
		expect(second.response.headers.get('location')).toContain(
			'error=invalid_request_uri'
		);
	});

	it('refuses a request_uri presented again after an authorization the user signed in for', async function () {
		await setup.login();
		const { request_uri, id } = await push();

		const resumed = await resumeFrom(id, 1);
		expect(resumed.response.status).toBe(303);
		expect(resumed.response.headers.get('location')).toContain('code=');

		expect(
			(await PushedAuthorizationRequest.find(id)).payload.consumed
		).toBeTruthy();

		const second = await present(request_uri, await setup.login());
		expect(second.response.headers.get('location')).toContain(
			'error=invalid_request_uri'
		);
	});

	it('refuses a request_uri presented again after an authorization that took two interactions', async function () {
		await setup.login();
		const { request_uri, id } = await push();

		const resumed = await resumeFrom(id, 2);
		expect(resumed.response.status).toBe(303);
		expect(resumed.response.headers.get('location')).toContain('code=');

		expect(
			(await PushedAuthorizationRequest.find(id)).payload.consumed
		).toBeTruthy();

		const second = await present(request_uri, await setup.login());
		expect(second.response.headers.get('location')).toContain(
			'error=invalid_request_uri'
		);
	});

	it('delivers the reuse refusal to the registered redirect uri carrying state', async function () {
		const cookie = await setup.login();
		const { request_uri } = await push();

		await present(request_uri, cookie);

		const auth = new AuthorizationRequest({
			client_id: clientId,
			request_uri
		});
		const { response } = await agent.auth.get({
			query: {
				client_id: clientId,
				request_uri,
				state: auth.params.state
			},
			headers: { cookie }
		});

		expect(response.status).toBe(303);
		auth.validatePresence(response, ['error', 'error_description', 'state']);
		auth.validateState(response);
		auth.validateClientLocation(response);
		auth.validateError(response, 'invalid_request_uri');
		auth.validateErrorDescription(
			response,
			'request_uri is invalid, expired, or was already used'
		);
	});

	it('accepts a second presentation made before any authorization response was produced', async function () {
		const cookie = await setup.login();
		const { request_uri, id } = await push();

		// Nothing has been produced from it yet, so it is still good: the rule is that a pushed
		// request is spent by the response, not by being read.
		expect(
			(await PushedAuthorizationRequest.find(id)).payload.consumed
		).toBeFalsy();

		const first = await present(request_uri, cookie);
		expect(first.response.headers.get('location')).toContain('code=');

		const second = await present(request_uri, cookie);
		expect(second.response.headers.get('location')).toContain(
			'error=invalid_request_uri'
		);
	});
});

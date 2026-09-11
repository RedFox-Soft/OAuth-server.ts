import { createHash, randomBytes } from 'node:crypto';

import { describe, it, expect } from 'bun:test';

import bootstrap, { agent, jsonToFormUrlEncoded } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { ISSUER } from 'lib/configs/env.js';

const form = 'application/x-www-form-urlencoded';

/*
 * A name no profile defines and this server therefore cannot recognize. Not `foo`: the point is a
 * parameter a *newer* specification could legitimately give a client, which is the case the ignore
 * rule exists for.
 */
const undefinedParameter = { ext_parameter_from_a_later_profile: 'value' };

const codeVerifier = randomBytes(32).toString('base64');
const codeChallenge = createHash('sha256')
	.update(codeVerifier)
	.digest('base64url');

const authorizationParameters = {
	client_id: 'client',
	response_type: 'code',
	scope: 'openid',
	redirect_uri: 'https://rp.example.com/cb',
	code_challenge_method: 'S256',
	code_challenge: codeChallenge,
	nonce: 'nonce'
};

const basic = () => AuthorizationRequest.basicAuthHeader('client', 'secret');

interface Outcome {
	status: number;
	error: string | null;
}

/*
 * The status alone does not describe what the authorization endpoint answered: it delivers a refusal
 * by redirecting to the client's redirect_uri, so a refused request and an honoured one are both a
 * 303 and differ only in the query. The error code is read from wherever that endpoint puts it.
 */
function outcome({
	response,
	data,
	error
}: {
	response: Response;
	data?: unknown;
	error?: { value?: unknown } | null;
}): Outcome {
	const location = response.headers.get('location');
	if (location) {
		// An honoured request redirects to the interaction with a relative Location; a refused one
		// redirects to the client's absolute redirect_uri. Both have to parse.
		return {
			status: response.status,
			error: new URL(location, ISSUER).searchParams.get('error')
		};
	}

	const body = (error?.value ?? data) as { error?: string } | undefined;
	return { status: response.status, error: body?.error ?? null };
}

/*
 * Each entry sends the endpoint's own request, with whatever extra parameters it is handed. The two
 * calls a case makes differ in nothing but those extras, so any difference in the answer is caused
 * by them.
 */
const endpoints: {
	name: string;
	send: (extra: Record<string, string>) => Promise<Outcome>;
}[] = [
	{
		name: 'GET /auth',
		send: async (extra) => {
			return outcome(
				await agent.auth.get({
					query: { ...authorizationParameters, ...extra }
				})
			);
		}
	},
	{
		name: 'POST /auth',
		send: async (extra) => {
			return outcome(
				await agent.auth.post(
					// @ts-expect-error the endpoint parses the form body into an object
					jsonToFormUrlEncoded({ ...authorizationParameters, ...extra }),
					{ headers: { ['content-type']: form } }
				)
			);
		}
	},
	{
		name: 'POST /par',
		send: async (extra) => {
			return outcome(
				await agent.par.post(
					// @ts-expect-error the endpoint parses the form body into an object
					jsonToFormUrlEncoded({ ...authorizationParameters, ...extra }),
					{ headers: { ['content-type']: form, ...basic() } }
				)
			);
		}
	},
	{
		name: 'POST /device/auth',
		send: async (extra) => {
			return outcome(
				await agent.device.auth.post(
					// @ts-expect-error the endpoint parses the form body into an object
					jsonToFormUrlEncoded({
						client_id: 'device-client',
						scope: 'openid',
						...extra
					}),
					{ headers: { ['content-type']: form } }
				)
			);
		}
	},
	{
		name: 'POST /token',
		send: async (extra) => {
			return outcome(
				await agent.token.post(
					// @ts-expect-error the endpoint parses the form body into an object
					jsonToFormUrlEncoded({
						grant_type: 'refresh_token',
						refresh_token: 'not-a-refresh-token',
						...extra
					}),
					{ headers: { ['content-type']: form, ...basic() } }
				)
			);
		}
	}
];

/**
 * @proves An endpoint that takes authorization-request parameters answers a request carrying a
 * parameter it does not define exactly as it answers the same request without it, so a client may
 * send what a later profile defines without the request failing.
 */
describe('undefined request parameters', async () => {
	await bootstrap(import.meta.url);

	endpoints.forEach(({ name, send }) => {
		describe(name, () => {
			it('answers a request carrying an undefined parameter as it answers one without', async () => {
				const plain = await send({});
				const extended = await send(undefinedParameter);

				// The comparison is only worth anything if the plain request got past the body
				// schema in the first place; 422 is how this server refuses one that did not.
				expect(plain.status).not.toBe(422);
				expect(extended).toEqual(plain);
			});
		});
	});
});

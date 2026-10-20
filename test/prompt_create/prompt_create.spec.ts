import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, {
	agent,
	bindClientToBucket,
	getHeader
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { getBucketStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { present } from 'test/shape.js';

const PASSWORD = 'correct horse battery';

async function seedProject(
	clientId: string,
	fields: Record<string, unknown>
): Promise<void> {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `${clientId} project`,
		emailVerificationRequired: false,
		...fields
	});
	await bindClientToBucket(clientId, bucket._id);
}

function cookiePair(response: Response, name: string): string {
	const found = response.headers
		.getSetCookie()
		.find((c) => c.startsWith(`${name}=`));
	if (!found) throw new Error(`expected a ${name} cookie`);
	return found.split(';')[0];
}

async function authorize(clientId: string, prompt?: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid',
		...(prompt === undefined ? {} : { prompt })
	});
	const { response } = await agent.auth.get({ query: auth.params });
	return { auth, response };
}

/**
 * @proves An application that asks for prompt=create has its user shown account creation, the person
 * who creates an account there finishes the same authorization with a code, a project that takes no
 * sign-ups offers its sign-in page instead, and discovery says the value is accepted.
 */
describe('prompt=create', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'prompt_create' });
		resetAdminMemoryStores();
		await seedProject('create-open-app', { registrationOpen: true });
		await seedProject('create-closed-app', { registrationOpen: false });
	});

	it('opens the interaction on the registration page', async () => {
		const { response } = await authorize('create-open-app', 'create');
		expect(response.status).toBe(303);
		expect(getHeader(response, 'location')).toMatch(
			/^\/ui\/[^/]+\/registration$/
		);
	});

	it('opens the interaction on the sign-in page when the request does not ask for it', async () => {
		const { response } = await authorize('create-open-app');
		expect(getHeader(response, 'location')).toMatch(/^\/ui\/[^/]+\/login$/);
	});

	it('returns the new account to the application with a code once it signs in', async () => {
		const { auth, response } = await authorize('create-open-app', 'create');
		const uid = getHeader(response, 'location').split('/')[2];
		const interaction = cookiePair(response, '_interaction');
		const email = 'created-at-the-door@x.io';

		const registered = await agent
			.ui({ uid })
			.registration.post(
				{ email, password: PASSWORD, confirmPassword: PASSWORD },
				{ headers: { cookie: interaction } }
			);
		expect(getHeader(registered.response, 'location')).toBe(`/ui/${uid}/login`);

		const signedIn = await agent
			.ui({ uid })
			.login.post(
				{ username: email, password: PASSWORD },
				{ headers: { cookie: interaction } }
			);
		expect(signedIn.response.status).toBe(303);
		const callback = new URL(getHeader(signedIn.response, 'location'));
		expect(callback.origin + callback.pathname).toBe(
			present(auth.params.redirect_uri, 'redirect_uri')
		);
		expect(callback.searchParams.get('code')).toBeTruthy();
		expect(callback.searchParams.get('state')).toBe(
			present(auth.params.state, 'state')
		);
	});

	it('offers the sign-in page instead when the project takes no sign-ups', async () => {
		const { response } = await authorize('create-closed-app', 'create');
		const location = getHeader(response, 'location');
		const uid = location.split('/')[2];
		const page = await agent.ui({ uid }).registration.get({
			headers: { cookie: cookiePair(response, '_interaction') }
		});
		expect(page.response.status).toBe(303);
		expect(getHeader(page.response, 'location')).toBe(`/ui/${uid}/login`);
	});

	it('still refuses the registration page of a project that takes no sign-ups to a request that did not ask for it', async () => {
		const { response } = await authorize('create-closed-app');
		const uid = getHeader(response, 'location').split('/')[2];
		const page = await agent.ui({ uid }).registration.get({
			headers: { cookie: cookiePair(response, '_interaction') }
		});
		expect(page.response.status).toBe(403);
	});

	it('is refused alongside prompt=none', async () => {
		const { response } = await authorize('create-open-app', 'none create');
		const callback = new URL(getHeader(response, 'location'));
		expect(callback.searchParams.get('error')).toBe('invalid_request');
	});

	it('is listed with every other accepted prompt value in the discovery document', async () => {
		const { data } = await agent['.well-known']['openid-configuration'].get();
		expect(
			[
				...(data as { prompt_values_supported: string[] })
					.prompt_values_supported
			].sort()
		).toEqual(['consent', 'create', 'login', 'none']);
	});
});

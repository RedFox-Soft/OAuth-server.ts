import { agent, bindClientToBucket, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

export const PASSWORD = 'correct horse battery';

/* A project open to sign-up, reached through `clientId`, requiring verification or not. */
export async function projectFor(
	clientId: string,
	emailVerificationRequired: boolean
): Promise<string> {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `honest ${clientId}`,
		registrationOpen: true,
		emailVerificationRequired,
		verificationMethod: 'link'
	});
	await bindClientToBucket(clientId, bucket._id);
	return bucket._id;
}

async function startInteraction(clientId: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

/* A person signing themselves up, as the registration page posts it. */
export async function signUp(clientId: string, email: string) {
	const { uid, cookie } = await startInteraction(clientId);
	await agent
		.ui({ uid })
		.registration.post(
			{ email, password: PASSWORD, confirmPassword: PASSWORD },
			{ headers: { cookie } }
		);
}

/* Signing in on a fresh interaction; answers the status the login POST gives. */
export async function signIn(clientId: string, email: string): Promise<number> {
	const { uid, cookie } = await startInteraction(clientId);
	const { response } = await agent
		.ui({ uid })
		.login.post(
			{ username: email, password: PASSWORD },
			{ headers: { cookie } }
		);
	return response.status;
}

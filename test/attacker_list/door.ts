import { agent, bindClientToBucket, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { elysia } from 'lib/index.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import type { PasswordGuessingSetting } from 'lib/adapters/types.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	PEER_HEADER,
	statePeerThroughHeader
} from '../caller_address/helper.ts';

/*
 * The password door driven as a browser drives it — /auth for an interaction, then POST /ui/:uid/login — with the
 * caller's address carried by the test peer header, so the list is asked about exactly that address.
 */

export const CLIENT = 'guessing-app';
export const PASSWORD = 'correct horse battery';
export const WRONG = 'not the password';
export const INVALID = 'Invalid username or password';

export async function seedProject(): Promise<string> {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: 'Guessing'
	});
	await bindClientToBucket(CLIENT, bucket._id);
	return bucket._id;
}

export async function setGuessing(
	bucketId: string,
	setting: PasswordGuessingSetting | undefined
): Promise<void> {
	await getBucketStore().update(bucketId, { passwordGuessing: setting });
}

let seq = 0;
export async function person(bucketId: string): Promise<string> {
	seq += 1;
	const email = `person-${String(seq)}@x.io`;
	await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
	return email;
}

export async function interaction(language?: string) {
	const auth = new AuthorizationRequest({
		client_id: CLIENT,
		scope: 'openid',
		...(language ? { ui_locales: language } : {})
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	const uid = location.split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

export interface Answer {
	status: number;
	text: string;
	setCookie: string | null;
	uid: string;
}

/* One password attempt from `from`, in a fresh interaction. Without `from`, the request has no address at all. */
export async function attempt(
	email: string,
	password: string,
	from?: string,
	language?: string
): Promise<Answer> {
	statePeerThroughHeader();
	const { uid, cookie } = await interaction(language);
	const response = await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie,
				...(from ? { [PEER_HEADER]: from } : {})
			},
			body: new URLSearchParams({ username: email, password }).toString(),
			redirect: 'manual'
		})
	);
	return {
		status: response.status,
		text: await response.text(),
		setCookie: response.headers.get('set-cookie'),
		uid
	};
}

/* The page with its interaction id blanked out: two attempts always carry different ones. */
export function withoutUid(answer: Answer): string {
	return answer.text.replaceAll(answer.uid, '<uid>');
}

export const REFUSAL_TITLE =
	'Password sign-in is not available from this network';

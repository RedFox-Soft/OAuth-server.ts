import { describe, expect, it } from 'bun:test';
import { isoBase64URL } from '@simplewebauthn/server/helpers';

import {
	addOptions,
	signInOptions,
	verifyAdd,
	verifySignIn,
	type Expected,
	type StoredPasskey
} from 'lib/passkeys/ceremony.ts';
import {
	SoftAuthenticator,
	type BrowserContext,
	type Flags,
	type GetChoices
} from './authenticator.ts';

const rpId = 'auth.example.com';
const origin = 'https://auth.example.com';
const page: BrowserContext = { origin };

function challenge(): string {
	return isoBase64URL.fromBuffer(crypto.getRandomValues(new Uint8Array(32)));
}

const userHandle = challenge();

async function addWith(
	device: SoftAuthenticator,
	browser: BrowserContext = page,
	flags: Flags = {}
) {
	const expected: Expected = { rpId, origin, challenge: challenge() };
	const options = await addOptions({
		rpId,
		rpName: 'Project',
		userId: userHandle,
		label: 'alice@example.com · Project',
		challenge: expected.challenge,
		exclude: []
	});
	return verifyAdd(await device.create(options, browser, { flags }), expected);
}

/* A passkey the device made and the server stored, as an add leaves it. */
async function stored(device: SoftAuthenticator): Promise<StoredPasskey> {
	const added = await addWith(device);
	if (!added.ok) throw new Error(`the add was refused: ${added.reason}`);
	return {
		credentialId: added.passkey.credentialId,
		publicKey: added.passkey.publicKey,
		counter: added.passkey.counter,
		userHandle
	};
}

async function signIn(
	device: SoftAuthenticator,
	passkey: StoredPasskey,
	{
		browser = page,
		choices = {},
		expect: change = {}
	}: {
		browser?: BrowserContext;
		choices?: GetChoices;
		expect?: Partial<Expected>;
	} = {}
) {
	const expected: Expected = {
		rpId,
		origin,
		challenge: challenge(),
		...change
	};
	const options = await signInOptions({ rpId, challenge: expected.challenge });
	const response = await device.get(
		{
			...options,
			challenge:
				change.challenge === undefined ? options.challenge : challenge()
		},
		browser,
		choices
	);
	return verifySignIn(response, expected, passkey);
}

/**
 * @proves A passkey this server added signs in again, and a response the server must not accept is refused: no user
 * verification, another origin, a cross-origin frame, another challenge or RP ID, a user handle that is not the
 * account's, or a counter going back — which alone, and only with a valid signature, reads as a copied passkey.
 */
describe('a passkey ceremony', () => {
	it('signs in with a passkey it added', async () => {
		const device = new SoftAuthenticator();
		expect((await signIn(device, await stored(device))).ok).toBe(true);
	});

	describe('adding', () => {
		it('refuses a passkey the device made without verifying the person, and says so', async () => {
			expect(
				await addWith(new SoftAuthenticator(), page, { uv: false })
			).toEqual({
				ok: false,
				reason: 'no_user_verification'
			});
		});

		it('refuses a passkey made inside a frame of another origin', async () => {
			const added = await addWith(new SoftAuthenticator(), {
				origin,
				crossOrigin: true,
				topOrigin: 'https://evil.example.net'
			});
			expect(added.ok).toBe(false);
		});

		it('refuses a passkey made on another origin', async () => {
			const added = await addWith(new SoftAuthenticator(), {
				origin: 'https://evil.example.net'
			});
			expect(added.ok).toBe(false);
		});
	});

	describe('signing in', () => {
		it('refuses a response the device made without verifying the person', async () => {
			const device = new SoftAuthenticator();
			const passkey = await stored(device);
			expect(
				(await signIn(device, passkey, { choices: { flags: { uv: false } } }))
					.ok
			).toBe(false);
		});

		it('refuses a response made on another origin', async () => {
			const device = new SoftAuthenticator();
			const passkey = await stored(device);
			expect(
				(
					await signIn(device, passkey, {
						browser: { origin: 'https://evil.example.net' }
					})
				).ok
			).toBe(false);
		});

		it('refuses a response made inside a cross-origin frame that names no top origin', async () => {
			const device = new SoftAuthenticator();
			const passkey = await stored(device);
			expect(
				(
					await signIn(device, passkey, {
						browser: { origin, crossOrigin: true }
					})
				).ok
			).toBe(false);
		});

		it('refuses a response made inside a cross-origin frame that names its top origin', async () => {
			const device = new SoftAuthenticator();
			const passkey = await stored(device);
			const framed = {
				origin,
				crossOrigin: true,
				topOrigin: 'https://evil.example.net'
			};
			expect((await signIn(device, passkey, { browser: framed })).ok).toBe(
				false
			);
		});

		it('refuses a response that names a top origin without being cross-origin', async () => {
			const device = new SoftAuthenticator();
			const passkey = await stored(device);
			const framed = { origin, topOrigin: origin };
			expect((await signIn(device, passkey, { browser: framed })).ok).toBe(
				false
			);
		});

		it('refuses a response to another challenge', async () => {
			const device = new SoftAuthenticator();
			const passkey = await stored(device);
			expect(
				(await signIn(device, passkey, { expect: { challenge: challenge() } }))
					.ok
			).toBe(false);
		});

		it('refuses a response made for another RP ID', async () => {
			const device = new SoftAuthenticator();
			const passkey = await stored(device);
			expect(
				(
					await signIn(device, passkey, {
						choices: { rpId: 'login.customer.com' }
					})
				).ok
			).toBe(false);
		});

		it('refuses a response whose user handle is not the account’s', async () => {
			const device = new SoftAuthenticator();
			const passkey = await stored(device);
			expect(
				await signIn(device, passkey, { choices: { userHandle: challenge() } })
			).toEqual({
				ok: false,
				reason: 'user_handle'
			});
		});

		it('refuses a counter going back as a possibly copied passkey', async () => {
			const device = new SoftAuthenticator();
			const passkey = { ...(await stored(device)), counter: 10 };
			expect(
				await signIn(device, passkey, { choices: { counter: 3 } })
			).toEqual({
				ok: false,
				reason: 'counter_back'
			});
		});

		it('never reads a counter going back as a copy when the signature does not verify', async () => {
			const device = new SoftAuthenticator();
			const passkey = { ...(await stored(device)), counter: 10 };
			const options = await signInOptions({ rpId, challenge: challenge() });
			const response = await device.get(options, page, { counter: 3 });
			const forged = {
				...response,
				response: {
					...response.response,
					signature: isoBase64URL.fromBuffer(new Uint8Array(70).fill(1))
				}
			};
			expect(
				await verifySignIn(
					forged,
					{ rpId, origin, challenge: options.challenge },
					passkey
				)
			).toEqual({
				ok: false,
				reason: 'refused'
			});
		});

		it('accepts a counter that stays at zero', async () => {
			const device = new SoftAuthenticator();
			device.countStep = 0;
			const passkey = await stored(device);
			expect(await signIn(device, passkey)).toMatchObject({
				ok: true,
				counter: 0
			});
		});
	});
});

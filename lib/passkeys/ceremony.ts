/*
 * The one module that imports the WebAuthn library (specs/139 research R1, R3). Everything about a passkey ceremony
 * the server decides — which origin, which RP ID, which challenge, whether the person was verified — is passed in
 * here as exactly one value each, and the checks the library leaves to its caller are made here too, so no other
 * module can reach the library with a looser call.
 *
 * Importing `@simplewebauthn/server` installs a global `Reflect.getMetadata` polyfill: its attestation code pulls in
 * `@peculiar/x509`, which loads `reflect-metadata` for its decorators. Nothing in this server reads that global or
 * enables decorators, so the polyfill changes no behaviour; attestation is always `none`, so that certificate code is
 * loaded and never run. It is written here because this import is the only way the polyfill arrives.
 */
import {
	generateAuthenticationOptions,
	generateRegistrationOptions,
	verifyAuthenticationResponse,
	verifyRegistrationResponse,
	type AuthenticationResponseJSON,
	type PublicKeyCredentialCreationOptionsJSON,
	type PublicKeyCredentialRequestOptionsJSON,
	type RegistrationResponseJSON
} from '@simplewebauthn/server';
import {
	decodeAttestationObject,
	decodeClientDataJSON,
	isoBase64URL
} from '@simplewebauthn/server/helpers';
import { Type as t } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';

import {
	PASSKEY_TRANSPORTS,
	type PasskeyTransport
} from '../adapters/types.js';
import { CEREMONY_SECONDS, CREDENTIAL_FIELD_MAX } from './consts.js';

/* The one origin and the one RP ID a ceremony is made for, from the project (lib/passkeys/relying_party.ts). */
export interface Expected {
	rpId: string;
	origin: string;
	/* base64url, as the options carried it. */
	challenge: string;
	/*
	 * The browser's silent creation (specs/141 research R8), which reports neither presence nor verification; the offer
	 * asks for it only where the passkey is full at once. Every later use requires both.
	 */
	silent?: boolean;
}

/* A browser's transports beyond the ones a record may hold are dropped: a stored value goes back to browsers. */
type Transport = PasskeyTransport;
const MAX_TRANSPORTS = 8;

/* A credential id is at most 1023 bytes (WebAuthn §5.1), which is 1364 base64url characters; 1366 leaves slack. */
const CREDENTIAL_ID_MAX = 1366;
const PUBLIC_KEY_MAX = 4096;

const Base64Url = (maxLength: number) =>
	t.String({ minLength: 1, maxLength, pattern: '^[A-Za-z0-9_-]+$' });

/*
 * The shapes a browser's `PublicKeyCredential.toJSON()` produces, checked before anything reads them: the form field
 * is the caller's text, and the library's own checks assume these members are present and strings.
 */
const AssertionShape = t.Object({
	id: Base64Url(CREDENTIAL_ID_MAX),
	rawId: Base64Url(CREDENTIAL_ID_MAX),
	type: t.Literal('public-key'),
	response: t.Object({
		clientDataJSON: Base64Url(CREDENTIAL_FIELD_MAX),
		authenticatorData: Base64Url(CREDENTIAL_FIELD_MAX),
		signature: Base64Url(CREDENTIAL_FIELD_MAX),
		userHandle: t.Optional(Base64Url(CREDENTIAL_FIELD_MAX))
	}),
	clientExtensionResults: t.Optional(t.Record(t.String(), t.Unknown())),
	authenticatorAttachment: t.Optional(t.String())
});

const AttestationShape = t.Object({
	id: Base64Url(CREDENTIAL_ID_MAX),
	rawId: Base64Url(CREDENTIAL_ID_MAX),
	type: t.Literal('public-key'),
	response: t.Object({
		clientDataJSON: Base64Url(CREDENTIAL_FIELD_MAX),
		attestationObject: Base64Url(CREDENTIAL_FIELD_MAX),
		transports: t.Optional(t.Array(t.String(), { maxItems: 32 }))
	}),
	clientExtensionResults: t.Optional(t.Record(t.String(), t.Unknown())),
	authenticatorAttachment: t.Optional(t.String())
});

function parsed(text: string): unknown {
	if (text.length === 0 || text.length > CREDENTIAL_FIELD_MAX) return undefined;
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
}

/* A sign-in's `credential` field, read as an assertion, or undefined when it is not one. */
export function readAssertion(
	text: string
): AuthenticationResponseJSON | undefined {
	const value = parsed(text);
	if (!Value.Check(AssertionShape, value)) return undefined;
	// Only the members verification reads: extension results and the attachment are the browser's, never trusted here.
	return {
		id: value.id,
		rawId: value.rawId,
		type: value.type,
		response: value.response,
		clientExtensionResults: {}
	};
}

/* An add's `credential` field, read as an attestation, or undefined when it is not one. */
export function readAttestation(
	text: string
): RegistrationResponseJSON | undefined {
	const value = parsed(text);
	if (!Value.Check(AttestationShape, value)) return undefined;
	return {
		id: value.id,
		rawId: value.rawId,
		type: value.type,
		response: value.response,
		clientExtensionResults: {}
	};
}

/*
 * Whether the browser says the ceremony ran inside a frame of another origin. Checked before the library, which
 * accepts `crossOrigin: true` when no `topOrigin` comes with it (Safari sends none), and on an add does not look at
 * either. A ceremony of this server is never framed: every page sends `frame-ancestors 'none'`.
 */
function framed(clientDataJSON: string): boolean {
	try {
		const clientData = decodeClientDataJSON(clientDataJSON);
		return (
			clientData.crossOrigin === true || clientData.topOrigin !== undefined
		);
	} catch {
		return true;
	}
}

const TIMEOUT_MS = CEREMONY_SECONDS * 1000;

/*
 * The options for a sign-in page. `allowCredentials` stays empty: a discoverable passkey is asked for without naming
 * the account first, so the page leaks no list of credential ids and autofill can offer every passkey of the RP ID.
 */
export function signInOptions(expected: {
	rpId: string;
	challenge: string;
}): Promise<PublicKeyCredentialRequestOptionsJSON> {
	return generateAuthenticationOptions({
		rpID: expected.rpId,
		challenge: isoBase64URL.toBuffer(expected.challenge),
		userVerification: 'required',
		allowCredentials: [],
		timeout: TIMEOUT_MS
	});
}

/*
 * The options for adding a passkey. `user.name` and `user.displayName` are both "{email} · {project}" (FR-009): a
 * browser lists passkeys by them, and on an RP ID several projects share they are what tells two passkeys apart.
 */
export function addOptions(input: {
	rpId: string;
	rpName: string;
	/* The account's `webauthnUserId`, base64url: never the account id or the address (FR-009). */
	userId: string;
	label: string;
	challenge: string;
	exclude: readonly {
		credentialId: string;
		transports: readonly Transport[];
	}[];
}): Promise<PublicKeyCredentialCreationOptionsJSON> {
	return generateRegistrationOptions({
		rpName: input.rpName,
		rpID: input.rpId,
		userName: input.label,
		userDisplayName: input.label,
		userID: isoBase64URL.toBuffer(input.userId),
		challenge: isoBase64URL.toBuffer(input.challenge),
		attestationType: 'none',
		authenticatorSelection: {
			residentKey: 'required',
			userVerification: 'required'
		},
		excludeCredentials: input.exclude.map((passkey) => ({
			id: passkey.credentialId,
			transports: [...passkey.transports]
		})),
		timeout: TIMEOUT_MS
	});
}

/* A verified add: what the passkey record keeps. */
export interface AddedPasskey {
	credentialId: string;
	/* The COSE public key, base64url. */
	publicKey: string;
	counter: number;
	backupEligible: boolean;
	backedUp: boolean;
	transports: Transport[];
	aaguid: string;
}

/*
 * Why an add was refused. `no_user_verification` is told apart because the person can fix it ("set up a PIN for
 * this security key"); every other refusal reads the same to them.
 */
export type AddRefusal = 'framed' | 'no_user_verification' | 'refused';

function flagsOf(authenticatorData: Uint8Array): number {
	return authenticatorData.at(32) ?? 0;
}

const UV = 0x04;

export async function verifyAdd(
	response: RegistrationResponseJSON,
	expected: Expected
): Promise<
	{ ok: true; passkey: AddedPasskey } | { ok: false; reason: AddRefusal }
> {
	if (framed(response.response.clientDataJSON))
		return { ok: false, reason: 'framed' };
	let result;
	try {
		result = await verifyRegistrationResponse({
			response,
			expectedChallenge: expected.challenge,
			expectedOrigin: expected.origin,
			expectedRPID: expected.rpId,
			requireUserPresence: expected.silent !== true,
			requireUserVerification: expected.silent !== true
		});
	} catch {
		return {
			ok: false,
			reason: withoutUserVerification(response)
				? 'no_user_verification'
				: 'refused'
		};
	}
	if (!result.verified) return { ok: false, reason: 'refused' };
	const info = result.registrationInfo;
	const publicKey = isoBase64URL.fromBuffer(info.credential.publicKey);
	if (
		publicKey.length > PUBLIC_KEY_MAX ||
		info.credential.id.length > CREDENTIAL_ID_MAX
	) {
		return { ok: false, reason: 'refused' };
	}
	return {
		ok: true,
		passkey: {
			credentialId: info.credential.id,
			publicKey,
			counter: info.credential.counter,
			backupEligible: info.credentialDeviceType === 'multiDevice',
			backedUp: info.credentialBackedUp,
			transports: knownTransports(response.response.transports ?? []),
			aaguid: info.aaguid
		}
	};
}

/*
 * Whether a refused add came from a device that did not verify the person, read from the response's own
 * authenticator data rather than the library's message. Only ever widens the sentence the person reads.
 */
function withoutUserVerification(response: RegistrationResponseJSON): boolean {
	try {
		const attestation = decodeAttestationObject(
			isoBase64URL.toBuffer(response.response.attestationObject)
		);
		const authData = attestation.get('authData');
		return authData instanceof Uint8Array && (flagsOf(authData) & UV) === 0;
	} catch {
		return false;
	}
}

function knownTransports(reported: readonly string[]): Transport[] {
	const known = new Set<string>(PASSKEY_TRANSPORTS);
	return [
		...new Set(
			reported.filter((transport): transport is Transport =>
				known.has(transport)
			)
		)
	].slice(0, MAX_TRANSPORTS);
}

/* What the server stored about the passkey a sign-in names. */
export interface StoredPasskey {
	credentialId: string;
	publicKey: string;
	counter: number;
	/* The account's `webauthnUserId`: the user handle a genuine response hands back. */
	userHandle: string;
}

/*
 * Why a sign-in was refused. `counter_back` is a response whose signature verified but whose counter did not move
 * forward: the passkey may have been copied, and the caller marks it (FR-015). Every other refusal reads the same.
 */
export type SignInRefusal =
	'framed' | 'refused' | 'user_handle' | 'counter_back';

export async function verifySignIn(
	response: AuthenticationResponseJSON,
	expected: Expected,
	stored: StoredPasskey
): Promise<
	| { ok: true; counter: number; backedUp: boolean }
	| { ok: false; reason: SignInRefusal }
> {
	if (response.id !== stored.credentialId)
		return { ok: false, reason: 'refused' };
	if (framed(response.response.clientDataJSON))
		return { ok: false, reason: 'framed' };
	let result;
	try {
		result = await verifyAuthenticationResponse({
			response,
			expectedChallenge: expected.challenge,
			expectedOrigin: expected.origin,
			expectedRPID: expected.rpId,
			/*
			 * Zero, so the library never refuses on the counter itself: it compares the counter before it checks the
			 * signature, and a counter refused before the signature is known would let anyone who saw a credential id
			 * mark that passkey copied. The comparison is made below, after the signature verified.
			 */
			credential: {
				id: stored.credentialId,
				publicKey: isoBase64URL.toBuffer(stored.publicKey),
				counter: 0
			},
			requireUserVerification: true
		});
	} catch {
		return { ok: false, reason: 'refused' };
	}
	if (!result.verified) return { ok: false, reason: 'refused' };
	/*
	 * The library does not compare the user handle (specs/139 research R3). A response that names another user
	 * handle than the account the passkey is stored under is a passkey the device holds for someone else.
	 */
	if (response.response.userHandle !== stored.userHandle)
		return { ok: false, reason: 'user_handle' };
	const counter = result.authenticationInfo.newCounter;
	/* A device that never counts sends zero every time (many synced passkeys); one that counts must count up. */
	if (!(counter > stored.counter || (counter === 0 && stored.counter === 0))) {
		return { ok: false, reason: 'counter_back' };
	}
	return {
		ok: true,
		counter,
		backedUp: result.authenticationInfo.credentialBackedUp
	};
}

/*
 * The account pages' one script (specs/139 research R12): the "Add a passkey" button of "Sign-in and security", and the
 * browser signals of specs/141. It carries no page data: the options it hands the browser, the sentences it may show
 * and what it signals are attributes written by the server (lib/account_page/html.ts). It runs as an external file, so
 * the page needs no inline script. Without it the button stays disabled and the sentence beside it says what is
 * missing; the rest of the page is plain forms.
 */
import {
	browserSupportsWebAuthn,
	startRegistration,
	WebAuthnError,
	type PublicKeyCredentialCreationOptionsJSON
} from '@simplewebauthn/browser';

function say(status: HTMLElement | null, sentence: string | undefined): void {
	if (status && sentence) status.textContent = sentence;
}

function wire(form: HTMLFormElement): void {
	const button = form.querySelector('button');
	const credential = form.querySelector<HTMLInputElement>(
		'input[name="credential"]'
	);
	const status = form.querySelector<HTMLElement>('[data-passkey-status]');
	const options = form.dataset.options;
	if (!button || !credential || options === undefined) return;
	if (!browserSupportsWebAuthn()) return;
	// Parsed from the server's own attribute: the creation options, as lib/passkeys/ceremony.ts made them.
	const optionsJSON = JSON.parse(
		options
	) as PublicKeyCredentialCreationOptionsJSON;
	button.disabled = false;
	if (status) status.textContent = '';
	button.focus();
	button.addEventListener('click', () => {
		button.disabled = true;
		say(status, '');
		startRegistration({ optionsJSON })
			.then((made) => {
				credential.value = JSON.stringify(made);
				form.submit();
			})
			.catch((error: unknown) => {
				button.disabled = false;
				const code = error instanceof WebAuthnError ? error.code : undefined;
				const cause =
					error instanceof WebAuthnError && error.cause instanceof Error
						? error.cause.name
						: undefined;
				if (code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED') {
					say(status, form.dataset.textExists);
				} else if (
					code === 'ERROR_AUTHENTICATOR_MISSING_USER_VERIFICATION_SUPPORT'
				) {
					say(status, form.dataset.textNoUv);
				} else if (
					code !== 'ERROR_CEREMONY_ABORTED' &&
					cause !== 'NotAllowedError'
				) {
					/* A cancelled or timed-out prompt is the person's own doing and needs no sentence; anything else does. */
					say(status, form.dataset.textFailed);
				}
			});
	});
}

for (const form of document.querySelectorAll<HTMLFormElement>(
	'form[data-passkey-add]'
)) {
	wire(form);
}

/*
 * The Signal API (specs/141 research R10): the passkeys this project accepts at this site for the person's passkey
 * identity here, and their current label, so a password manager hides a passkey the server no longer takes and shows
 * the current address. Feature-detected and fire-and-forget: a browser without it, or one that refuses, changes
 * nothing on the page.
 */
interface SignallingCredential {
	signalAllAcceptedCredentials?: (options: {
		rpId: string;
		userId: string;
		allAcceptedCredentialIds: string[];
	}) => Promise<void>;
	signalCurrentUserDetails?: (options: {
		rpId: string;
		userId: string;
		name: string;
		displayName: string;
	}) => Promise<void>;
}

function signal(holder: HTMLElement): void {
	if (typeof PublicKeyCredential === 'undefined') return;
	const { rpId, userId, accepted, name, displayName } = holder.dataset;
	if (!rpId || !userId || accepted === undefined) return;
	/* Typed by hand: the Signal API is newer than the DOM library this bundle is checked against. */
	const api = PublicKeyCredential as unknown as SignallingCredential;
	// The server's own attribute: a JSON array of the credential ids it accepts.
	const ids = JSON.parse(accepted) as string[];
	api
		.signalAllAcceptedCredentials?.({
			rpId,
			userId,
			allAcceptedCredentialIds: ids
		})
		.catch(() => undefined);
	if (name && displayName) {
		api
			.signalCurrentUserDetails?.({ rpId, userId, name, displayName })
			.catch(() => undefined);
	}
}

for (const holder of document.querySelectorAll<HTMLElement>(
	'[data-passkey-signals]'
)) {
	signal(holder);
}

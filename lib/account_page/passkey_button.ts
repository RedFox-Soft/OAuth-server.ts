/*
 * The account pages' one script (specs/139 research R12): the "Add a passkey" button of "Sign-in and security". It
 * carries no page data: the options it hands the browser and the sentences it may show are attributes of the form it
 * finds, written by the server (lib/account_page/html.ts). It runs as an external file, so the page needs no inline
 * script. Without it the button stays disabled and the sentence beside it says what is missing; the rest of the page is
 * plain forms.
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

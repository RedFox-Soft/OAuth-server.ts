import { useConfirm } from '../../frame/confirm.js';
import type { RequestResult } from '../../frame/request.js';

/* The server's account of making an application require a code (specs/127): what it does to whom, counted. */
interface Preview {
	confirmationRequired: true;
	consequences: string[];
	expect: Record<string, number>;
}

function isPreview(body: unknown): body is Preview {
	return (
		typeof body === 'object' &&
		body !== null &&
		(body as { confirmationRequired?: unknown }).confirmationRequired ===
			true &&
		Array.isArray((body as { consequences?: unknown }).consequences)
	);
}

/*
 * Sends an application's create or save, and when it makes the application require a code, asks with the server's own
 * account of whom that reaches and sends it again carrying the counts that were shown — so consent is to the numbers
 * the operator read, and a count that moved in between is asked again (the Sign-in tab's protocol, useSignInSave).
 * Answers null when the operator kept editing.
 */
export function useCodeConsent() {
	const confirm = useConfirm();

	return async function send<T>(
		go: (consent?: Record<string, number>) => Promise<RequestResult<T>>,
		name: string,
		consent?: Record<string, number>
	): Promise<RequestResult<T> | null> {
		const result = await go(consent);
		if (!result.ok && result.status === 409 && isPreview(result.error)) {
			const preview = result.error;
			const agreed = await confirm('client.requireCode.confirm', {
				target: name,
				consequences: consent
					? [
							'What this change affects has changed since you last looked.',
							...preview.consequences
						]
					: preview.consequences
			});
			return agreed ? send(go, name, preview.expect) : null;
		}
		return result;
	};
}

/* The body a consent is carried in. */
export function withConsent(
	body: Record<string, unknown>,
	consent: Record<string, number> | undefined
): Record<string, unknown> {
	return consent ? { ...body, confirm: true, expect: consent } : body;
}

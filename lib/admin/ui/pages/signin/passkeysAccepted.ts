import { useEffect, useState } from 'react';

import { request } from '../../frame/request.js';

/*
 * Whether a project accepts passkeys (specs/139), for the console's words about a requirement of two-step sign-in:
 * "a code from an authenticator app, or a passkey" only where a passkey can meet it (research R22). Read from the
 * project as the server presents it; false until read, so the words never promise a passkey the project refuses.
 */
export function usePasskeysAccepted(bucketId: string): boolean {
	const [accepted, setAccepted] = useState(false);
	useEffect(() => {
		let current = true;
		void request<{ passkeyLogin?: boolean }>(
			'GET',
			`/admin/api/projects/${encodeURIComponent(bucketId)}`
		).then((read) => {
			if (current && read.ok) setAccepted(read.data.passkeyLogin === true);
		});
		return () => {
			current = false;
		};
	}, [bucketId]);
	return accepted;
}

/* The second step a requirement asks for, in the console's words, with a passkey only where one meets it. */
export function secondStepWords(passkeys: boolean): string {
	return passkeys
		? 'a code from an authenticator app, or a passkey'
		: 'a code from an authenticator app';
}

import { checkedAdapter } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import { CEREMONY_SECONDS } from './consts.js';
import { PasskeyCeremonyPayload } from './types.js';

/*
 * The add and removal ceremonies the person's own page prepares (specs/139 research R15). The account page reads its
 * session and never saves it, so what a later POST must find — the challenge, the proof, the one RP ID and origin, the
 * passkey a removal is for — is written here, keyed by the browser session, for five minutes.
 */

function ceremonies() {
	return checkedAdapter('PasskeyCeremony', PasskeyCeremonyPayload);
}

export type CeremonyPurpose = PasskeyCeremonyPayload['purpose'];

/* One add and one removal per browser session: `add:<session uid>`, `remove:<session uid>`. */
export function ceremonyId(
	purpose: CeremonyPurpose,
	sessionUid: string
): string {
	return `${purpose}:${sessionUid}`;
}

/* Writes a ceremony, replacing the session's earlier one of the same purpose; it works for five minutes. */
export async function prepareCeremony(
	id: string,
	ceremony: Omit<PasskeyCeremonyPayload, 'exp'>
): Promise<PasskeyCeremonyPayload> {
	const written = { ...ceremony, exp: epochTime() + CEREMONY_SECONDS };
	await ceremonies().upsert(id, written, CEREMONY_SECONDS);
	return written;
}

/* A live ceremony, read without spending it: what the page renders its form from. */
export async function liveCeremony(
	id: string
): Promise<PasskeyCeremonyPayload | undefined> {
	const record = await ceremonies().find(id);
	return record && record.exp > epochTime() ? record : undefined;
}

/*
 * Spends a ceremony at the act: answers it only to the one call that consumed it, while it is live and held by this
 * browser session. Of two racing posts of one ceremony, exactly one gets it.
 */
export async function takeCeremony(
	id: string,
	holder: string
): Promise<PasskeyCeremonyPayload | undefined> {
	const record = await liveCeremony(id);
	if (!record || record.holder !== holder) return undefined;
	if (!(await ceremonies().consume(id))) return undefined;
	/*
	 * Gone once spent: a consumed record still reads back as live until it expires, and the page must then prepare a
	 * fresh ceremony rather than show the spent one's options again.
	 */
	await ceremonies().destroy(id);
	return record;
}

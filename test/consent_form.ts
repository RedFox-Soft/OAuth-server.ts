import { Interaction } from 'lib/models/interaction.js';

/*
 * The account a consent page was shown for — the value its form posts back as `accountId`, without which
 * the server refuses the decision (lib/interactions/index.ts). Read from the interaction rather than
 * scraped from the page, so a spec that never renders the page can still submit the form a browser would.
 * Empty once the interaction is gone, which is what a browser resubmitting a stale page would send too.
 */
export async function shownAccount(uid: string): Promise<string> {
	const interaction = await Interaction.tryFind(uid);
	return interaction?.payload.session?.accountId ?? '';
}

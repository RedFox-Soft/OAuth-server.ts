import { CLOUD_CONSOLE, CLOUD_FLAGS_ON, CLOUD_FREE_FEATURES } from './cloud.ts';
import { loadExport, type GuideSituationEntry } from './export.ts';

/*
 * What the site's "What do you need?" page computes from the guide data (lib/consts/situation_guide.ts, through the
 * docs export). The console reads the instance it runs on; the site describes FoxAuth Cloud, so every mark here is
 * read for Cloud: its switched-on flags (cloud.ts) and its Free plan.
 */

export type GuideNeeds = GuideSituationEntry['needs'];

/*
 * - ready: a Cloud project can set it up now, so the answer gets the button.
 * - ownServer: Cloud cannot. A flag is off there, or it needs a super administrator, which a Cloud tenant never is.
 * - notOnFree: the Free plan leaves it out; a paid plan or your own server has it.
 * An answer that is both is ownServer: no plan would help.
 */
export type CloudMark = 'ready' | 'ownServer' | 'notOnFree';

/* The answers chosen when the address names none, so the page is never empty. */
export const DEFAULT_ANSWER = {
	product: 'server',
	enterprise: 'okta'
} as const;

/* The setting a guide flag is read from, as the server declares it (GUIDE_FLAG_SETTINGS, through the export). */
export function settingKey(flag: string): string {
	const key = loadExport().situationGuide.flagSettings[flag];
	if (!key) throw new Error(`The guide flag "${flag}" names no setting`);
	return key;
}

/* The setting's card on the Reference page: SettingCard gives each card its key as the id. */
export function settingHref(flag: string): string {
	return `/docs/reference/settings/#${settingKey(flag)}`;
}

function onCloud(flag: string): boolean {
	return CLOUD_FLAGS_ON.has(settingKey(flag));
}

export function cloudMark(needs: GuideNeeds): CloudMark {
	const flagOff = (needs.flags ?? []).some((flag) => !onCloud(flag));
	const noneOfAnyOf =
		needs.anyOf !== undefined &&
		needs.anyOf.length > 0 &&
		!needs.anyOf.some(onCloud);
	if (flagOff || noneOfAnyOf || needs.role === 'super') return 'ownServer';
	if (needs.planFeature && !CLOUD_FREE_FEATURES.has(needs.planFeature))
		return 'notOnFree';
	return 'ready';
}

/*
 * The console's door for a situation: after sign-in, or a free registration, it lands on the reader's project's guide
 * with this answer chosen. `?s=` opens it on the first tab, `?e=` on the Enterprise tab.
 */
export function startHref(situation: Pick<GuideSituationEntry, 'id' | 'tab'>) {
	const key = situation.tab === 'enterprise' ? 'e' : 's';
	return `${CLOUD_CONSOLE}/start?${key}=${encodeURIComponent(situation.id)}`;
}

/*
 * A prompt as the site shows it. The console fills in the project's own issuer; the site does not know the reader's
 * project, so it names where to find it. Prompts stay English in every language.
 */
export function renderPrompt(prompt: string): string {
	return prompt
		.replaceAll('{issuer}', "<your project's issuer, on its Overview>")
		.replaceAll('{discovery}', '<issuer>/.well-known/openid-configuration')
		.replaceAll('{console}', CLOUD_CONSOLE);
}

export type Persona = 'person' | 'program' | 'agent' | 'enterprise';

/* Who the answer is about, for the tag above its title: the same rule the console uses. */
export function personaOf(situation: GuideSituationEntry): Persona {
	if (situation.tab === 'enterprise') return 'enterprise';
	if (situation.ask) return situation.ask.actor;
	if (situation.lanes.some((l) => l.kind === 'agent')) return 'agent';
	if (situation.lanes.some((l) => l.kind === 'person')) return 'person';
	return 'program';
}

import type { EndUserProfile } from '../adapters/types.js';

/*
 * What an administrator may write into a local person's profile beyond the closed shape (specs/089): values
 * that reach applications as standard claims must be values those claims allow. OIDC Core §5.1 gives `locale`
 * as a BCP 47 tag, `zoneinfo` as a time-zone database name, and recommends E.164 for `phone_number`.
 *
 * The administrator's path only. A directory's data is the directory's: SCIM keeps accepting what it sends
 * (lib/scim/resource.ts), because refusing a sync over a locale spelling would stop a directory provisioning
 * people for a reason nobody on its side can see.
 */

export interface ProfileRefusal {
	field: string;
	message: string;
}

const E164 = /^\+[1-9]\d{1,14}$/;

function isLanguageTag(value: string): boolean {
	try {
		return Intl.getCanonicalLocales(value).length === 1;
	} catch {
		return false;
	}
}

function isTimeZone(value: string): boolean {
	try {
		new Intl.DateTimeFormat('en', { timeZone: value });
		return true;
	} catch {
		return false;
	}
}

export function validateProfile(
	profile: EndUserProfile
): ProfileRefusal | null {
	if (profile.locale !== undefined && !isLanguageTag(profile.locale)) {
		return {
			field: 'profile.locale',
			message: 'locale must be a language tag, such as en-US'
		};
	}
	if (profile.timezone !== undefined && !isTimeZone(profile.timezone)) {
		return {
			field: 'profile.timezone',
			message: 'timezone must be a time-zone name, such as Europe/Berlin'
		};
	}
	if (profile.phoneNumbers?.some((phone) => !E164.test(phone.value))) {
		return {
			field: 'profile.phoneNumbers',
			message:
				'a phone number must be in international form, such as +14155550100'
		};
	}
	return null;
}

/*
 * The profile fields an edit changed, as `profile.<field>` names for the audit entry — never their values.
 * The nested name and enterprise parts are named by their own fields (`profile.givenName`), which are unique
 * across the profile.
 */
export function changedProfileFields(
	before: EndUserProfile | undefined,
	after: EndUserProfile
): string[] {
	const leaves = (profile: EndUserProfile | undefined) => {
		const out = new Map<string, string>();
		for (const [key, value] of Object.entries(profile ?? {})) {
			if (
				(key === 'name' || key === 'enterprise') &&
				typeof value === 'object'
			) {
				for (const [inner, innerValue] of Object.entries(value)) {
					out.set(inner, JSON.stringify(innerValue));
				}
			} else {
				out.set(key, JSON.stringify(value));
			}
		}
		return out;
	};
	const old = leaves(before);
	const next = leaves(after);
	const names = new Set([...old.keys(), ...next.keys()]);
	return [...names]
		.filter((name) => old.get(name) !== next.get(name))
		.map((name) => `profile.${name}`)
		.sort();
}

/*
 * Which OpenID Connect standard claims (Core 1.0 §5.1) a provisioned profile yields. No specification maps
 * SCIM attributes to OIDC claims — not SCIM, not IPSIE, not FastFed — so this table is this server's own and
 * is declared once, here, where it can be read without the account code around it.
 *
 * Only claims with a clear counterpart are derived. Absent sources produce no claim at all, never `null`.
 * Which of these a client receives is still the claims setting's decision: each is released only under the
 * scope that setting maps to it, as every other claim is.
 *
 * Import-free on purpose (lib/consts/ holds declarations), so the shape it reads is restated structurally.
 */

interface ProfileSource {
	userName?: string;
	profile?: {
		name?: {
			formatted?: string;
			givenName?: string;
			familyName?: string;
			middleName?: string;
		};
		displayName?: string;
		nickName?: string;
		locale?: string;
		timezone?: string;
		phoneNumbers?: ReadonlyArray<{ value: string; primary?: boolean }>;
	};
}

/* The primary entry, else the only one; several with none marked primary name no single number. */
function primaryOf<T extends { primary?: boolean }>(
	entries: ReadonlyArray<T> | undefined
): T | undefined {
	if (!entries?.length) return undefined;
	return (
		entries.find((entry) => entry.primary) ??
		(entries.length === 1 ? entries[0] : undefined)
	);
}

export function profileClaims(user: ProfileSource): Record<string, string> {
	const { profile } = user;
	const claims: Record<string, string | undefined> = {
		preferred_username: user.userName,
		name: profile?.name?.formatted ?? profile?.displayName,
		given_name: profile?.name?.givenName,
		family_name: profile?.name?.familyName,
		middle_name: profile?.name?.middleName,
		nickname: profile?.nickName,
		locale: profile?.locale,
		zoneinfo: profile?.timezone,
		phone_number: primaryOf(profile?.phoneNumbers)?.value
	};
	return Object.fromEntries(
		Object.entries(claims).filter(
			(entry): entry is [string, string] => entry[1] !== undefined
		)
	);
}

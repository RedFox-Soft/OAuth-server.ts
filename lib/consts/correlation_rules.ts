/*
 * The two correlation rules this server recommends, as data. Import-free so the directory catalogue
 * (./known_directories.ts) and the connection default (lib/provisioning/correlation.ts) state the same pair
 * from one place rather than two copies that drift.
 *
 * Microsoft's `oid` is the object id Entra also sends to SCIM as `externalId`, stable across every
 * application in the tenant; its `sub` is pairwise, so it can never be the key (issue #62). Every other
 * provider starts from `preferred_username` ↔ `userName`, which is what Okta sends.
 */

export interface CorrelationRule {
	readonly claim: string;
	readonly attribute: 'externalId' | 'userName';
}

export const MICROSOFT_CORRELATION: CorrelationRule = {
	claim: 'oid',
	attribute: 'externalId'
};

export const DEFAULT_CORRELATION: CorrelationRule = {
	claim: 'preferred_username',
	attribute: 'userName'
};

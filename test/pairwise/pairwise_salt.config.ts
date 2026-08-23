import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Pairwise identifier fixtures — spec 023.
 *
 * Deliberately declares NO `addons` export. The pairwise fixtures in test/claims/ and
 * test/introspection/ override `pairwiseIdentifier` with a stub, which is right for what those suites
 * assert (masking and endpoint access) and useless here: this suite is about the real derivation, so
 * it must run the real one.
 *
 * No existing config registers two clients under one sector identifier, which is what the scoping
 * assertions need. With no `sectorIdentifierUri`, a pairwise client's sector is the HOST of its first
 * redirect_uri (lib/helpers/sector_identifier.ts) — so `pairwise-one` and `pairwise-one-sibling` share
 * a sector by sharing a host while differing in path, and `pairwise-two` is in another sector by
 * having another host. Getting that wrong silently turns the "same sector, same sub" case into a
 * tautology, which is why the paths differ: two identical clients would prove nothing.
 */

export const ApplicationConfig = {
	'introspection.enabled': true,
	'userinfo.enabled': true
};

export const clients = [
	{
		clientId: 'public-one',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://rp-one.example.com/cb']
	},
	{
		clientId: 'pairwise-one',
		clientSecret: 'secret',
		subjectType: 'pairwise',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://rp-one.example.com/cb']
	},
	{
		clientId: 'pairwise-one-sibling',
		clientSecret: 'secret',
		subjectType: 'pairwise',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://rp-one.example.com/sibling/cb']
	},
	{
		clientId: 'pairwise-two',
		clientSecret: 'secret',
		subjectType: 'pairwise',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://rp-two.example.com/cb']
	}
];

export default {
	config
};

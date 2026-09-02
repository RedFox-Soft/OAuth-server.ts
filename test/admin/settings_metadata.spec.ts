import { describe, it, expect } from 'bun:test';
import {
	SETTINGS_CATALOG,
	SETTING_DOMAINS,
	type SettingDomain
} from 'lib/admin/settings/catalog.ts';
import { hasDetail } from 'lib/admin/ui/settings/model.ts';

/*
 * The presentation metadata the console navigates by: which pane a setting appears on, the one line
 * shown next to its control, the unit suffix on a number, and whether changing it has a security
 * consequence worth confirming.
 *
 * Kept apart from settings_catalog.spec.ts on purpose. That file pins what the catalog *is* — which
 * keys exist, what may never be reachable through the admin API. This one pins that every key is
 * presentable: a descriptor the console cannot file, summarise or label is not a validation failure,
 * it is a setting an operator meets as an unexplained control on a pane that may not exist.
 */
describe('settings catalog presentation metadata', () => {
	const DOMAIN_IDS = SETTING_DOMAINS.map((d) => d.id);

	it('declares an ordered, non-empty domain list with labels and blurbs', () => {
		expect(SETTING_DOMAINS.length).toBeGreaterThan(0);
		const seen = new Set<string>();
		for (const domain of SETTING_DOMAINS) {
			expect(seen.has(domain.id)).toBe(false);
			seen.add(domain.id);
			expect(domain.label.length).toBeGreaterThan(0);
			expect(domain.blurb.length).toBeGreaterThan(0);
		}
	});

	it('files every setting under a declared domain', () => {
		for (const d of SETTINGS_CATALOG) {
			expect(DOMAIN_IDS).toContain(d.domain);
		}
	});

	/*
	 * A pane with nothing on it is a dead entry in the sub-nav. Enforced rather than trusted because
	 * the failure is invisible from the catalog side: a domain loses its last setting the moment one
	 * key is re-filed, and nothing else complains.
	 */
	it('leaves no domain without settings', () => {
		const occupied = new Set<SettingDomain>(
			SETTINGS_CATALOG.map((d) => d.domain)
		);
		expect(DOMAIN_IDS.filter((id) => !occupied.has(id))).toEqual([]);
	});

	/*
	 * The console renders one card per group inside one pane, so a group split across two domains
	 * would render as two cards with the same heading in different places.
	 */
	it('keeps every group within a single domain', () => {
		const domainByGroup = new Map<string, SettingDomain>();
		for (const d of SETTINGS_CATALOG) {
			const already = domainByGroup.get(d.group);
			if (already === undefined) domainByGroup.set(d.group, d.domain);
			else expect(already).toBe(d.domain);
		}
	});

	/*
	 * The summary is what an operator reads while scanning; the description is what they read once
	 * they have stopped on one row. Bounding the summary is what keeps the two from collapsing back
	 * into a single wall of prose — the shape this page had before.
	 */
	it('gives every setting a one-line summary distinct from its label', () => {
		for (const d of SETTINGS_CATALOG) {
			expect(d.summary.length).toBeGreaterThan(0);
			expect(d.summary.length).toBeLessThanOrEqual(100);
			expect(d.summary).not.toContain('\n');
			expect(d.summary).not.toBe(d.label);
			expect(d.summary).not.toBe(d.description);
		}
	});

	/*
	 * Not every setting has a long form worth reading. Seventeen descriptions are terser than the
	 * summary written for them — 'Requires mTLS enabled.', 'Enables Token Revocation.' — because the
	 * key and the label already said it. Those rows must not offer a disclosure that opens onto less
	 * than the line above it, which is what `hasDetail` decides; this pins that the distinction is
	 * real in the data rather than a rule the console applies to nothing.
	 */
	it('leaves some settings with no long form, and most with one', () => {
		const withDetail = SETTINGS_CATALOG.filter((d) => hasDetail(d));
		const without = SETTINGS_CATALOG.filter((d) => !hasDetail(d));

		expect(withDetail.length).toBeGreaterThan(0);
		expect(without.length).toBeGreaterThan(0);
		// Whatever is offered as detail genuinely says more than the summary it sits under.
		for (const d of withDetail) {
			expect(d.description.length).toBeGreaterThan(d.summary.length);
		}
	});

	/*
	 * Every number on this page is a quantity of something — seconds, days, requests, faults — and
	 * none of them says so today. Required on numbers and refused elsewhere, so the suffix cannot
	 * drift onto a control that has no room for it.
	 */
	it('labels every numeric setting with a unit, and only numeric settings', () => {
		for (const d of SETTINGS_CATALOG) {
			if (d.type === 'number') {
				expect(d.unit).toBeDefined();
				expect(d.unit?.length).toBeGreaterThan(0);
				expect(d.unit?.length).toBeLessThanOrEqual(12);
			} else {
				expect(d.unit).toBeUndefined();
			}
		}
	});

	/*
	 * The security flag drives a confirmation step on save, so the set it covers is pinned rather than
	 * described: a setting that weakens the server silently losing its flag is exactly the regression
	 * an assertion on "some settings are flagged" would not catch.
	 */
	it('flags every setting whose change has a security consequence', () => {
		const flagged = SETTINGS_CATALOG.filter((d) => d.risk === 'security')
			.map((d) => d.key as string)
			.sort();

		expect(flagged).toEqual(
			[
				'authorization.allowOmittingSingleRegisteredRedirectUri',
				'conformIdTokenClaims',
				'cors.enabled',
				'par.allowUnregisteredRedirectUris',
				'rateLimit.enabled',
				'rateLimit.trustedProxy'
			].sort()
		);
		/*
		 * `dpop.allowReplay` was the seventh until the settings audit demoted it to boot configuration.
		 * A flag is only useful on a setting the console can reach, so its absence here follows from its
		 * absence from the catalog — asserted at the source in settings_catalog.spec.ts.
		 */
		expect(flagged).not.toContain('dpop.allowReplay');
	});

	it('admits no risk value other than the declared one', () => {
		for (const d of SETTINGS_CATALOG) {
			if (d.risk !== undefined) expect(d.risk).toBe('security');
		}
	});
});

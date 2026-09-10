import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	calculateDiscovery,
	metadataClassification
} from 'lib/configs/discoverySupport.js';

/*
 * The two-way drift guard over the metadata classification, in the shape of discovery_map.spec.ts.
 *
 * A total Record already makes an unclassified member a type error, but tsc is not this repository's
 * merge gate — `bun run format` and `bun test` are, and the typecheck carries a large pre-existing
 * error baseline in which one more error is not a stop signal. So the totality is asserted here too,
 * where it fails on the gate that actually blocks, naming the member.
 *
 * Read against calculateDiscovery() rather than against a fetched document: the served body has
 * already been pruned by feature flag and extended by operator overrides, and neither of those is
 * what this table is total over.
 */
/**
 * @proves Every member the discovery document can produce is classified, nothing stale is
 * declared, and every coherence-admitted member is anchored to one that still exists.
 */
describe('discovery metadata classification', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'all_features' });
	});

	const computed = () => Object.keys(calculateDiscovery());
	const classified = () => Object.keys(metadataClassification);

	it('classifies every member the discovery document can produce', () => {
		const unclassified = computed().filter(
			(member) => !(member in metadataClassification)
		);

		expect(
			unclassified,
			`unclassified discovery member(s): ${unclassified.join(', ')} — add an entry to metadataClassification saying which document each belongs to`
		).toEqual([]);
	});

	it('declares no entry for a member the discovery document no longer produces', () => {
		const computedKeys = new Set(computed());
		const stale = classified().filter((member) => !computedKeys.has(member));

		expect(
			stale,
			`stale classification entr(ies): ${stale.join(', ')} — calculateDiscovery no longer produces these`
		).toEqual([]);
	});

	/*
	 * The third direction, and the one a plain totality check misses. Twelve members are in the OAuth
	 * document only because an OAuth-registered member would be unreadable without them. Remove that
	 * anchor — or reclassify it to `oidc` — and those twelve keep their place on a justification that
	 * no longer holds, with nothing to report it.
	 */
	it('anchors every coherence-admitted member to a member that still exists and is itself shared', () => {
		const document = calculateDiscovery() as Record<string, unknown>;
		const orphaned: string[] = [];

		for (const [member, classification] of Object.entries(
			metadataClassification
		)) {
			if (!('coherentWith' in classification)) continue;

			const anchor = classification.coherentWith;
			const anchorClassification = metadataClassification[anchor];

			if (!(anchor in document)) {
				orphaned.push(`${member} → ${anchor} (no longer produced)`);
			} else if (anchorClassification?.audience !== 'both') {
				orphaned.push(
					`${member} → ${anchor} (anchor is not in both documents)`
				);
			}
		}

		expect(
			orphaned,
			`coherence justification(s) no longer hold: ${orphaned.join('; ')}`
		).toEqual([]);
	});
});

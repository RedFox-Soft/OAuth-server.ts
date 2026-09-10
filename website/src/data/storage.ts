import { loadExport } from './export.ts';

/*
 * How the site talks about the datastore, in one place, derived from the server.
 *
 * This exists because of a specific failure. When PostgreSQL shipped, the documentation pages were
 * updated by name from a task list and everything else was not: five comparison tables, the feature
 * grid and the home page went on saying the server stores its data in MongoDB, and the Zitadel
 * comparison offered "most teams already run PostgreSQL; fewer already run MongoDB" as a reason to
 * choose the competitor. Nothing failed, because prose is not checked against anything.
 *
 * So the sentence is computed from `docs-export.json`, whose `storage.backends` comes from
 * `lib/adapters/selectBackend.ts` — the module that actually makes the choice. A third backend
 * changes this text by existing. `scripts/seo/verify.ts` covers the copy that cannot be computed,
 * by failing any marketing or comparison page that names one production datastore and omits another.
 */

export interface StorageBackend {
	name: string;
	selectedBy: string;
	label: string;
}

export function storageBackends(): StorageBackend[] {
	return loadExport().storage.backends;
}

/** Just the words: `['PostgreSQL', 'MongoDB']`. */
export function backendLabels(): string[] {
	return storageBackends().map((backend) => backend.label);
}

/** `PostgreSQL or MongoDB` — for a sentence that offers a choice. */
export function backendChoice(): string {
	const labels = backendLabels();
	if (labels.length <= 1) return labels[0] ?? '';
	return `${labels.slice(0, -1).join(', ')} or ${labels[labels.length - 1]}`;
}

/** `PostgreSQL, MongoDB and in-memory` — for a sentence that lists what ships. */
export function backendList(trailing?: string): string {
	const labels = [...backendLabels(), ...(trailing ? [trailing] : [])];
	if (labels.length <= 1) return labels[0] ?? '';
	return `${labels.slice(0, -1).join(', ')} and ${labels[labels.length - 1]}`;
}

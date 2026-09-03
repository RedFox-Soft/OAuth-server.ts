import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'astro/zod';

const VersionSchema = z.object({
	version: z.string(),
	lastTag: z.string().nullable(),
	commit: z.string(),
	unreleased: z.boolean(),
	generatedAt: z.string()
});

export type VersionInfo = z.infer<typeof VersionSchema>;

export function loadVersion(): VersionInfo {
	// Not import.meta.dirname: the SSR/prerender bundler relocates this module into
	// dist/.prerender/chunks/, which breaks a path relative to the source file's own location.
	// Every documented invocation (dev/check/build/preview) runs with cwd = website/.
	const file = resolve(process.cwd(), 'generated/version.json');
	let raw: unknown;
	try {
		raw = JSON.parse(readFileSync(file, 'utf8'));
	} catch (error) {
		throw new Error(
			`generated/version.json is missing or unreadable — run \`bun run generate\` (${String(error)})`
		);
	}
	try {
		return VersionSchema.parse(raw);
	} catch (error) {
		throw new Error(
			`generated/version.json is malformed — run \`bun run generate\`: ${String(error)}`
		);
	}
}

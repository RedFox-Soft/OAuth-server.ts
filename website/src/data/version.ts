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
	const file = resolve(import.meta.dirname, '../../generated/version.json');
	return VersionSchema.parse(JSON.parse(readFileSync(file, 'utf8')));
}

import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

export const collections = {
	docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
	/*
	 * The repository's own documents, rendered rather than copied: a copy under website/ would be the
	 * one that goes stale. The base is the repository root, one level above the Astro project.
	 *
	 * LICENSE is deliberately absent: the glob loader dispatches on file extension and silently skips
	 * an extensionless file (the entry never appears, with no warning). license.astro therefore reads
	 * it with `fs` and renders it with `marked`, the same way it already has to for NOTICE.
	 */
	root: defineCollection({
		loader: glob({ base: '..', pattern: ['CHANGELOG.md', 'SECURITY.md'] }),
		schema: z.object({}).passthrough()
	})
};

import { defineCollection } from 'astro:content';
import { z } from 'astro/zod';
import { glob } from 'astro/loaders';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

/*
 * `yes` built in · `flag` available but switched on, previewed or paid for · `no` not available ·
 * `unknown` the documentation did not say · `na` the question does not apply to this product.
 */
const CompareCell = z.object({
	status: z.enum(['yes', 'flag', 'no', 'unknown', 'na']),
	text: z.string()
});

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
		schema: z.looseObject({})
	}),
	/*
	 * The comparison pages. `sources` is required and non-empty by intent: every claim about another
	 * product has to be checkable against a page we actually read, and `lastChecked` dates that
	 * reading, because their products move.
	 */
	compare: defineCollection({
		loader: glob({ base: './src/content/compare', pattern: '**/*.mdx' }),
		schema: z.object({
			title: z.string(),
			competitor: z.string(),
			description: z.string(),
			lastChecked: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
			sources: z.array(z.string().url()),
			/* One sentence a reader can act on before reading a single row. */
			bottomLine: z.string(),
			chooseThem: z.array(z.string()).min(1),
			chooseUs: z.array(z.string()).min(1),
			/*
			 * The table as data rather than Markdown, so every row must carry a verdict and a reason —
			 * a comparison that only lists facts leaves the reader to do the comparing.
			 */
			groups: z
				.array(
					z.object({
						label: z.string(),
						rows: z.array(
							z.object({
								dimension: z.string(),
								us: CompareCell,
								them: CompareCell,
								verdict: z.enum(['us', 'them', 'even', 'different']),
								why: z.string(),
								/* What the competitor's documentation literally says; kept for verifiability. */
								note: z.string().optional()
							})
						)
					})
				)
				.min(1)
		})
	})
};

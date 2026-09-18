import { defineCollection } from 'astro:content';
import { z } from 'astro/zod';
import { glob } from 'astro/loaders';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { backendLabels } from './data/storage.ts';

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
							z
								.object({
									dimension: z.string(),
									us: CompareCell,
									them: CompareCell,
									verdict: z.enum(['us', 'them', 'even', 'different']),
									why: z.string(),
									/* What the competitor's documentation literally says; kept for verifiability. */
									note: z.string().optional()
								})
								/*
								 * Our own cell may not describe a world with fewer datastores than ship.
								 *
								 * Checked here rather than in the post-build sweep because on a comparison page
								 * the *competitor's* cell routinely names PostgreSQL, so a scan of the rendered
								 * page is satisfied by text that says nothing about us. That is not a hypothetical:
								 * the first version of this guard was a page-level scan, and it passed a
								 * deliberately reverted row without a murmur.
								 *
								 * The backend list comes from `docs-export.json`, which takes it from
								 * `lib/adapters/selectBackend.ts`. A third backend therefore fails every
								 * comparison whose storage sentence has not been rewritten, by file and by field.
								 */
								.superRefine((row, ctx) => {
									const labels = backendLabels();
									if (labels.length < 2) return;

									const named = labels.filter((label) =>
										row.us.text.includes(label)
									);
									if (named.length === 0 || named.length === labels.length)
										return;

									ctx.addIssue({
										code: z.ZodIssueCode.custom,
										path: ['us', 'text'],
										message:
											`the "${row.dimension}" row names ${named.join(', ')} but not ` +
											`${labels.filter((label) => !named.includes(label)).join(', ')}. ` +
											'Every datastore that ships has to appear in a sentence that describes ours.'
									});
								})
						)
					})
				)
				.min(1),
			/*
			 * The questions this comparison provokes, answered. One array feeds both the visible
			 * section and the machine-readable description, so the two cannot disagree — and the
			 * guardrail's existing overclaim rule proves it on every build by requiring every
			 * answer to appear in the rendered text. Optional so a page can ship before its
			 * questions are written.
			 */
			faq: z
				.array(
					z.object({
						/* In the words a reader would use, not assembled from search terms. */
						question: z.string().min(1),
						/* Must stay true and comprehensible quoted alone, without its question. */
						answer: z.string().min(1)
					})
				)
				.optional()
		})
	}),
	/*
	 * The blog. An author writes one file here and everything else follows: the page, the index
	 * entry, the sitemap entry, the card, the Markdown alternate, the feed item and the structured
	 * description are all derived, and no other file is edited to publish.
	 *
	 * The fields below are the whole authoring contract, so what is absent is as deliberate as what
	 * is present. There is no `author` — attribution is fixed to the organisation, so a per-article
	 * field would have one legal value. No `slug` — the filename is the slug, and a second source
	 * for one value is a second thing to keep in step. No `coverImage` — no binary asset is
	 * committed to this repository, and the social card is rendered after the build.
	 */
	blog: defineCollection({
		loader: glob({ base: './src/content/blog', pattern: '**/*.mdx' }),
		schema: z.object({
			title: z.string().min(1),
			description: z.string().min(1),
			publishedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
			/*
			 * An editorial claim to the reader, not a fact about the repository — the sitemap's
			 * lastmod is the latter and comes from git. Kept separate on purpose: a typo fix moves
			 * the git date and must not claim the article was revised.
			 */
			updatedAt: z
				.string()
				.regex(/^\d{4}-\d{2}-\d{2}$/)
				.optional(),
			draft: z.boolean().default(false),
			/* Shown on the article and used to relate articles. No page is generated per tag. */
			tags: z.array(z.string()).default([]),
			/*
			 * Set only by an article genuinely about running on one backend. It exempts the
			 * article's prose from the rule that fails any marketing sentence naming one datastore
			 * and not the others — and it pays for that exemption by being stated to the reader on
			 * the page, rather than hidden in a list of excused routes. The permitted values come
			 * from the server's own backend list, so retiring a backend fails every article scoped
			 * to it instead of leaving the claim standing.
			 */
			storageScope: z
				.string()
				.refine((value) => backendLabels().includes(value), {
					message: `storageScope must name a datastore that ships: ${backendLabels().join(', ')}`
				})
				.optional()
		})
	})
};

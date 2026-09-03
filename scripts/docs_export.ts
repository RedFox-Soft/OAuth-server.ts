import * as path from 'node:path';

/*
 * Writes the documentation export the website builds its Reference section from.
 *
 * Runs on a bare checkout: the release workflow has no database and sets no ISSUER. So the
 * environment is chosen here, before anything under lib/ loads. `lib/adapters/index.ts` selects the
 * Mongo adapter and configStore off `MONGODB_URI` alone — not off `NODE_ENV` — so those two variables
 * are deleted here to force the in-memory stores regardless of what the shell or a dotenv file (Bun
 * loads `.env.local` before any script line runs) provides; otherwise the export's `value` fields
 * would carry a live database's settings instead of the shipped defaults. `NODE_ENV=test` is still
 * needed separately, to swap in the in-memory `Adapter`. The ISSUER value is a placeholder nothing in
 * the export depends on. Dynamic imports keep this ordering honest; a static import would evaluate
 * lib/configs/env.ts first and throw.
 */
delete process.env.MONGODB_URI;
delete process.env.DATABASE_NAME;
process.env.NODE_ENV ??= 'test';
process.env.ISSUER ??= 'https://docs-export.invalid';

const output = process.argv[2] ?? path.join('dist', 'docs-export.json');

const { buildDocsExport } = await import('../lib/docs_export/build.ts');
const pkg = (await Bun.file(
	new URL('../package.json', import.meta.url)
).json()) as { version: string };

const data = buildDocsExport({
	version: pkg.version,
	generatedAt: new Date().toISOString()
});

await Bun.write(output, `${JSON.stringify(data, null, 2)}\n`);
console.log(
	`${output}: ${data.settings.entries.length} settings, ${data.endpoints.length} endpoints, ${data.mcp.tools.length} MCP tools, ${data.addonSeams.length} addon seams`
);
process.exit(0);

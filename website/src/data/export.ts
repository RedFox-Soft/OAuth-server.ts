import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'astro/zod';

/*
 * The Reference section renders only from this file. The schema is deliberately strict about the
 * fields the pages use and permissive (passthrough) about the rest, so a new field in the export
 * does not break the site while a missing or renamed field the pages depend on fails the build with
 * a named path rather than an empty page.
 */
const Setting = z
	.object({
		key: z.string(),
		domain: z.string(),
		group: z.string(),
		label: z.string(),
		summary: z.string(),
		description: z.string(),
		type: z.string(),
		options: z.array(z.string()).optional(),
		unit: z.string().optional(),
		dependsOn: z.string().nullable(),
		risk: z.string().optional(),
		experimental: z.boolean().optional(),
		value: z.unknown()
	})
	.passthrough();

const Endpoint = z.object({
	method: z.string(),
	path: z.string(),
	flag: z.string().nullable(),
	cors: z.enum(['open', 'client-based', 'none']),
	rate: z.enum(['strict', 'ordinary', 'public', 'exempt'])
});

const McpTool = z
	.object({
		tool: z.string(),
		method: z.string(),
		path: z.string(),
		action: z.string().nullable(),
		consequence: z.enum(['read', 'ordinary', 'high']),
		summary: z.string(),
		bodySchema: z.record(z.string(), z.unknown()).nullable(),
		querySchema: z.record(z.string(), z.unknown()).nullable()
	})
	.passthrough();

export const DocsExportSchema = z.object({
	schemaVersion: z.literal(1),
	version: z.string(),
	generatedAt: z.string(),
	settings: z.object({
		domains: z.array(
			z.object({ id: z.string(), label: z.string(), blurb: z.string() })
		),
		entries: z.array(Setting)
	}),
	endpoints: z.array(Endpoint),
	alwaysAvailablePrefixes: z.array(z.string()),
	adminApi: z.object({
		audited: z.array(
			z.object({
				action: z.string(),
				method: z.string(),
				path: z.string(),
				targetType: z.string()
			})
		)
	}),
	mcp: z.object({
		tools: z.array(McpTool),
		excluded: z.array(
			z.object({
				method: z.string(),
				path: z.string(),
				reason: z.string(),
				absence: z.enum(['withheld', 'inapplicable'])
			})
		)
	}),
	addonSeams: z.array(z.string()),
	environment: z.array(
		z.object({
			name: z.string(),
			requirement: z.enum(['required', 'optional', 'test-only']),
			description: z.string(),
			example: z.string().optional()
		})
	)
});

export type DocsExport = z.infer<typeof DocsExportSchema>;
export type SettingEntry = z.infer<typeof Setting>;
export type EndpointEntry = z.infer<typeof Endpoint>;
export type McpToolEntry = z.infer<typeof McpTool>;

let cached: DocsExport | undefined;

export function loadExport(): DocsExport {
	if (cached) return cached;
	const file = resolve(import.meta.dirname, '../../generated/docs-export.json');
	let raw: unknown;
	try {
		raw = JSON.parse(readFileSync(file, 'utf8'));
	} catch (error) {
		throw new Error(
			`generated/docs-export.json is missing or unreadable — run \`bun run generate\` (${String(error)})`
		);
	}
	cached = DocsExportSchema.parse(raw);
	return cached;
}

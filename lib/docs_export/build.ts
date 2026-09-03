import {
	SETTINGS_CATALOG,
	SETTING_DOMAINS,
	type SettingDescriptor
} from '../admin/settings/catalog.js';
import { ApplicationConfig } from '../configs/application.js';
import {
	alwaysAvailablePrefixes,
	alwaysAvailableRoutes,
	corsClassForPattern,
	gatedRoutes,
	rateClassForPattern,
	type CorsClass,
	type RateClass
} from '../consts/route_classification.js';
import {
	auditedAdminRoutes,
	type AuditedAdminRoute
} from '../consts/admin_audit_routes.js';
import {
	excludedConsoleOperations,
	mcpCatalogue,
	type ExcludedConsoleOperation,
	type McpTool
} from '../mcp/catalogue.js';
import { ADDON_SEAMS } from '../addon/seams.js';
import {
	ENVIRONMENT_VARIABLES,
	type EnvironmentVariable
} from './environment.js';

/*
 * What the website builds its Reference section from. Assembled from the tables the server already
 * keeps as data and guards with drift tests — the settings catalogue, the route classification, the
 * MCP catalogue, the audit route table — so a reference page cannot describe a setting or a route the
 * server does not have, and cannot be edited by hand into disagreement with it.
 *
 * Imports catalogues and tables only, never a route module: `lib/admin/routes.ts` reaches the MongoDB
 * adapter, which connects at import time, and this must be buildable from a checkout with no database.
 *
 * `schemaVersion` is the contract the site pins. Bump it when a field changes shape; add fields freely.
 */

export interface SettingExport extends Omit<
	SettingDescriptor,
	'key' | 'dependsOn'
> {
	readonly key: string;
	readonly dependsOn: string | null;
	/* The value on this build's ApplicationConfig — the shipped default when nothing overrides it. */
	readonly value: unknown;
}

export interface EndpointExport {
	readonly method: string;
	readonly path: string;
	/* The governing feature flag, or null when the route is always served. */
	readonly flag: string | null;
	readonly cors: CorsClass;
	readonly rate: RateClass;
}

export interface McpToolExport extends Omit<
	McpTool,
	'bodySchema' | 'querySchema'
> {
	readonly bodySchema: Record<string, unknown> | null;
	readonly querySchema: Record<string, unknown> | null;
}

export interface DocsExport {
	readonly schemaVersion: 1;
	readonly version: string;
	readonly generatedAt: string;
	readonly settings: {
		readonly domains: typeof SETTING_DOMAINS;
		readonly entries: readonly SettingExport[];
	};
	readonly endpoints: readonly EndpointExport[];
	readonly alwaysAvailablePrefixes: readonly string[];
	readonly adminApi: {
		readonly audited: readonly AuditedAdminRoute[];
	};
	readonly mcp: {
		readonly tools: readonly McpToolExport[];
		readonly excluded: readonly ExcludedConsoleOperation[];
	};
	readonly addonSeams: readonly string[];
	readonly environment: readonly EnvironmentVariable[];
}

export interface DocsExportStamp {
	readonly version: string;
	readonly generatedAt: string;
}

// TypeBox schemas carry symbol-keyed metadata; a JSON round-trip is what strips it to plain data.
function asJson(schema: unknown): Record<string, unknown> | null {
	return schema === null || schema === undefined
		? null
		: (JSON.parse(JSON.stringify(schema)) as Record<string, unknown>);
}

function exportSetting(descriptor: SettingDescriptor): SettingExport {
	const { key, dependsOn, ...rest } = descriptor;
	return {
		...rest,
		key,
		dependsOn: dependsOn ?? null,
		value: ApplicationConfig[key]
	};
}

function exportEndpoint(
	route: { method: string; path: string },
	flag: string | null
): EndpointExport {
	return {
		method: route.method,
		path: route.path,
		flag,
		cors: corsClassForPattern(route.method, route.path),
		rate: rateClassForPattern(route.method, route.path)
	};
}

function exportTool(tool: McpTool): McpToolExport {
	const { bodySchema, querySchema, ...rest } = tool;
	return {
		...rest,
		bodySchema: asJson(bodySchema),
		querySchema: asJson(querySchema)
	};
}

export function buildDocsExport(stamp: DocsExportStamp): DocsExport {
	return {
		schemaVersion: 1,
		version: stamp.version,
		generatedAt: stamp.generatedAt,
		settings: {
			domains: SETTING_DOMAINS,
			entries: SETTINGS_CATALOG.map(exportSetting)
		},
		endpoints: [
			...alwaysAvailableRoutes.map((route) => exportEndpoint(route, null)),
			...gatedRoutes.map((route) => exportEndpoint(route, route.flag))
		],
		alwaysAvailablePrefixes: [...alwaysAvailablePrefixes],
		adminApi: { audited: [...auditedAdminRoutes] },
		mcp: {
			tools: mcpCatalogue.map(exportTool),
			excluded: [...excludedConsoleOperations]
		},
		addonSeams: [...ADDON_SEAMS],
		environment: ENVIRONMENT_VARIABLES
	};
}

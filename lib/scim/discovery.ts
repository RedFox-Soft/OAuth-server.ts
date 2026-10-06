import {
	SCIM_ENTERPRISE_ATTRIBUTES,
	SCIM_ENTERPRISE_USER_SCHEMA,
	SCIM_LIST_RESPONSE,
	SCIM_MAX_PAGE,
	SCIM_RESOURCE_TYPE_SCHEMA,
	SCIM_SCHEMA_SCHEMA,
	SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA,
	SCIM_USER_ATTRIBUTES,
	SCIM_USER_SCHEMA,
	type ScimAttribute
} from '../consts/scim.js';
import { ScimError } from './errors.js';

/*
 * The three discovery endpoints (RFC 7644 §4), generated from the declared attribute table so what is
 * advertised is exactly what is accepted. Nothing here describes a credential (IPSIE §6.1.2), and bulk,
 * sort, ETags and password change are declared unsupported because they are.
 */

export function serviceProviderConfig(
	base: string,
	strict: boolean
): Record<string, unknown> {
	return {
		schemas: [SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA],
		patch: { supported: true },
		/* IPSIE §4.3 requires /Bulk; no v1 client calls it. A documented deviation (CONFORMANCE.md). */
		bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
		filter: { supported: true, maxResults: SCIM_MAX_PAGE },
		changePassword: { supported: false },
		sort: { supported: false },
		etag: { supported: false },
		authenticationSchemes: [
			{
				type: 'oauthbearertoken',
				name: 'OAuth Bearer Token',
				description:
					'A scim-scoped access token from this bucket’s token endpoint, or the connection’s static token',
				specUri: 'https://www.rfc-editor.org/info/rfc6750',
				primary: true
			}
		],
		/*
		 * Claimed only in strict mode, the one mode in which every request the SCIM 2.0 Interoperability
		 * Profile tells a service provider to refuse is refused (spec FR-034a).
		 */
		...(strict ? { interopProfileConformant: true } : {}),
		meta: {
			resourceType: 'ServiceProviderConfig',
			location: `${base}/ServiceProviderConfig`
		}
	};
}

function describe(attribute: ScimAttribute): Record<string, unknown> {
	return {
		name: attribute.name,
		type: attribute.type,
		multiValued: attribute.multiValued,
		description: attribute.description,
		required: attribute.required,
		caseExact: attribute.caseExact,
		mutability: attribute.mutability,
		returned: 'default',
		uniqueness: attribute.uniqueness,
		...(attribute.subAttributes
			? { subAttributes: attribute.subAttributes.map(describe) }
			: {})
	};
}

function schemaResource(
	base: string,
	id: string,
	name: string,
	description: string,
	attributes: readonly ScimAttribute[]
): Record<string, unknown> {
	return {
		schemas: [SCIM_SCHEMA_SCHEMA],
		id,
		name,
		description,
		attributes: attributes.map(describe),
		meta: { resourceType: 'Schema', location: `${base}/Schemas/${id}` }
	};
}

function schemaResources(base: string): Record<string, unknown>[] {
	return [
		schemaResource(
			base,
			SCIM_USER_SCHEMA,
			'User',
			'An end user of this bucket',
			SCIM_USER_ATTRIBUTES
		),
		schemaResource(
			base,
			SCIM_ENTERPRISE_USER_SCHEMA,
			'EnterpriseUser',
			'Enterprise attributes of an end user',
			SCIM_ENTERPRISE_ATTRIBUTES
		)
	];
}

function userResourceType(base: string): Record<string, unknown> {
	return {
		schemas: [SCIM_RESOURCE_TYPE_SCHEMA],
		id: 'User',
		name: 'User',
		endpoint: '/Users',
		description: 'End users of this bucket',
		schema: SCIM_USER_SCHEMA,
		schemaExtensions: [
			{ schema: SCIM_ENTERPRISE_USER_SCHEMA, required: false }
		],
		meta: {
			resourceType: 'ResourceType',
			location: `${base}/ResourceTypes/User`
		}
	};
}

function listOf(resources: Record<string, unknown>[]): Record<string, unknown> {
	return {
		schemas: [SCIM_LIST_RESPONSE],
		totalResults: resources.length,
		startIndex: 1,
		itemsPerPage: resources.length,
		Resources: resources
	};
}

export function schemas(base: string): Record<string, unknown> {
	return listOf(schemaResources(base));
}

export function schemaById(base: string, id: string): Record<string, unknown> {
	const found = schemaResources(base).find(
		(s) => String(s.id).toLowerCase() === id.toLowerCase()
	);
	if (!found) throw new ScimError(404, undefined, 'no such schema');
	return found;
}

export function resourceTypes(base: string): Record<string, unknown> {
	return listOf([userResourceType(base)]);
}

export function resourceTypeById(
	base: string,
	id: string
): Record<string, unknown> {
	if (id.toLowerCase() !== 'user') {
		throw new ScimError(404, undefined, 'no such resource type');
	}
	return userResourceType(base);
}

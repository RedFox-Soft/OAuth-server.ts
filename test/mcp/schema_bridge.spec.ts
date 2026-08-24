import { describe, it, expect } from 'bun:test';
import { fromJsonSchema } from '@modelcontextprotocol/server';

import {
	CreateProjectBody,
	UpdateProjectBody,
	SetBucketBody
} from 'lib/admin/projects/schema.ts';
import {
	CreateBucketBody,
	UpdateBucketBody
} from 'lib/admin/buckets/schema.ts';
import {
	CreateClientBody,
	UpdateClientBody
} from 'lib/admin/clients/schema.ts';

/*
 * T004. The feature's schema story (research.md D2) is that a tool's input schema IS the TypeBox
 * schema the admin route validates against — one object, so the schema an agent reads to build a
 * call cannot drift from the schema the route enforces.
 *
 * That rests on two claims worth measuring rather than assuming: TypeBox emits plain JSON Schema,
 * and the SDK's `fromJsonSchema` accepts the particular shapes these schemas use. The shape D2
 * flagged as the open risk is `t.Union([t.Literal(...)])` — `VerificationMethod` in the bucket
 * schemas — which TypeBox renders as `anyOf` + `const` rather than as an `enum`.
 */

const schemas = {
	CreateProjectBody,
	UpdateProjectBody,
	SetBucketBody,
	CreateBucketBody,
	UpdateBucketBody,
	CreateClientBody,
	UpdateClientBody
};

describe('TypeBox admin schemas bridge into MCP tool schemas', () => {
	it('every admin schema is already plain JSON Schema', () => {
		for (const [name, schema] of Object.entries(schemas)) {
			expect(schema.type, name).toBe('object');
			expect(schema.properties, name).toBeDefined();
		}
	});

	it('fromJsonSchema accepts each one', () => {
		for (const [name, schema] of Object.entries(schemas)) {
			const bridged = fromJsonSchema(
				schema as Parameters<typeof fromJsonSchema>[0]
			);
			expect(bridged, name).toBeDefined();
		}
	});

	// The specific risk D2 named. `verificationMethod: t.Union([t.Literal('link'), t.Literal('code')])`
	// must survive the bridge and still discriminate, or the affected schemas need an `enum` form.
	it('renders and validates t.Union([t.Literal]) — the VerificationMethod case', () => {
		const raw = CreateBucketBody.properties.verificationMethod;
		// Record how TypeBox actually renders it, so a future TypeBox change is visible here.
		expect(JSON.stringify(raw)).toMatch(/anyOf|enum|const/);

		const bridged = fromJsonSchema(
			CreateBucketBody as Parameters<typeof fromJsonSchema>[0]
		);
		type Validator = {
			validate?: (v: unknown) => unknown;
			['~standard']?: {
				validate: (v: unknown) => { issues?: unknown[] } | Promise<unknown>;
			};
		};
		const v = bridged as unknown as Validator;
		const std = v['~standard'];
		if (!std) {
			throw new Error(
				'the bridged schema exposes no Standard Schema validator'
			);
		}

		const ok = std.validate({ name: 'B', verificationMethod: 'link' }) as {
			issues?: unknown[];
		};
		expect(ok.issues ?? []).toBeArrayOfSize(0);

		const bad = std.validate({
			name: 'B',
			verificationMethod: 'carrier-pigeon'
		}) as { issues?: unknown[] };
		expect((bad.issues ?? []).length).toBeGreaterThan(0);
	});

	// Optionality must survive too: TypeBox marks optional fields by omission from `required`,
	// and an update body that requires every field would refuse every legitimate PATCH.
	it('preserves optionality: an update body requires nothing', () => {
		expect(UpdateProjectBody.required ?? []).toBeArrayOfSize(0);
		expect(UpdateBucketBody.required ?? []).toBeArrayOfSize(0);
		expect(CreateProjectBody.required).toContain('name');
		expect(CreateProjectBody.required).toContain('slug');
	});
});

---
type: concept
title: 'TypeBox is seen twice by the type checker: meet Elysia on shape, not on TypeBox names'
tags: [gotcha, types, architecture]
sources: [oauth-server-codebase]
created: 2026-09-24
updated: 2026-09-24
---

# TypeBox is seen twice by the type checker

`bunx tsc` resolves `@sinclair/typebox` to **two different declaration sets** in this repository, and
the runtime resolves it to one. Code that passes a schema, or an error TypeBox raised, between this
repository and Elysia can fail to type-check even though the value is exactly right.

## Why

The project compiles with `"module": "nodenext"` (`tsconfig.json:4,8`). TypeBox 0.34 ships
conditional exports, with CommonJS declarations under `require` (`build/cjs/index.d.ts`) and ES module
declarations under `import` (`build/esm/index.d.mts`). Our files are ES modules, so
`import … from '@sinclair/typebox'` resolves to the `.d.mts` set. Elysia's published `dist/index.d.ts`
is not marked as a module, so its own `import … from '@sinclair/typebox'`
(`node_modules/elysia/dist/index.d.ts:1`) resolves through `require` to the `.d.ts` set.

The two sets declare the same classes and the same enum separately. TypeScript compares classes with
private members and enums nominally, so:

- a `TObject` built with this repository's `Type` import is not assignable where Elysia expects its
  `TSchema`/`AnySchema`, and the reverse;
- a `ValueError` from `@sinclair/typebox/value` is not assignable to Elysia's `mapValueError`
  parameter, because `ValueErrorType` is a distinct enum in each set.

At runtime there is one TypeBox: `instanceof TransformDecodeCheckError` and the `Kind` symbols work
across the boundary, which is why this shows up only as type errors.

## What to do

**Meet Elysia on shape.** Where a function takes a schema only to read it, declare the part it reads:
`declaredParams`/`ignoreUnknownParams` take `{ properties: Record<string, unknown> }`
(`lib/plugins/ignore_unknown_params.ts`), which a schema from either set satisfies. Where a schema must
also reach an Elysia API, take Elysia's own `TSchema` (imported from `'elysia'`) and add the shape you
read — `processRequestObject` takes `TSchema & { properties }`
(`lib/actions/authorization/process_request_object.ts`). Where an error value crosses, read its
members into a local shape rather than handing it to the other set's function
(`getFirstError` in `lib/shared/authorization_error_handler.ts`).

**Do not map `@sinclair/typebox` in `tsconfig` `paths` to force one set.** Bun honours `paths` at
runtime, so the mapping would load a second copy of TypeBox beside the one Elysia imports, and the
`instanceof` checks that work today would stop working.

A cast (`schema as TObject`) silences the error but asserts a type the checker has just shown it cannot
relate; it is what `process_request_object.ts` carried until 2026-09-24.

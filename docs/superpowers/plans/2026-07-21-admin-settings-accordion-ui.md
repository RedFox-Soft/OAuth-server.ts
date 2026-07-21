# Admin Settings — Accordion UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the server-settings editor so a feature's detail sub-settings appear only when the feature is enabled, via an antd `Collapse` accordion.

**Architecture:** Add a UI-only `dependsOn` field to each detail descriptor in the settings catalog (naming its group's enable flag). The `Settings.tsx` page derives three sections from the catalog — plain toggle rows for detail-less boolean features, a `Collapse` accordion for features that have details (enable `Switch` in each panel header, details in the body gated on `dependsOn`, panel expands with the toggle), and a Card for the enable-less Discovery array settings. Toggling a feature off cascade-resets its boolean sub-flags. The settings API/validation are unchanged.

**Tech Stack:** React 19 + Ant Design 6, Bun, bun:test.

## Global Constraints

- UI + catalog metadata only. No change to `lib/admin/settings/routes.ts`, the validation, the GET/PUT contract, or the restart-required banner. The server never reads `dependsOn`.
- `dependsOn` on a detail descriptor is always the same group's boolean `.enabled` key. Primaries and Discovery array settings have no `dependsOn`.
- A detail control renders only when its `dependsOn` value is currently `true`.
- Accordion panels expand when their feature is enabled and collapse when disabled.
- Cascade: toggling a feature off resets every boolean detail whose `dependsOn` is that feature to `false` (prevents a hidden-but-true dependent from tripping the server's merged-config 422 on Save).
- Follow existing UI idioms. TDD for the catalog change; UI verified by build + typecheck + manual check (no UI unit tests, per the SP-4 pattern). One commit per task.

---

### Task 1: Catalog `dependsOn` metadata

**Files:**
- Modify: `lib/admin/settings/catalog.ts`
- Test: `test/admin/settings_catalog.spec.ts`

**Interfaces:**
- Produces: `SettingDescriptor.dependsOn?: keyof typeof ApplicationConfig`; each detail descriptor carries `dependsOn` = its group's `.enabled` key.

- [ ] **Step 1: Write the failing test.** Append to `test/admin/settings_catalog.spec.ts` (inside the existing `describe`):

```ts
	it('every dependsOn references a boolean catalog key in the same group', () => {
		const byKey = new Map(SETTINGS_CATALOG.map((d) => [d.key, d]));
		const details = SETTINGS_CATALOG.filter((d) => d.dependsOn);
		expect(details.length).toBeGreaterThan(0);
		for (const d of details) {
			expect(
				Object.prototype.hasOwnProperty.call(ApplicationConfig, d.dependsOn as string)
			).toBe(true);
			const parent = byKey.get(d.dependsOn as keyof typeof ApplicationConfig);
			expect(parent).toBeDefined();
			expect(parent?.type).toBe('boolean');
			expect(parent?.group).toBe(d.group);
			expect(parent?.dependsOn).toBeUndefined(); // parents are primaries
		}
	});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test test/admin/settings_catalog.spec.ts -t "dependsOn"`
Expected: FAIL (`details.length` is 0 — no descriptor has `dependsOn` yet).

- [ ] **Step 3: Implement.** In `lib/admin/settings/catalog.ts`:

Add the field to the interface (after `options?`):
```ts
	options?: string[];
	dependsOn?: keyof typeof ApplicationConfig;
```

Add `dependsOn` to each detail descriptor (replace each listed line with the same line plus the `dependsOn` property). The detail descriptors and their `dependsOn`:
```ts
	{ key: 'par.allowUnregisteredRedirectUris', group: 'PAR', label: 'Allow unregistered redirect_uris via PAR', type: 'boolean', dependsOn: 'par.enabled', description: 'Lets authenticated PAR clients use unregistered redirect_uri values (no sector_identifier_uri).' },
```
```ts
	{ key: 'dpop.requireNonce', group: 'DPoP', label: 'Require DPoP nonce', type: 'boolean', dependsOn: 'dpop.enabled', description: 'Requires a server-provided DPoP nonce.' },
	{ key: 'dpop.allowReplay', group: 'DPoP', label: 'Allow DPoP proof replay', type: 'boolean', dependsOn: 'dpop.enabled', description: 'Disables DPoP proof replay detection.' },
```
```ts
	{ key: 'jwtIntrospection.enabled', group: 'Introspection', label: 'JWT introspection responses (RFC 9701)', type: 'boolean', dependsOn: 'introspection.enabled', description: 'JWT responses for introspection. Requires Introspection enabled.' },
```
```ts
	{ key: 'jwtUserinfo.enabled', group: 'UserInfo', label: 'JWT UserInfo responses', type: 'boolean', dependsOn: 'userinfo.enabled', description: 'JWT responses for UserInfo. Requires UserInfo enabled.' },
```
```ts
	{ key: 'mTLS.certificateBoundAccessTokens', group: 'mTLS', label: 'Certificate-bound access tokens', type: 'boolean', dependsOn: 'mTLS.enabled', description: 'Requires mTLS enabled.' },
	{ key: 'mTLS.selfSignedTlsClientAuth', group: 'mTLS', label: 'self_signed_tls_client_auth method', type: 'boolean', dependsOn: 'mTLS.enabled', description: 'Requires mTLS enabled.' },
	{ key: 'mTLS.tlsClientAuth', group: 'mTLS', label: 'tls_client_auth method', type: 'boolean', dependsOn: 'mTLS.enabled', description: 'Requires mTLS enabled.' },
```
```ts
	{ key: 'deviceFlow.charset', group: 'Device Flow', label: 'User-code charset', type: 'enum', options: ['base-20', 'digits'], dependsOn: 'deviceFlow.enabled', description: 'Character set for generated user codes.' },
	{ key: 'deviceFlow.mask', group: 'Device Flow', label: 'User-code mask', type: 'string', dependsOn: 'deviceFlow.enabled', description: 'Template for user codes; * is replaced by a random charset char.' },
```
```ts
	{ key: 'ciba.deliveryModes', group: 'CIBA', label: 'Token delivery modes', type: 'string-array', options: ['poll', 'ping'], dependsOn: 'ciba.enabled', description: 'Supported CIBA token delivery modes.' },
```
```ts
	{ key: 'requestObjects.requireSignedRequestObject', group: 'Request Objects', label: 'Require signed request objects', type: 'boolean', dependsOn: 'requestObjects.enabled', description: 'Requires signed request objects for all authorization requests.' },
```
```ts
	{ key: 'registration.issueRegistrationAccessToken', group: 'Registration', label: 'Issue registration access token', type: 'boolean', dependsOn: 'registration.enabled', description: 'Whether a registration access token is issued.' },
```
```ts
	{ key: 'registrationManagement.rotateRegistrationAccessToken', group: 'Registration Management', label: 'Rotate registration access token', type: 'boolean', dependsOn: 'registrationManagement.enabled', description: 'Enables registration access token rotation.' },
```

Do NOT add `dependsOn` to any primary (`*.enabled` that heads its group) or to the Discovery settings (`scopes`, `acrValues`, `clientAuthMethods`). Note `registrationManagement.enabled` and `richAuthorizationRequests.enabled` are primaries (no `dependsOn`).

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test test/admin/settings_catalog.spec.ts`
Expected: PASS (all catalog tests). If a `dependsOn` value fails the `keyof typeof ApplicationConfig` type constraint, it is misspelled — fix against `lib/configs/application.ts`.

- [ ] **Step 5: Commit**

```bash
git add lib/admin/settings/catalog.ts test/admin/settings_catalog.spec.ts
git commit -m "feat(admin): dependsOn metadata on settings catalog details"
```

---

### Task 2: Accordion Settings page

**Files:**
- Modify (full rewrite): `lib/admin/ui/pages/Settings.tsx`
- Build: `bun build.ts`

**Interfaces:**
- Consumes: the `GET`/`PUT /admin/api/settings` response `{ catalog, values, restartRequired, changedKeys }` where each catalog descriptor now may carry `dependsOn`.
- Produces: `Settings` React component `Settings()` (no props) — unchanged export.

- [ ] **Step 1: Rewrite the component.** Replace the entire contents of `lib/admin/ui/pages/Settings.tsx` with:

```tsx
import { useEffect, useMemo, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Collapse,
	Form,
	Input,
	Select,
	Switch,
	Typography,
	message
} from 'antd';

type SettingType = 'boolean' | 'string' | 'enum' | 'string-array';
interface Descriptor {
	key: string;
	group: string;
	label: string;
	description: string;
	type: SettingType;
	options?: string[];
	dependsOn?: string;
}
interface SettingsResponse {
	catalog: Descriptor[];
	values: Record<string, unknown>;
	restartRequired: boolean;
	changedKeys: string[];
}

// The detail groups whose primary is currently enabled — used to seed which
// accordion panels start expanded after a load/save.
function enabledDetailGroups(
	catalog: Descriptor[],
	values: Record<string, unknown>
): string[] {
	const detailGroups = new Set(
		catalog.filter((d) => d.dependsOn).map((d) => d.group)
	);
	return [...detailGroups].filter((g) => {
		const primary = catalog.find((d) => d.group === g && !d.dependsOn);
		return primary ? values[primary.key] === true : false;
	});
}

export function Settings() {
	const [catalog, setCatalog] = useState<Descriptor[]>([]);
	const [values, setValues] = useState<Record<string, unknown>>({});
	const [restartRequired, setRestartRequired] = useState(false);
	const [changedKeys, setChangedKeys] = useState<string[]>([]);
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);
	const [openGroups, setOpenGroups] = useState<string[]>([]);

	function apply(body: SettingsResponse) {
		setCatalog(body.catalog);
		setValues(body.values);
		setRestartRequired(body.restartRequired);
		setChangedKeys(body.changedKeys);
		setOpenGroups(enabledDetailGroups(body.catalog, body.values));
	}

	async function load() {
		setLoading(true);
		try {
			const res = await fetch('/admin/api/settings');
			if (res.ok) apply((await res.json()) as SettingsResponse);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
	}, []);

	async function save() {
		setSaving(true);
		try {
			const res = await fetch('/admin/api/settings', {
				method: 'PUT',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			const body = (await res.json().catch(() => null)) as
				| (SettingsResponse & { message?: string })
				| null;
			if (!res.ok) {
				message.error(body?.message || 'failed to save settings');
				return;
			}
			if (body) apply(body);
			message.success('settings saved');
		} finally {
			setSaving(false);
		}
	}

	function setValue(key: string, value: unknown) {
		setValues((prev) => ({ ...prev, [key]: value }));
	}

	// Toggle a primary feature flag. On disable, cascade-reset its boolean detail
	// dependents to false (so a hidden-but-true dependent can't trip the server's
	// merged-config validation on Save), and collapse its panel; on enable, expand it.
	function onToggleFeature(primary: Descriptor, checked: boolean) {
		setValues((prev) => {
			const next = { ...prev, [primary.key]: checked };
			if (!checked) {
				for (const d of catalog) {
					if (d.dependsOn === primary.key && d.type === 'boolean') {
						next[d.key] = false;
					}
				}
			}
			return next;
		});
		setOpenGroups((prev) =>
			checked
				? prev.includes(primary.group)
					? prev
					: [...prev, primary.group]
				: prev.filter((g) => g !== primary.group)
		);
	}

	// Section partition, derived from the catalog.
	const detailGroups = useMemo(
		() => new Set(catalog.filter((d) => d.dependsOn).map((d) => d.group)),
		[catalog]
	);
	const toggleRows = useMemo(
		() =>
			catalog.filter(
				(d) => !d.dependsOn && d.type === 'boolean' && !detailGroups.has(d.group)
			),
		[catalog, detailGroups]
	);
	const accordion = useMemo(() => {
		const order: string[] = [];
		for (const d of catalog) {
			if (detailGroups.has(d.group) && !order.includes(d.group)) {
				order.push(d.group);
			}
		}
		return order.map((group) => ({
			group,
			primary: catalog.find((d) => d.group === group && !d.dependsOn) as Descriptor,
			details: catalog.filter((d) => d.group === group && d.dependsOn)
		}));
	}, [catalog, detailGroups]);
	const otherGroups = useMemo(() => {
		const rest = catalog.filter(
			(d) => !d.dependsOn && d.type !== 'boolean' && !detailGroups.has(d.group)
		);
		const order: string[] = [];
		for (const d of rest) if (!order.includes(d.group)) order.push(d.group);
		return order.map((group) => ({
			group,
			items: rest.filter((d) => d.group === group)
		}));
	}, [catalog, detailGroups]);

	function control(d: Descriptor) {
		const value = values[d.key];
		if (d.type === 'boolean') {
			return (
				<Switch
					checked={value === true}
					onChange={(checked) => setValue(d.key, checked)}
				/>
			);
		}
		if (d.type === 'enum') {
			return (
				<Select
					style={{ minWidth: 220 }}
					value={value as string}
					options={(d.options ?? []).map((o) => ({ label: o, value: o }))}
					onChange={(v) => setValue(d.key, v)}
				/>
			);
		}
		if (d.type === 'string-array') {
			return (
				<Select
					mode={d.options ? 'multiple' : 'tags'}
					style={{ minWidth: 320 }}
					value={(value as string[]) ?? []}
					options={(d.options ?? []).map((o) => ({ label: o, value: o }))}
					onChange={(v) => setValue(d.key, v)}
				/>
			);
		}
		return (
			<Input
				style={{ maxWidth: 320 }}
				value={(value as string) ?? ''}
				onChange={(e) => setValue(d.key, e.target.value)}
			/>
		);
	}

	function field(d: Descriptor) {
		return (
			<Form.Item
				key={d.key}
				label={d.label}
				help={d.description}
				style={{ marginBottom: 16 }}
			>
				{control(d)}
			</Form.Item>
		);
	}

	return (
		<>
			<div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
				<Typography.Title level={4} style={{ margin: 0 }}>
					Server settings
				</Typography.Title>
				<Button type="primary" loading={saving} onClick={save}>
					Save
				</Button>
			</div>
			{restartRequired && (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					message="Restart required to apply"
					description={`Saved changes take effect after a server restart: ${changedKeys.join(', ')}`}
				/>
			)}

			<Card title="Features" size="small" style={{ marginBottom: 16 }} loading={loading}>
				<Form layout="vertical">{toggleRows.map(field)}</Form>
			</Card>

			<Collapse
				style={{ marginBottom: 16 }}
				collapsible="icon"
				activeKey={openGroups}
				onChange={(keys) =>
					setOpenGroups(Array.isArray(keys) ? (keys as string[]) : [keys as string])
				}
				items={accordion.map(({ group, primary, details }) => {
					const on = values[primary.key] === true;
					return {
						key: group,
						label: (
							<div>
								<div>{primary.label}</div>
								<Typography.Text type="secondary" style={{ fontSize: 12 }}>
									{primary.description}
								</Typography.Text>
							</div>
						),
						extra: (
							<Switch
								checked={on}
								onChange={(checked) => onToggleFeature(primary, checked)}
							/>
						),
						children: on ? (
							<Form layout="vertical">
								{details
									.filter((d) => values[d.dependsOn as string] === true)
									.map(field)}
							</Form>
						) : (
							<Typography.Text type="secondary">
								Enable this feature to configure its options.
							</Typography.Text>
						)
					};
				})}
			/>

			{otherGroups.map(({ group, items }) => (
				<Card key={group} title={group} size="small" style={{ marginBottom: 16 }} loading={loading}>
					<Form layout="vertical">{items.map(field)}</Form>
				</Card>
			))}
		</>
	);
}
```

- [ ] **Step 2: Build the bundle**

Run: `bun build.ts`
Expected: `built ./lib/admin/ui/adminClient.tsx → public/admin.js` with no errors.

- [ ] **Step 3: Typecheck the changed UI**

Run: `bun run typecheck 2>&1 | grep -E "Settings\.tsx" || echo "clean"`
Expected: `clean`. (If antd's `Collapse` `items`/`collapsible`/`extra` prop types complain in this antd version, adjust to the version's supported shape — keep the accordion behavior: header toggle + gated details + expand-on-enable.)

- [ ] **Step 4: Commit**

```bash
git add lib/admin/ui/pages/Settings.tsx
git commit -m "feat(admin): accordion settings UI with progressive disclosure"
```
(`public/admin.js` is an untracked build artifact — do not add it; confirm with `git ls-files public/admin.js` returning nothing.)

---

### Task 3: Verification

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

Run: `bun test`
Expected: all pass, 0 fail (the catalog `dependsOn` test plus all prior tests; `settings_routes` unaffected since the server ignores `dependsOn`).

- [ ] **Step 2: Typecheck**

Run: `bun run typecheck 2>&1 | grep -E "admin/settings|Settings\.tsx|catalog\.ts" || echo "no new type errors in changed files"`
Expected: `no new type errors in changed files`.

- [ ] **Step 3: Server smoke test.** Start the server (`bun lib/index.ts`), confirm the bundle serves and settings still requires auth:

Run: `curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/public/admin.js` → `200`
Run: `curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/admin/api/settings` → `401`
Kill the server afterward (`Get-Process bun | Stop-Process -Force`).

- [ ] **Step 4: Authenticated UI check (manual — needs admin credentials).** Log in to `/admin` as super_admin, open **Settings**: confirm (a) detail-less features appear as toggle rows under "Features"; (b) features with details are accordion panels — enabling one expands it and reveals its detail controls, disabling one collapses/hides them; (c) enabling Introspection then disabling it resets `jwtIntrospection` (no 422 on Save); (d) Discovery (scopes/acr/clientAuthMethods) is always shown; (e) Save still persists and shows the restart banner. Flag results to the reviewer.

---

## Self-Review

**Spec coverage:**
- `dependsOn` catalog field + values on all 14 detail descriptors → Task 1. ✓
- `dependsOn`-integrity test (exists, boolean, same group, parent is primary) → Task 1. ✓
- Three-section layout (toggle rows / accordion / Discovery Card) derived from `dependsOn`+`group` → Task 2. ✓
- Detail shown only when `dependsOn` true; panel expands with the toggle → Task 2 (`on ? … : hint`, `openGroups`). ✓
- Cascade-reset of boolean details on disable → Task 2 (`onToggleFeature`). ✓
- Server/routes/validation unchanged → no route files in scope. ✓
- Verification (suite, typecheck, smoke, manual) → Task 3. ✓

**Placeholder scan:** No TBD/TODO; complete code for both files. ✓

**Type consistency:** `dependsOn` typed `keyof typeof ApplicationConfig` in the catalog (Task 1) and `string` in the UI `Descriptor` (Task 2, matching the JSON-over-the-wire shape); `Settings()` export unchanged; response shape `{ catalog, values, restartRequired, changedKeys }` unchanged. ✓

**Note for implementer:** every detail's `dependsOn` names a boolean primary in the *same* group, so an accordion panel's `on` state (the primary's value) and its details' visibility (`values[dependsOn] === true`) always agree — a panel is expanded exactly when its details should show. The cascade only touches boolean details; non-boolean details (`deviceFlow.mask`/`charset`, `ciba.deliveryModes`) keep their values, which is safe because the server's boot checks either ignore them while the parent is off or (for `ciba.deliveryModes`) validate them regardless.
